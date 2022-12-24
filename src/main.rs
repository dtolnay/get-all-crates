use anyhow::bail;
use clap::Parser;
use futures::stream::StreamExt;
use governor::state::direct::StreamRateLimitExt;
use governor::{Quota, RateLimiter};
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::str::from_utf8;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncBufReadExt;
use tracing::{debug, error, info, warn};
use tracing_subscriber::filter::EnvFilter;

/// One version per line in the index metadata files.
#[derive(Debug, Clone, Deserialize)]
pub struct CrateVersion {
    pub name: String,
    pub vers: String,
    pub cksum: String,
}

/// Configuration for where to save the downloaded .crate files, and
/// using what syntax for the output filenames.
#[derive(Debug, Parser)]
pub struct OutputConfig {
    /// Directory where downloaded .crate files will be saved to.
    #[clap(short = 'o', long = "output-path", default_value = DEFAULT_OUTPUT_PATH)]
    pub path: PathBuf,
    /// Download files when if .crate file already exists in output dir for a
    /// given crate version, and overwrite the existing file with the new one.
    /// Default behavior is to skip downloading if .crate file already exists.
    #[clap(long)]
    pub overwrite_existing: bool,
    /// What format to use for the output filenames. Works the same as
    /// Cargo's registry syntax for the "dl" key in the `config.json`
    /// file in a reigstry index. See [Cargo
    /// docs](https://doc.rust-lang.org/cargo/reference/registries.html#index-format)
    /// for additional details. Not specifying this field is equivalent
    /// to specifying "{crate}/{version}/download", the default.
    ///
    /// The resulting path specified by the format should be relative;
    /// it will be joined with the --output-path. (i.e. it should not start
    /// with "/".)
    #[clap(long = "output-format")]
    pub format: Option<String>,
}

#[derive(Parser)]
pub struct HttpConfig {
    /// Value of user-agent HTTP header
    #[clap(short = 'U', long, default_value = DEFAULT_USER_AGENT)]
    pub user_agent: String,
    /// Requests to registry server will not exceed this rate
    #[clap(short = 'R', long, default_value_t = default_requests_per_second())]
    #[clap(value_name = "INT")]
    pub requests_per_second: NonZeroU32,
    /// Independent of the requests per second rate limit, no more
    /// than `max_concurrent_requests` will be in flight at any given
    /// moment.
    #[clap(short = 'M', long, default_value_t = default_max_concurrent_requests())]
    #[clap(value_name = "INT")]
    pub max_concurrent_requests: NonZeroU32,
}

#[derive(Parser)]
pub struct TargetRegistryConfig {
    /// URL of the registry index we are downloading .crate files from. The
    /// program expects that it will be able to clone the index to a local
    /// temporary directory; the user must handle authentication if needed.
    #[clap(long, value_name = "URL")]
    pub index_url: Option<String>,
    /// instead of an index url, just point to a local path where the index
    /// is already cloned.
    #[clap(long, conflicts_with = "index-url")]
    #[clap(value_name = "PATH")]
    pub index_path: Option<PathBuf>,
    /// If registry requires authorization (i.e. "auth-required" key is
    /// set to `true` in the `config.json` file), the token to include
    /// using the Authorization HTTP header.
    #[clap(short, long, value_name = "TOKEN")]
    pub auth_token: Option<String>,
}

/// Download all .crate files from a registry server.
#[derive(Parser, Debug)]
#[clap(author, version, global_setting(clap::AppSettings::DeriveDisplayOrder))]
pub struct Config {
    /// Crate registry location and authentication
    #[clap(flatten)]
    pub registry: TargetRegistryConfig,
    /// Where to save the downloaded files
    #[clap(flatten)]
    pub output: OutputConfig,
    /// Download settings
    #[clap(flatten)]
    pub http: HttpConfig,

    /// Only crates with names that match --filter-crate regex will be downloaded
    #[clap(long, value_name = "REGEX")]
    pub filter_crates: Option<String>,

    /// Don't actually download the .crate files, just list files which would be
    /// downloaded. Note: --requests-per-second and --max-concurrent-requests are
    /// still enforced even in --dry-mode!
    #[clap(long)]
    pub dry_run: bool,
}

const DEFAULT_OUTPUT_PATH: &str = "output";
const DEFAULT_USER_AGENT: &str = concat!("registry-backup/v", clap::crate_version!());

const fn default_requests_per_second() -> NonZeroU32 {
    unsafe { NonZeroU32::new_unchecked(100) }
}

const fn default_max_concurrent_requests() -> NonZeroU32 {
    unsafe { NonZeroU32::new_unchecked(50) }
}

impl Config {
    pub fn skip_existing(&self) -> bool {
        !self.output.overwrite_existing
    }

    pub fn compile_filter(&self) -> anyhow::Result<Option<regex::Regex>> {
        match self.filter_crates.as_ref() {
            Some(regex) => {
                let compiled = regex::Regex::new(regex).map_err(|e| {
                    error!(%regex, err = ?e, "regex failed to compile: {}", e);
                    e
                })?;
                Ok(Some(compiled))
            }
            None => Ok(None),
        }
    }
}

impl std::fmt::Debug for TargetRegistryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("index_url", &self.index_url)
            .field("index_path", &self.index_path)
            .field("auth_token", &"***") // hide sensitive data
            .finish()
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            requests_per_second: default_requests_per_second(),
            max_concurrent_requests: default_max_concurrent_requests(),
        }
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Config")
            .field(
                "user_agent",
                if self.user_agent.starts_with("shipyard ") {
                    &"shipyard ***"
                } else {
                    &self.user_agent
                },
            )
            .field("requests_per_second", &self.requests_per_second)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .finish()
    }
}

async fn popen(cmd: &str, args: &[&str], envs: &[(&str, &str)]) -> anyhow::Result<Output> {
    let args: Vec<String> = args.iter().map(|x| x.to_string()).collect();

    let output = tokio::process::Command::new(cmd)
        .args(args.iter().map(|x| x.as_str()))
        .envs(envs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .output()
        .await
        .map_err(|e| {
            error!("Command `{}` failed to execute at all: {:?}", cmd, e);
            e
        })?;

    debug!(
        "finished executing `{}` Command with status {:?}\n STDOUT (length={}):\n{}\n STDERR (length={}):\n{}\n",
        cmd,
        output.status,
        output.stdout.len(),
        from_utf8(&output.stdout)?,
        output.stderr.len(),
        from_utf8(&output.stderr)?,
    );

    if !output.status.success() {
        error!(
            "finished executing `{}` Command with status {:?}\n STDOUT (length={}):\n{}\n STDERR (length={}):\n{}\n",
            cmd,
            output.status,
            output.stdout.len(),
            from_utf8(&output.stdout)?,
            output.stderr.len(),
            from_utf8(&output.stderr)?,
        );

        bail!(
            "git clone commnad failed with error code {:?}",
            output.status,
        );
    }

    Ok(output)
}

async fn git_clone(src: &str, dst: &Path, envs: &[(&str, &str)]) -> anyhow::Result<()> {
    let begin = Instant::now();
    popen(
        "git",
        &[
            "clone",
            src,
            dst.to_str().expect("dst path .to_str() failed"),
        ][..],
        envs,
    )
    .await
    .map_err(|e| -> anyhow::Error {
        error!(%src, ?dst, ?e, "in git_clone, Command failed");
        e
    })?;

    info!(%src, ?dst, "cloned repo in {:?}", begin.elapsed());

    Ok(())
}

fn setup_logger() {
    let env_filter = EnvFilter::from_default_env();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(true);
    builder.init();
}

fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

async fn get_crate_versions(
    config: &Config,
    clone_dir: &Path,
) -> anyhow::Result<Vec<CrateVersion>> {
    let filter = config.compile_filter()?;
    let mut n_excl = 0;
    let n_existing = Arc::new(AtomicUsize::new(0));

    let files: Vec<PathBuf> = walkdir::WalkDir::new(clone_dir)
        .max_depth(3)
        .into_iter()
        .filter_entry(|e| !is_hidden(e))
        .filter_map(|res| match res {
            Ok(entry) => {
                if entry.file_type().is_file() && entry.depth() >= 2 && entry.depth() <= 3 {
                    let path = entry.into_path();

                    if let Some(filter) = filter.as_ref() {
                        let crate_name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");
                        if !filter.is_match(crate_name.as_ref()) {
                            n_excl += 1;
                            return None;
                        }
                    }

                    debug!(?path, "found crate metadata file to parse");
                    Some(path)
                } else {
                    None
                }
            }
            Err(e) => {
                warn!(error = ?e, "walkdir result is error");
                None
            }
        })
        .collect();

    let n_files = files.len();
    info!("found {} crate metadata files to parse", n_files);

    if n_excl > 0 {
        warn!(
            regex = %config.filter_crates.as_deref().unwrap_or(""),
            n_files,
            n_excl,
            "--filter excluded {} crates", n_excl,
        );
    }

    let crate_versions: Vec<anyhow::Result<Vec<CrateVersion>>> =
        futures::stream::iter(files.into_iter().map(|path| {
            let n_existing = n_existing.clone();
            async move {
                let file = tokio::fs::File::open(&path).await.map_err(|e| {
                    error!(err = ?e, ?path, "failed to open file");
                    e
                })?;
                let buf = tokio::io::BufReader::new(file);
                let mut out = Vec::new();
                let mut lines = buf.lines();
                'lines: while let Some(line) = lines.next_line().await? {
                    let vers: CrateVersion = serde_json::from_str(&line).map_err(|e| {
                        error!(err = ?e, ?path, "failed to parse line");
                        e
                    })?;

                    if config.skip_existing() {
                        let vers_path = format!("{}/{}/download", vers.name, vers.vers);
                        let output_path = config.output.path.join(vers_path);
                        if output_path.exists() {
                            n_existing.fetch_add(1, Ordering::Relaxed);
                            continue 'lines;
                        }
                    }

                    out.push(vers);
                }
                debug!(crate_name = %out.first().map(|x| x.name.as_str()).unwrap_or("na"),
                    "parsed {} crate versions from metadata file", out.len()
                );

                Ok(out)
            }
        }))
        .buffer_unordered(num_cpus::get())
        .collect()
        .await;

    let n_existing = n_existing.load(Ordering::Relaxed);

    if n_existing > 0 {
        warn!(
            "skipped {} crate versions that were previously downloaded",
            n_existing,
        );
    }

    let crate_versions: Vec<CrateVersion> = crate_versions
        .into_iter()
        .flat_map(|result| match result {
            Ok(xs) => xs.into_iter().filter(|x| x.name != "vst").collect(),
            Err(e) => {
                error!(err = ?e, "parsing metadata failed, skipping file");
                vec![]
            }
        })
        .collect();

    info!(
        n_files,
        n_excl,
        n_existing,
        n_download_targets = crate_versions.len(),
        "collected {} total crate versions to download",
        crate_versions.len()
    );

    Ok(crate_versions)
}

async fn ensure_dir_exists<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<()> {
    match tokio::fs::metadata(path.as_ref()).await {
        Ok(meta) if meta.is_dir() => Ok(()),

        Ok(meta) /* if ! meta.is_dir() */ => {
            debug_assert!( ! meta.is_dir());
            bail!("path exists, but is not a directory: {:?}", path.as_ref());
        }

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(&path).await?;
            Ok(())
        }

        Err(e) => Err(e.into()),
    }
}

async fn ensure_file_parent_dir_exists<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<()> {
    if let Some(parent_dir) = path.as_ref().parent() {
        ensure_dir_exists(parent_dir).await
    } else {
        Ok(())
    }
}

macro_rules! megabytes {
    ($x:expr) => {{
        use pretty_toa::ThousandsSep;
        let mb = $x as f64 / 1024.0 / 1024.0;
        if mb > 2048.0 {
            format!(
                "{}G",
                (((mb / 1024.0) * 100.0).round() / 100.0).thousands_sep()
            )
        } else if mb < 0.75 {
            let kb = $x as f64 / 1024.0;
            format!("{}K", ((kb * 10.0).round() / 10.0).thousands_sep())
        } else {
            format!("{}M", ((mb * 10.0).round() / 10.0).thousands_sep())
        }
    }};
}

async fn download_versions(config: &Config, versions: Vec<CrateVersion>) -> anyhow::Result<()> {
    let begin = Instant::now();
    ensure_dir_exists(&config.output.path).await?;

    let rate_limit = RateLimiter::direct(Quota::per_second(config.http.requests_per_second));

    let http_client = reqwest::Client::builder()
        .user_agent(&config.http.user_agent)
        .build()?;

    info!(
        reqs_per_sec = config.http.requests_per_second,
        max_concurrency = config.http.max_concurrent_requests,
        "downloading crates at {} reqs/sec",
        config.http.requests_per_second,
    );

    let inner_stream = futures::stream::iter(versions.into_iter().map(|vers| {
        let req_begin = Instant::now();
        let http_client = http_client.clone();

        async move {
            let url = url::Url::parse(&format!(
                "https://static.crates.io/crates/{name}/{name}-{version}.crate",
                name = vers.name,
                version = vers.vers,
            ))?;

            let name_lower = vers.name.to_ascii_lowercase();
            let output_path = config
                .output
                .path
                .join(PathBuf::from_iter(match name_lower.len() {
                    1 => vec!["1"],
                    2 => vec!["2"],
                    3 => vec!["3", &name_lower[..1]],
                    _ => vec![&name_lower[0..2], &name_lower[2..4]],
                }))
                .join(name_lower)
                .join(format!("{}-{}.crate", vers.name, vers.vers));

            if config.dry_run {
                debug!(%url, "skipping download (--dry-run mode)");
                return Ok(None);
            }

            debug!(?url, "downloading...");
            let req = http_client.get(url);

            let req = if let Some(token) = config.registry.auth_token.as_deref() {
                req.header(AUTHORIZATION, token)
            } else {
                req
            };

            let resp = req.send().await?;
            let status = resp.status();
            let body = resp.bytes().await?;

            if !status.is_success() {
                error!(status = ?status, "download failed");
                debug!("response body:\n{}\n", from_utf8(&body.slice(..))?);
                bail!("error response {:?} from server", status);
            } else {
                // TODO: check if this path exists already before downloading
                ensure_file_parent_dir_exists(&output_path)
                    .await
                    .map_err(|e| {
                        error!(?output_path, err = ?e, "ensure parent dir exists failed");
                        e
                    })?;
                tokio::fs::write(&output_path, body.slice(..))
                    .await
                    .map_err(|e| {
                        error!(err = ?e, "writing file failed");
                        e
                    })?;
                info!(
                        filesize = megabytes!(body.len()),
                        crate_name = %vers.name,
                        version = %vers.vers,
                        "downloaded .crate file in {:?}", req_begin.elapsed());
                debug!(?output_path, "wrote {} bytes to file", body.len());
                Ok(Some(output_path))
            }
        }
    }))
    .buffer_unordered(config.http.max_concurrent_requests.get() as usize);

    let outer_stream = inner_stream.ratelimit_stream(&rate_limit);

    let results: Vec<anyhow::Result<Option<PathBuf>>> = outer_stream.collect().await;

    let mut ret = Ok(());

    let n = results.len();
    let mut n_err = 0;
    let mut n_skip = 0;
    for result in results {
        match result {
            Ok(None) => n_skip += 1,

            Err(e) => {
                n_err += 1;
                error!(err = ?e, "download failed");
                ret = Err(e);
            }

            _ => {}
        }
    }

    let n_ok = n - n_err - n_skip;
    info!(
        n_ok,
        n_err,
        n_skip,
        "finished downloading {} files in {:?}",
        n_ok,
        begin.elapsed()
    );

    ret
}

async fn run(config: Config) -> anyhow::Result<()> {
    debug!("config:\n{:#?}\n", config);

    assert!(
        config.registry.index_url.is_some() || config.registry.index_path.is_some(),
        "one of index-url or index-path is required",
    );

    // verify regex compiles
    let _ = config.compile_filter()?;

    let tmpdir = tempdir::TempDir::new("registry-backup-index")?;

    let index_path = match (&config.registry.index_url, &config.registry.index_path) {
        (Some(url), _) => {
            let tmp = tmpdir.path();
            git_clone(url, tmp, &[][..]).await?;
            tmp
        }

        (_, Some(path)) => path,

        _ => unreachable!(),
    };

    let versions = get_crate_versions(&config, index_path).await?;

    download_versions(&config, versions).await?;

    Ok(())
}

fn main() {
    let begin = Instant::now();

    setup_logger();

    info!("initializing...");

    let config = Config::parse();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(run(config)).unwrap();

    info!("finished in {:?}", begin.elapsed());
}

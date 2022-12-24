use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::str::from_utf8;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::*;

use clap::Parser;
use futures::stream::StreamExt;
use governor::prelude::*;
use governor::{Quota, RateLimiter};
use reqwest::header::AUTHORIZATION; // ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;
use tracing::{debug, error, info, warn};
use tracing_subscriber::filter::EnvFilter;

type AnyError = Box<dyn std::error::Error>;

// const CRATESIO_INDEX: &str = "https://github.com/rust-lang/crates.io-index.git";
const CRATESIO_DL_URL: &str = "https://crates.io/api/v1/crates";

/// type representing the schema of the config.json file
/// placed at the root of the crate index repo.
///
/// e.g.
///
/// ```json,ignore
/// {
///   "dl": "https://crates.shipyard.rs/api/v1/crates",
///   "api": "https://crates.shipyard.rs",
///   "allowed-registries": ["https://github.com/rust-lang/crates.io-index"]
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RegistryConfig {
    pub dl: String,
    pub api: String,
    #[serde(default)]
    pub allowed_registries: Vec<String>,
    #[serde(default)]
    pub auth_required: Option<bool>,
}

impl RegistryConfig {
    pub fn is_crates_io(&self) -> bool {
        self.dl == CRATESIO_DL_URL
    }

    pub fn get_dl_url(&self, name: &str, version: &str, cksum: &str) -> String {
        const TEMPLATE_KEYS: [&str; 5] = [
            "{crate}",
            "{version}",
            "{prefix}",
            "{lowerprefix}",
            "{sha256-checksum}",
        ];

        if self.is_crates_io() {
            // instead of following 302 redirect from /api endpoint, just preemptively
            // get the static cdn url
            format!(
                "https://static.crates.io/crates/{name}/{name}-{version}.crate",
                name = name,
                version = version,
            )
        } else if TEMPLATE_KEYS.iter().any(|k| self.dl.contains(k)) {
            let mut out = self.dl.clone();

            if self.dl.contains("{prefix}") {
                let prefix = relative_index_file_helper(name).join("/");
                out = out.replace("{prefix}", &prefix);
            }

            if self.dl.contains("{lowerprefix}") {
                let prefix = relative_index_file_helper(&name.to_lowercase()).join("/");
                out = out.replace("{lowerprefix}", &prefix);
            }

            out = out.replace("{crate}", name);
            out = out.replace("{version}", version);
            out = out.replace("{sha256-checksum}", cksum);
            out
        } else {
            Path::new(&self.dl)
                .join(&format!(
                    "{name}/{version}/download",
                    name = name,
                    version = version,
                ))
                .display()
                .to_string()
        }
    }
}

/// One version per line in the index metadata files.
#[derive(Debug, Clone, Deserialize)]
pub struct CrateVersion {
    pub name: String,
    pub vers: String,
    pub cksum: String,
}

/// Configuration for where to save the downloaded .crate files, and
/// using what syntax for the output filenames.
#[derive(Deserialize, Debug, Parser)]
#[serde(rename_all = "kebab-case")]
pub struct OutputConfig {
    /// Directory where downloaded .crate files will be saved to.
    #[clap(short = 'o', long = "output-path", default_value = DEFAULT_OUTPUT_PATH)]
    #[serde(default = "default_output_path")]
    pub path: PathBuf,
    /// Download files when if .crate file already exists in output dir for a
    /// given crate version, and overwrite the existing file with the new one.
    /// Default behavior is to skip downloading if .crate file already exists.
    #[serde(default)]
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

#[derive(Deserialize, Parser)]
#[serde(rename_all = "kebab-case")]
pub struct HttpConfig {
    /// Value of user-agent HTTP header
    #[serde(default = "default_user_agent")]
    #[clap(short = 'U', long, default_value = DEFAULT_USER_AGENT)]
    pub user_agent: String,
    /// Requests to registry server will not exceed this rate
    #[serde(default = "default_requests_per_second")]
    #[clap(short = 'R', long, default_value_t = default_requests_per_second())]
    #[clap(value_name = "INT")]
    pub requests_per_second: NonZeroU32,
    /// Independent of the requests per second rate limit, no more
    /// than `max_concurrent_requests` will be in flight at any given
    /// moment.
    #[serde(default = "default_max_concurrent_requests")]
    #[clap(short = 'M', long, default_value_t = default_max_concurrent_requests())]
    #[clap(value_name = "INT")]
    #[clap(alias = "max-concurrency", alias = "concurrency")]
    #[serde(alias = "max-concurrency", alias = "concurrency")]
    pub max_concurrent_requests: NonZeroU32,
}

#[derive(Deserialize, Parser)]
#[serde(rename_all = "kebab-case")]
pub struct TargetRegistryConfig {
    /// URL of the registry index we are downloading .crate files from. The
    /// program expects that it will be able to clone the index to a local
    /// temporary directory; the user must handle authentication if needed.
    #[serde(default, alias = "registry-path")]
    #[clap(long, alias = "registry-url", value_name = "URL")]
    pub index_url: Option<String>,
    /// instead of an index url, just point to a local path where the index
    /// is already cloned.
    #[serde(default, alias = "registry-path")]
    #[clap(long, conflicts_with = "index-url", alias = "registry-path")]
    #[clap(value_name = "PATH")]
    pub index_path: Option<PathBuf>,
    /// If registry requires authorization (i.e. "auth-required" key is
    /// set to `true` in the `config.json` file), the token to include
    /// using the Authorization HTTP header.
    #[clap(short, long, alias = "token", value_name = "TOKEN")]
    #[serde(default)]
    pub auth_token: Option<String>,
}

/// Download all .crate files from a registry server.
#[derive(Deserialize, Parser, Debug)]
#[serde(rename_all = "kebab-case")]
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
    #[serde(default)]
    pub http: HttpConfig,
    /// Specify configuration values using the provided TOML file, instead of
    /// via command line flags. The values in the config file will override
    /// any values passed as command line flags. See config.toml.sample for
    /// syntax of the config file.
    #[serde(default)]
    #[clap(short, long, value_name = "PATH")]
    #[clap(conflicts_with_all(&[
        "index-url",
        "index-path",
        "auth-token",
        "path",
        "user-agent",
        "requests-per-second",
        "max-concurrent-requests",
        "overwrite-existing",
    ][..]))]
    pub config_file: Option<PathBuf>,

    /// Only crates with names that match --filter-crate regex will be downloaded
    #[serde(default)]
    #[clap(long, value_name = "REGEX", alias = "filter")]
    pub filter_crates: Option<String>,

    /// Don't actually download the .crate files, just list files which would be
    /// downloaded. Note: --requests-per-second and --max-concurrent-requests are
    /// still enforced even in --dry-mode!
    #[serde(default)]
    #[clap(long)]
    pub dry_run: bool,
}

const DEFAULT_OUTPUT_PATH: &str = "output";
const DEFAULT_USER_AGENT: &str = concat!("registry-backup/v", clap::crate_version!());

fn default_output_path() -> PathBuf {
    PathBuf::from(DEFAULT_OUTPUT_PATH)
}

fn default_user_agent() -> String {
    DEFAULT_USER_AGENT.to_string()
}

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

    pub fn compile_filter(&self) -> Result<Option<regex::Regex>, AnyError> {
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
            user_agent: default_user_agent(),
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

async fn popen(cmd: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<Output, AnyError> {
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

        return Err(format!(
            "git clone commnad failed with error code {:?}",
            output.status
        )
        .into());
    }

    Ok(output)
}

async fn git_clone(src: &str, dst: &Path, envs: &[(&str, &str)]) -> Result<(), AnyError> {
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
    .map_err(|e| -> AnyError {
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

async fn load_config_file(config: Config) -> Result<Config, AnyError> {
    match config.config_file.as_ref() {
        Some(path) => {
            debug!(?path, "loading config file");
            let toml = tokio::fs::read_to_string(&path).await?;
            let config: Config = match toml::from_str(&toml) {
                Ok(c) => c,
                Err(e) => panic!(
                    "\nfatal error: parsing config file at {} failed:\n\n{}\n\n",
                    path.display(),
                    e
                ),
            };
            Ok(config)
        }

        None => Ok(config),
    }
}

async fn load_registry_config(clone_dir: &Path) -> Result<RegistryConfig, AnyError> {
    let json = tokio::fs::read_to_string(clone_dir.join("config.json")).await?;
    let parsed = serde_json::from_str(&json)?;
    Ok(parsed)
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
) -> Result<Vec<CrateVersion>, AnyError> {
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

    let crate_versions: Vec<Result<Vec<CrateVersion>, AnyError>> =
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

async fn ensure_dir_exists<P: AsRef<std::path::Path>>(path: P) -> Result<(), AnyError> {
    match tokio::fs::metadata(path.as_ref()).await {
        Ok(meta) if meta.is_dir() => Ok(()),

        Ok(meta) /* if ! meta.is_dir() */ => {
            debug_assert!( ! meta.is_dir());
            Err(format!("path exists, but is not a directory: {:?}", path.as_ref()).into())
        }

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(&path).await?;
            Ok(())
        }

        Err(e) => Err(e.into()),
    }
}

async fn ensure_file_parent_dir_exists<P: AsRef<std::path::Path>>(path: P) -> Result<(), AnyError> {
    if let Some(parent_dir) = path.as_ref().parent() {
        ensure_dir_exists(parent_dir).await
    } else {
        Ok(())
    }
}

// relative_index_* fns taken from rust-lang/crates.io source code

/// Returns the relative path to the crate index file.
/// Does not perform conversion to lowercase.
fn relative_index_file_helper(name: &str) -> Vec<&str> {
    match name.len() {
        1 => vec!["1", name],
        2 => vec!["2", name],
        3 => vec!["3", &name[..1], name],
        _ => vec![&name[0..2], &name[2..4], name],
    }
}

// /// Returns the relative path to the crate index file that corresponds to
// /// the given crate name as a path (i.e. with platform-dependent folder separators).
// ///
// /// see <https://doc.rust-lang.org/cargo/reference/registries.html#index-format>
// fn relative_index_file(name: &str) -> PathBuf {
//     let name = name.to_lowercase();
//     Self::relative_index_file_helper(&name).iter().collect()
// }
//
// /// Returns the relative path to the crate index file that corresponds to
// /// the given crate name for usage in URLs (i.e. with `/` separator).
// ///
// /// see <https://doc.rust-lang.org/cargo/reference/registries.html#index-format>
// fn relative_index_file_for_url(name: &str) -> String {
//     let name = name.to_lowercase();
//     Self::relative_index_file_helper(&name).join("/")
// }

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

async fn download_versions(
    config: &Config,
    registry_config: &RegistryConfig,
    versions: Vec<CrateVersion>,
) -> Result<(), AnyError> {
    let begin = Instant::now();
    ensure_dir_exists(&config.output.path).await?;

    let rate_limit = RateLimiter::direct(Quota::per_second(config.http.requests_per_second));

    // piggy back on Registry Config's url template functionality
    // to render the relative output path
    let output_config = RegistryConfig {
        dl: config.output.format.as_deref().unwrap_or("").to_string(),
        api: String::new(),
        allowed_registries: vec![],
        auth_required: None,
    };

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
        let output_config = &output_config;

        async move {
            let url =
                url::Url::parse(&registry_config.get_dl_url(&vers.name, &vers.vers, &vers.cksum))?;

            let output_path = config.output.path.join(output_config.get_dl_url(
                &vers.name,
                &vers.vers,
                &vers.cksum,
            ));

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
                Err::<_, AnyError>(format!("error response {:?} from server", status).into())
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

    let results: Vec<Result<Option<PathBuf>, AnyError>> = outer_stream.collect().await;

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

async fn run(config: Config) -> Result<(), AnyError> {
    let config = load_config_file(config).await?;
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

    let registry_config = load_registry_config(index_path).await?;

    let versions = get_crate_versions(&config, index_path).await?;

    download_versions(&config, &registry_config, versions).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_config() {
        const TOML: &str = include_str!("../config.toml.sample");
        let _config: Config = toml::from_str(TOML).unwrap();
    }

    #[test]
    fn sanity_check_url_template_rendering() {
        let config = RegistryConfig {
            dl: "{prefix}__{lowerprefix}__{sha256-checksum}__{crate}__{version}.tar.gz".to_string(),
            api: String::new(),
            allowed_registries: vec![],
            auth_required: Some(true),
        };

        assert_eq!(
            config.get_dl_url("iM-14yo-LoL", "0.69.42-rc.123", "c5b6fc73"),
            "iM/-1/iM-14yo-LoL__im/-1/im-14yo-lol__c5b6fc73__iM-14yo-LoL__0.69.42-rc.123.tar.gz",
        );
    }

    #[test]
    fn sanity_check_url_template_used_for_output_path() {
        let config = RegistryConfig {
            dl: "{crate}/{sha256-checksum}".to_string(),
            api: String::new(),
            allowed_registries: vec![],
            auth_required: Some(true),
        };

        let output_path =
            Path::new("output").join(config.get_dl_url("lazy-static", "1.0.0", "x7b2z899"));

        assert_eq!(output_path, Path::new("output/lazy-static/x7b2z899"),);
    }

    #[test]
    fn verify_blank_url_template_works_same_as_default() {
        let c1 = RegistryConfig {
            dl: "{crate}/{version}/download".to_string(),
            api: String::new(),
            allowed_registries: vec![],
            auth_required: Some(true),
        };
        let mut c2 = c1.clone();
        c2.dl = "".to_string();

        assert_eq!(
            c1.get_dl_url("lazy-static", "1.0.0", "x7b2z899"),
            c2.get_dl_url("lazy-static", "1.0.0", "x7b2z899"),
        );
        assert_eq!(
            Path::new("output").join(c1.get_dl_url("lazy-static", "1.0.0", "x7b2z899")),
            Path::new("output/lazy-static/1.0.0/download"),
        );
    }
}

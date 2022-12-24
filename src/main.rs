use anyhow::bail;
use clap::Parser;
use futures::stream::StreamExt;
use parking_lot::Mutex;
use pretty_toa::ThousandsSep;
use rayon::ThreadPoolBuilder;
use semver::Version;
use serde::Deserialize;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use tracing_subscriber::filter::EnvFilter;
use url::Url;
use walkdir::{DirEntry, WalkDir};

const USER_AGENT: &str = concat!("dtolnay/get-all-crates/v", env!("CARGO_PKG_VERSION"));

#[derive(Deserialize)]
struct CrateVersion {
    name: String,
    vers: Version,
    #[serde(with = "hex")]
    #[allow(dead_code)]
    cksum: [u8; 32],
}

/// Download all .crate files from a registry server.
#[derive(Parser)]
#[command(author, version)]
struct Config {
    /// Local path where the crates.io-index is already cloned
    #[arg(long = "index", value_name = "PATH")]
    index_path: PathBuf,

    /// Directory in which to put downloaded .crate files
    #[arg(long = "out", value_name = "PATH")]
    output_path: PathBuf,

    /// Limit number of concurrent requests in flight
    #[arg(short = 'j', value_name = "INT", default_value = "50")]
    max_concurrent_requests: NonZeroU32,
}

fn setup_logger() {
    let env_filter = EnvFilter::from_default_env();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(true);
    builder.init();
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

fn get_crate_versions(path: &Path) -> anyhow::Result<Vec<CrateVersion>> {
    let file = File::open(path).map_err(|e| {
        error!(err = ?e, ?path, "failed to open file");
        e
    })?;
    let buf = BufReader::new(file);
    let mut out = Vec::new();
    for line in buf.lines() {
        let line = line?;
        let vers: CrateVersion = serde_json::from_str(&line).map_err(|e| {
            error!(?path, "{},", e);
            e
        })?;
        out.push(vers);
    }
    Ok(out)
}

fn get_all_crate_versions(config: &Config) -> anyhow::Result<Vec<CrateVersion>> {
    let num_threads = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let thread_pool = ThreadPoolBuilder::new().num_threads(num_threads).build()?;

    let crate_versions = Mutex::new(Vec::new());
    let mut n_files = 0;
    thread_pool.in_place_scope(|scope| {
        for entry in WalkDir::new(&config.index_path)
            .max_depth(3)
            .into_iter()
            .filter_entry(|e| !is_hidden(e))
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warn!(?error, "walkdir result is error");
                    continue;
                }
            };

            if !(entry.file_type().is_file() && entry.depth() >= 2 && entry.depth() <= 3) {
                continue;
            }

            n_files += 1;
            scope.spawn(|_scope| {
                let path = entry.into_path();
                match get_crate_versions(&path) {
                    Ok(vec) => crate_versions.lock().extend(vec),
                    Err(err) => error!(?err, "parsing metadata failed, skipping file"),
                }
            });
        }
    });

    let crate_versions = crate_versions.into_inner();

    info!(
        n_files,
        n_download_targets = crate_versions.len(),
        "collected {} total crate versions to download",
        crate_versions.len()
    );

    Ok(crate_versions)
}

async fn ensure_dir_exists(path: &Path) -> anyhow::Result<()> {
    match tokio::fs::metadata(path).await {
        Ok(meta) if meta.is_dir() => Ok(()),

        Ok(meta) /* if ! meta.is_dir() */ => {
            debug_assert!( ! meta.is_dir());
            bail!("path exists, but is not a directory: {:?}", path);
        }

        Err(e) if e.kind() == ErrorKind::NotFound => {
            tokio::fs::create_dir_all(&path).await?;
            Ok(())
        }

        Err(e) => Err(e.into()),
    }
}

async fn ensure_file_parent_dir_exists(path: &Path) -> anyhow::Result<()> {
    if let Some(parent_dir) = path.parent() {
        ensure_dir_exists(parent_dir).await
    } else {
        Ok(())
    }
}

fn filesize(bytes: usize) -> impl Display {
    struct FileSize {
        bytes: usize,
    }

    impl Display for FileSize {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            let kb = self.bytes as f64 / 1024.0;
            let mb = kb / 1024.0;
            let (quantity, suffix) = if mb > 2048.0 {
                let gb = mb / 1024.0;
                ((gb * 100.0).round() / 100.0, 'G')
            } else if mb < 0.75 {
                ((kb * 10.0).round() / 10.0, 'K')
            } else {
                ((mb * 10.0).round() / 10.0, 'M')
            };
            write!(formatter, "{}{}", quantity.thousands_sep(), suffix)
        }
    }

    FileSize { bytes }
}

fn millis(duration: Duration) -> Duration {
    Duration::from_millis(duration.as_millis() as u64)
}

async fn download_versions(config: &Config, versions: Vec<CrateVersion>) -> anyhow::Result<()> {
    let begin = Instant::now();
    ensure_dir_exists(&config.output_path).await?;

    let http_client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    info!(
        max_concurrency = config.max_concurrent_requests,
        "downloading crates",
    );

    let stream = futures::stream::iter(versions.into_iter().map(|vers| {
        let req_begin = Instant::now();
        let http_client = http_client.clone();

        async move {
            let url = Url::parse(&format!(
                "https://static.crates.io/crates/{name}/{name}-{version}.crate",
                name = vers.name,
                version = vers.vers,
            ))?;

            let name_lower = vers.name.to_ascii_lowercase();
            let output_path = config
                .output_path
                .join(PathBuf::from_iter(match name_lower.len() {
                    1 => vec!["1"],
                    2 => vec!["2"],
                    3 => vec!["3", &name_lower[..1]],
                    _ => vec![&name_lower[0..2], &name_lower[2..4]],
                }))
                .join(name_lower)
                .join(format!("{}-{}.crate", vers.name, vers.vers));

            let req = http_client.get(url);
            let resp = req.send().await?;
            let status = resp.status();
            let body = resp.bytes().await?;

            if !status.is_success() {
                error!(status = ?status, "download failed");
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
                    crate = %vers.name,
                    version = %vers.vers,
                    size = %filesize(body.len()),
                    elapsed = ?millis(req_begin.elapsed()),
                );
                Ok(Some(output_path))
            }
        }
    }))
    .buffer_unordered(config.max_concurrent_requests.get() as usize);

    let results: Vec<anyhow::Result<Option<PathBuf>>> = stream.collect().await;

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
        millis(begin.elapsed())
    );

    ret
}

fn main() -> anyhow::Result<()> {
    let begin = Instant::now();

    setup_logger();

    info!("initializing...");

    let config = Config::parse();
    let versions = get_all_crate_versions(&config)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        if false {
            download_versions(&config, versions).await?;
        }
        info!("finished in {:?}", millis(begin.elapsed()));
        Ok(())
    })
}

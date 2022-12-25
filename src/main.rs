use anyhow::bail;
use clap::Parser;
use futures::stream::StreamExt;
use num_format::Locale;
use parking_lot::Mutex;
use rayon::ThreadPoolBuilder;
use semver::Version;
use serde::de::{Deserializer, Visitor};
use serde::Deserialize;
use std::fmt::{self, Display};
use std::fs;
use std::io::ErrorKind;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::{Directive, LevelFilter};
use url::Url;
use walkdir::{DirEntry, WalkDir};

const USER_AGENT: &str = concat!("dtolnay/get-all-crates/v", env!("CARGO_PKG_VERSION"));

struct CrateVersions {
    name: String,
    versions: Vec<CrateVersion>,
}

struct CrateVersion {
    version: Version,
    #[allow(dead_code)]
    checksum: [u8; 32],
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

fn setup_tracing() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(Directive::from(LevelFilter::INFO))
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .without_time()
        .with_target(false)
        .init();
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

fn get_crate_versions(path: &Path) -> anyhow::Result<CrateVersions> {
    #[derive(Deserialize)]
    struct LenientCrateVersion<'a> {
        name: &'a str,
        #[serde(rename = "vers")]
        version: ProbablyVersion,
        #[serde(rename = "cksum", with = "hex")]
        checksum: [u8; 32],
    }

    enum ProbablyVersion {
        Ok(Version),
        Err {
            string: String,
            error: semver::Error,
        },
    }

    impl<'de> Deserialize<'de> for ProbablyVersion {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(ProbablyVersionVisitor)
        }
    }

    struct ProbablyVersionVisitor;

    impl<'de> Visitor<'de> for ProbablyVersionVisitor {
        type Value = ProbablyVersion;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("semver version")
        }

        fn visit_str<E: serde::de::Error>(self, string: &str) -> Result<Self::Value, E> {
            match Version::parse(string) {
                Ok(version) => Ok(ProbablyVersion::Ok(version)),
                Err(error) => Ok(ProbablyVersion::Err {
                    string: string.to_owned(),
                    error,
                }),
            }
        }
    }

    let content = fs::read(path)?;
    let deserializer = serde_json::Deserializer::from_slice(&content);
    let mut vec = Vec::new();
    let mut crate_name = None;
    for line in deserializer.into_iter::<LenientCrateVersion>() {
        let line = line?;
        crate_name = Some(line.name);
        let version = match line.version {
            ProbablyVersion::Ok(version) => version,
            ProbablyVersion::Err { string, error } => {
                warn!(version = %string, ?path, "{}", error);
                continue;
            }
        };
        vec.push(CrateVersion {
            version,
            checksum: line.checksum,
        });
    }
    Ok(CrateVersions {
        name: crate_name
            .unwrap_or_else(|| path.file_name().unwrap().to_str().unwrap())
            .to_owned(),
        versions: vec,
    })
}

fn get_all_crate_versions(config: &Config) -> anyhow::Result<Vec<CrateVersions>> {
    let num_threads = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let thread_pool = ThreadPoolBuilder::new().num_threads(num_threads).build()?;

    let crate_versions = Mutex::new(Vec::new());
    let mut n_crates = 0;
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

            n_crates += 1;
            scope.spawn(|_scope| {
                let path = entry.into_path();
                match get_crate_versions(&path) {
                    Ok(vec) => crate_versions.lock().push(vec),
                    Err(err) => error!(?path, "{},", err),
                }
            });
        }
    });

    let crate_versions = crate_versions.into_inner();
    info!(
        n_crates = %thousands(n_crates),
        n_versions = %thousands(crate_versions.len()),
        "collected",
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

fn thousands(n: usize) -> impl Display {
    struct Thousands(usize);

    impl Display for Thousands {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            let mut buffer = num_format::Buffer::new();
            buffer.write_formatted(&self.0, &Locale::en);
            formatter.write_str(buffer.as_str())
        }
    }

    Thousands(n)
}

fn millis(duration: Duration) -> Duration {
    Duration::from_millis(duration.as_millis() as u64)
}

async fn download_versions(config: &Config, versions: Vec<CrateVersions>) -> anyhow::Result<()> {
    ensure_dir_exists(&config.output_path).await?;

    let http_client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    info!(
        max_concurrency = config.max_concurrent_requests,
        "downloading crates",
    );

    let iter = versions
        .iter()
        .flat_map(|krate| krate.versions.iter().map(|vers| (&krate.name, vers)))
        .map(|(name, vers)| {
            let req_begin = Instant::now();
            let http_client = http_client.clone();

            async move {
                let url = Url::parse(&format!(
                    "https://static.crates.io/crates/{name}/{name}-{version}.crate",
                    version = vers.version,
                ))?;

                let name_lower = name.to_ascii_lowercase();
                let output_path = config
                    .output_path
                    .join(PathBuf::from_iter(match name_lower.len() {
                        1 => vec!["1"],
                        2 => vec!["2"],
                        3 => vec!["3", &name_lower[..1]],
                        _ => vec![&name_lower[0..2], &name_lower[2..4]],
                    }))
                    .join(name_lower)
                    .join(format!("{}-{}.crate", name, vers.version));

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
                        crate = %name,
                        version = %vers.version,
                        elapsed = ?millis(req_begin.elapsed()),
                    );
                    Ok(Some(output_path))
                }
            }
        });

    let results = futures::stream::iter(iter)
        .buffer_unordered(config.max_concurrent_requests.get() as usize)
        .collect::<Vec<anyhow::Result<Option<PathBuf>>>>()
        .await;

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
    info!(n_ok, n_err, n_skip);
    ret
}

fn main() -> anyhow::Result<()> {
    let begin = Instant::now();

    setup_tracing();

    info!("initializing...");

    let config = Config::parse();

    let mut versions = get_all_crate_versions(&config)?;
    versions.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    if true {
        versions.truncate(50);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        download_versions(&config, versions).await?;
        info!("finished in {:?}", millis(begin.elapsed()));
        Ok(())
    })
}

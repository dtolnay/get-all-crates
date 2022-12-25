use anyhow::bail;
use bytes::Bytes;
use clap::Parser;
use futures::stream::StreamExt;
use num_format::Locale;
use parking_lot::Mutex;
use rayon::ThreadPoolBuilder;
use semver::Version;
use serde::de::{Deserializer, Visitor};
use serde::Deserialize;
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::fs;
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

fn dir_for_crate(output_path: &Path, name: &str) -> PathBuf {
    let mut path = output_path.to_owned();
    let name_lower = name.to_ascii_lowercase();
    match name_lower.len() {
        1 => path.push("1"),
        2 => path.push("2"),
        3 => path.extend(["3", &name_lower[..1]]),
        _ => path.extend([&name_lower[0..2], &name_lower[2..4]]),
    }
    path.push(name_lower);
    path
}

enum DownloadResult {
    Exists {
        path: PathBuf,
        expected_checksum: [u8; 32],
    },
    Downloaded {
        path: PathBuf,
        body: Bytes,
    },
}

async fn download_version(
    http_client: &reqwest::Client,
    dir: PathBuf,
    name: &str,
    vers: &CrateVersion,
) -> anyhow::Result<DownloadResult> {
    let mut output_path = dir;
    output_path.push(format!("{}-{}.crate", name, vers.version));
    if output_path.try_exists()? {
        return Ok(DownloadResult::Exists {
            path: output_path,
            expected_checksum: vers.checksum,
        });
    }

    let url = Url::parse(&format!(
        "https://static.crates.io/crates/{name}/{name}-{version}.crate",
        version = vers.version,
    ))?;

    let req_begin = Instant::now();
    let req = http_client.get(url);
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        error!(status = ?status, "download failed");
        bail!("error response {:?} from server", status);
    }

    let body = resp.bytes().await?;

    info!(
        crate = %name,
        version = %vers.version,
        elapsed = ?millis(req_begin.elapsed()),
    );

    Ok(DownloadResult::Downloaded {
        path: output_path,
        body,
    })
}

fn finish(result: DownloadResult) -> anyhow::Result<()> {
    match result {
        DownloadResult::Exists {
            path,
            expected_checksum: _,
        } => {
            let _bytes = fs::read(path)?;
            // TODO: checksum
            Ok(())
        }
        DownloadResult::Downloaded { path, body } => {
            fs::write(path, body.slice(..))?;
            Ok(())
        }
    }
}

async fn download_versions(config: &Config, versions: Vec<CrateVersions>) -> anyhow::Result<()> {
    let http_client = &reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    info!(
        max_concurrency = config.max_concurrent_requests,
        "downloading crates",
    );

    let iter = versions.iter().flat_map(|krate| {
        let dir = dir_for_crate(&config.output_path, &krate.name);
        let versions = match fs::create_dir_all(&dir) {
            Ok(()) => &*krate.versions,
            Err(err) => {
                error!(directory = ?dir, %err, "failed to create");
                &[]
            }
        };
        versions
            .iter()
            .map(move |vers| download_version(http_client, dir.clone(), &krate.name, vers))
    });

    futures::stream::iter(iter)
        .buffer_unordered(config.max_concurrent_requests.get() as usize)
        .for_each(|download| async {
            if let Err(err) = download.and_then(finish) {
                error!(%err);
            }
        })
        .await;

    Ok(())
}

fn cmp_ignore_ascii_case(a: &str, b: &str) -> Ordering {
    struct CaseAgnosticByte(u8);

    impl Ord for CaseAgnosticByte {
        fn cmp(&self, rhs: &Self) -> Ordering {
            self.0.to_ascii_lowercase().cmp(&rhs.0.to_ascii_lowercase())
        }
    }

    impl PartialOrd for CaseAgnosticByte {
        fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
            Some(self.cmp(rhs))
        }
    }

    impl Eq for CaseAgnosticByte {}

    impl PartialEq for CaseAgnosticByte {
        fn eq(&self, rhs: &Self) -> bool {
            self.cmp(rhs) == Ordering::Equal
        }
    }

    a.bytes()
        .map(CaseAgnosticByte)
        .cmp(b.bytes().map(CaseAgnosticByte))
}

fn main() -> anyhow::Result<()> {
    let begin = Instant::now();

    setup_tracing();

    info!("initializing...");

    let config = Config::parse();

    let mut versions = get_all_crate_versions(&config)?;
    versions.sort_unstable_by(|a, b| cmp_ignore_ascii_case(&a.name, &b.name));
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

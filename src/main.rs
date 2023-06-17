#![allow(clippy::cast_possible_truncation, clippy::match_single_binding)]

mod crateversion;
mod forbidden;

use crate::crateversion::{Checksum, CrateVersion};
use anyhow::bail;
use bytes::Bytes;
use clap::Parser;
use crypto_hash::{Algorithm, Hasher};
use futures::stream::StreamExt;
use memmap2::Mmap;
use num_format::Locale;
use parking_lot::Mutex;
use rayon::ThreadPoolBuilder;
use semver::Version;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde_derive::Deserialize;
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io::{self, Write};
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

/// Download .crate files of all versions of all crates from crates.io.
#[derive(Parser)]
#[command(author, version)]
struct Config {
    /// Local path where the crates.io-index is already cloned
    #[arg(long = "index", value_name = "PATH")]
    index_path: PathBuf,

    /// Directory in which to put downloaded .crate files
    #[arg(long = "out", value_name = "PATH")]
    output_path: PathBuf,

    /// Only get highest non-prerelease non-yanked version of each crate
    #[arg(long)]
    latest: bool,

    /// Limit number of concurrent requests in flight
    #[arg(short = 'j', value_name = "INT", default_value = "50")]
    max_concurrent_requests: NonZeroU32,

    /// Verify checksum of all previously downloaded crates
    #[arg(long)]
    verify: bool,
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
        .map_or(false, |s| s.starts_with('.'))
}

fn checksum(bytes: &[u8]) -> Checksum {
    let mut hasher = Hasher::new(Algorithm::SHA256);
    hasher.write_all(bytes).unwrap();
    let mut checksum = [0; 32];
    checksum.copy_from_slice(&hasher.finish());
    checksum
}

fn verify_checksum(crate_file_path: &Path, expected_checksum: Checksum) -> io::Result<()> {
    let actual_checksum = match File::open(crate_file_path)? {
        file => checksum(&unsafe { Mmap::map(&file) }?),
    };
    if expected_checksum != actual_checksum {
        error!(path = ?crate_file_path, "checksum mismatch");
    }
    Ok(())
}

fn get_crate_versions(path: &Path, config: &Config) -> anyhow::Result<CrateVersions> {
    #[derive(Deserialize)]
    struct LenientCrateVersion<'a> {
        name: &'a str,
        #[serde(rename = "vers")]
        version: ProbablyVersion,
        #[serde(rename = "cksum", with = "hex")]
        checksum: Checksum,
        yanked: bool,
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
        if config.latest && line.yanked {
            continue;
        }
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

    if config.latest && !vec.is_empty() {
        let max_non_prerelease = vec.iter().filter(|v| v.version.pre.is_empty()).max();
        let max = if let Some(max_non_prerelease) = max_non_prerelease {
            max_non_prerelease
        } else {
            vec.iter().max().unwrap()
        };
        vec = vec![max.clone()];
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
                let mut vers = match get_crate_versions(&path, config) {
                    Ok(vers) => vers,
                    Err(err) => return error!(?path, "{},", err),
                };
                let name = &vers.name;
                let output_dir = dir_for_crate(&config.output_path, name);
                if let Err(err) = fs::create_dir_all(&output_dir) {
                    error!(directory = ?output_dir, %err, "failed to create");
                }
                vers.versions.retain(|vers| {
                    let path = output_dir.join(format!("{}-{}.crate", name, vers.version));
                    match path.try_exists() {
                        Ok(true) => {
                            if config.verify {
                                if let Err(err) = verify_checksum(&path, vers.checksum) {
                                    error!(?path, "{},", err);
                                }
                            }
                            false
                        }
                        Ok(false) => true,
                        Err(err) => {
                            error!(?path, "{},", err);
                            false
                        }
                    }
                });
                if !vers.versions.is_empty() {
                    crate_versions.lock().push(vers);
                }
            });
        }
    });

    let crate_versions = crate_versions.into_inner();
    let n_versions = crate_versions
        .iter()
        .map(|krate| krate.versions.len())
        .sum();
    info!(
        n_crates = %thousands(n_crates),
        n_versions = %thousands(n_versions),
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

struct Download {
    output_path: PathBuf,
    body: Bytes,
    expected_checksum: Checksum,
}

async fn download_version(
    http_client: &reqwest::Client,
    dir: PathBuf,
    name: &str,
    vers: &CrateVersion,
) -> anyhow::Result<Option<Download>> {
    let mut output_path = dir;
    output_path.push(format!("{}-{}.crate", name, vers.version));

    let url_string = format!(
        "https://static.crates.io/crates/{name}/{name}-{version}.crate",
        version = vers.version,
    );
    let url = Url::parse(&url_string)?;

    let req_begin = Instant::now();
    let req = http_client.get(url);
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        // Some crates in the index are consistently broken...
        if status == 403 && forbidden::known_broken(name, &vers.version) {
            return Ok(None);
        }
        bail!("{} {}", status, url_string);
    }

    let body = resp.bytes().await?;

    info!(
        crate = %name,
        version = %vers.version,
        elapsed = ?millis(req_begin.elapsed()),
    );

    Ok(Some(Download {
        output_path,
        body,
        expected_checksum: vers.checksum,
    }))
}

async fn download_versions(config: &Config, versions: Vec<CrateVersions>) -> anyhow::Result<()> {
    let http_client = &reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    info!(
        max_concurrency = config.max_concurrent_requests,
        "downloading crates",
    );

    let iter = versions.iter().flat_map(|krate| {
        let dir = dir_for_crate(&config.output_path, &krate.name);
        krate
            .versions
            .iter()
            .map(move |vers| download_version(http_client, dir.clone(), &krate.name, vers))
    });

    futures::stream::iter(iter)
        .buffer_unordered(config.max_concurrent_requests.get() as usize)
        .for_each_concurrent(None, |download| async {
            match download {
                Ok(Some(download)) => {
                    let task = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                        if download.expected_checksum == checksum(&download.body) {
                            fs::write(download.output_path, download.body)?;
                        } else {
                            error!(path = ?download.output_path, "checksum mismatch");
                        }
                        Ok(())
                    });
                    match task.await.map_err(anyhow::Error::new) {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) | Err(err) => error!("{}", err),
                    }
                }
                Ok(None) => {}
                Err(err) => error!("{}", err),
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
    let config = Config::parse();

    setup_tracing();

    let begin = Instant::now();

    let mut versions = get_all_crate_versions(&config)?;
    versions.sort_unstable_by(|a, b| cmp_ignore_ascii_case(&a.name, &b.name));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        download_versions(&config, versions).await?;
        info!("finished in {:?}", millis(begin.elapsed()));
        Ok(())
    })
}

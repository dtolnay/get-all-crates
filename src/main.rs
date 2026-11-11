#![allow(
    clippy::cast_possible_truncation,
    clippy::elidable_lifetime_names,
    clippy::match_single_binding,
    clippy::needless_lifetimes,
    clippy::unconditional_recursion, // https://github.com/rust-lang/rust-clippy/issues/12052
)]

mod crateversion;

use crate::crateversion::{Checksum, CrateVersion};
use anyhow::bail;
use bytesize::ByteSize;
use clap::Parser;
use crypto_hash::{Algorithm, Hasher};
use futures::stream::StreamExt;
use indicatif::ProgressStyle;
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
use tokio::io::AsyncWriteExt;
use tokio::task::spawn_blocking;
use tracing::{error, info, instrument, warn, Span};
use tracing_indicatif::span_ext::IndicatifSpanExt;
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::{Directive, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use url::Url;
use walkdir::{DirEntry, WalkDir};

const USER_AGENT: &str = concat!("dtolnay/get-all-crates/v", env!("CARGO_PKG_VERSION"));

/// Maximum buffer size for writing a downloaded crate to disk. Crates have a
/// median size of 31 KiB (p90 328 KiB), so 256 KiB fits most of them (~85-90%)
/// in a single write.
const WRITE_BUFFER_SIZE: usize = 256 * 1024;

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

    /// Delete and re-download existing .crate files with mismatched checksum
    #[arg(long, requires = "verify")]
    replace_mismatch: bool,
}

fn setup_tracing() {
    let indicatif_layer = IndicatifLayer::new().with_max_progress_bars(1, None);

    let env_filter = EnvFilter::builder()
        .with_default_directive(Directive::from(LevelFilter::INFO))
        .from_env_lossy();

    let log_layer = tracing_subscriber::fmt::layer()
        .without_time()
        .with_target(false)
        .with_writer(indicatif_layer.get_stderr_writer())
        .with_filter(env_filter);

    tracing_subscriber::registry()
        .with(log_layer)
        .with(indicatif_layer)
        .init();
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|s| s.starts_with('.'))
}

fn checksum(bytes: &[u8]) -> Checksum {
    let mut hasher = Hasher::new(Algorithm::SHA256);
    hasher.write_all(bytes).unwrap();
    let mut checksum = [0; 32];
    checksum.copy_from_slice(&hasher.finish());
    checksum
}

enum ChecksumVerification {
    Match,
    Mismatch,
}

fn verify_checksum(
    crate_file_path: &Path,
    expected_checksum: Checksum,
) -> io::Result<ChecksumVerification> {
    let actual_checksum = match File::open(crate_file_path)? {
        file => checksum(&unsafe { Mmap::map(&file) }?),
    };
    if expected_checksum == actual_checksum {
        Ok(ChecksumVerification::Match)
    } else {
        Ok(ChecksumVerification::Mismatch)
    }
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

struct AllCrateVersions {
    vec: Vec<CrateVersions>,
    count: u32,
}

fn get_all_crate_versions(config: &Config) -> anyhow::Result<AllCrateVersions> {
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
                            config.verify
                                && match verify_checksum(&path, vers.checksum) {
                                    Ok(ChecksumVerification::Match) => false,
                                    Ok(ChecksumVerification::Mismatch) => {
                                        error!(?path, "checksum mismatch");
                                        config.replace_mismatch
                                    }
                                    Err(err) => {
                                        error!(?path, "{},", err);
                                        false
                                    }
                                }
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
        .map(|krate| krate.versions.len() as u32)
        .sum();
    info!(
        n_crates = %thousands(n_crates),
        n_versions = %thousands(n_versions),
        "collected",
    );
    Ok(AllCrateVersions {
        vec: crate_versions,
        count: n_versions,
    })
}

fn thousands(n: u32) -> impl Display {
    struct Thousands(u32);

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

async fn download_version(
    http_client: &reqwest::Client,
    dir: PathBuf,
    name: &str,
    vers: &CrateVersion,
) -> anyhow::Result<()> {
    let file_name = format!("{}-{}.crate", name, vers.version);
    let output_path = dir.join(&file_name);

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
        bail!("{status} {url_string}");
    }

    // Stream the body into a temporary file next to its final location so that
    // memory use stays bounded by the number of concurrent requests, regardless
    // of how fast the disk is. The temporary file is deleted when `temp_path` is
    // dropped, unless it has been persisted under its final name.
    let (file, temp_path) = spawn_blocking(move || {
        let prefix = format!(".{file_name}.");
        let mut builder = tempfile::Builder::new();
        builder.prefix(&prefix).suffix(".part");
        // tempfile defaults to 0o600, which `persist` keeps. Match the 0o644
        // (minus umask) that a plain `fs::write` would have produced.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o644));
        }
        builder.tempfile_in(dir)
    })
    .await??
    .into_parts();

    let (checksum, len) = stream_to_file(resp, tokio::fs::File::from_std(file)).await?;
    if checksum != vers.checksum {
        error!(path = ?output_path, "checksum mismatch");
        return Ok(());
    }
    spawn_blocking(move || temp_path.persist(output_path)).await??;

    info!(
        crate = %name,
        version = %vers.version,
        elapsed = ?millis(req_begin.elapsed()),
        size = %ByteSize(len),
    );

    Ok(())
}

async fn stream_to_file(
    mut resp: reqwest::Response,
    file: tokio::fs::File,
) -> anyhow::Result<(Checksum, u64)> {
    // Coalesce small (~16 KiB) network chunks into fewer blocking writes, and
    // don't allocate more than the body needs when its size is known.
    let capacity = resp
        .content_length()
        .and_then(|len| usize::try_from(len).ok())
        .map_or(WRITE_BUFFER_SIZE, |len| len.min(WRITE_BUFFER_SIZE));

    let mut file = tokio::io::BufWriter::with_capacity(capacity, file);
    let mut hasher = Hasher::new(Algorithm::SHA256);

    let mut len = 0;
    while let Some(chunk) = resp.chunk().await? {
        hasher.write_all(&chunk)?;
        file.write_all(&chunk).await?;
        len += chunk.len() as u64;
    }
    file.flush().await?;
    drop(file);

    let mut checksum = [0; 32];
    checksum.copy_from_slice(&hasher.finish());
    Ok((checksum, len))
}

#[instrument(skip_all, level = "debug")]
async fn download_versions(config: &Config, versions: AllCrateVersions) -> anyhow::Result<()> {
    let http_client = &reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    info!(
        max_concurrency = config.max_concurrent_requests,
        "downloading crates",
    );

    let pb_style =
        ProgressStyle::with_template("{bar:60} ({pos}/{len}, ETA {eta}) {wide_msg}").unwrap();

    let span = Span::current();
    span.pb_set_style(&pb_style);
    span.pb_set_length(u64::from(versions.count));

    let iter = versions.vec.iter().flat_map(|krate| {
        let dir = dir_for_crate(&config.output_path, &krate.name);
        krate
            .versions
            .iter()
            .map(move |vers| (krate, dir.clone(), vers))
    });

    futures::stream::iter(iter)
        .for_each_concurrent(
            config.max_concurrent_requests.get() as usize,
            |(krate, dir, vers)| async move {
                Span::current().pb_set_message(&krate.name);
                if let Err(err) = download_version(http_client, dir, &krate.name, vers).await {
                    error!(crate = %krate.name, version = %vers.version, "{}", err);
                }
                Span::current().pb_inc(1);
            },
        )
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
    versions
        .vec
        .sort_unstable_by(|a, b| cmp_ignore_ascii_case(&a.name, &b.name));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        download_versions(&config, versions).await?;
        info!("finished in {:?}", millis(begin.elapsed()));
        Ok(())
    })
}

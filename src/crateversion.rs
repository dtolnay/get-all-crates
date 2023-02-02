use semver::Version;
use std::cmp::Ordering;

#[derive(Clone)]
pub struct CrateVersion {
    pub version: Version,
    #[allow(dead_code)]
    pub checksum: Checksum,
}

pub type Checksum = [u8; 32];

impl Ord for CrateVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let CrateVersion {
            version: this_version,
            checksum: _,
        } = self;
        let CrateVersion {
            version: other_version,
            checksum: _,
        } = other;
        this_version.cmp(other_version)
    }
}

impl PartialOrd for CrateVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Eq for CrateVersion {}

impl PartialEq for CrateVersion {
    fn eq(&self, other: &Self) -> bool {
        let CrateVersion {
            version: this_version,
            checksum: _,
        } = self;
        let CrateVersion {
            version: other_version,
            checksum: _,
        } = other;
        this_version == other_version
    }
}

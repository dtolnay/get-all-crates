use semver::Version;

pub struct CrateVersion {
    pub version: Version,
    #[allow(dead_code)]
    pub checksum: Checksum,
}

pub type Checksum = [u8; 32];

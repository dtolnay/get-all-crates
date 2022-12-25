use semver::Version;

// Some crates in the index have download URLs that consistently return HTTP
// 403 (forbidden). It seems like someone should remove these from the index
// altogether... but for now we handle this by still attempting every download,
// but silently swallowing the error if the failing crate is one of the
// following known broken crate versions.
const KNOWN_BROKEN: &[(&str, Version)] = &[
    ("bork", Version::new(0, 0, 0)),
    ("bork", Version::new(0, 1, 0)),
    ("bork", Version::new(0, 2, 0)),
    ("css-modules", Version::new(0, 1, 0)),
    ("css-modules", Version::new(0, 1, 1)),
    ("css-modules", Version::new(0, 2, 0)),
    ("css-modules", Version::new(0, 3, 0)),
    ("css-modules", Version::new(0, 4, 0)),
    ("css-modules", Version::new(0, 5, 0)),
    ("css-modules", Version::new(0, 5, 1)),
    ("css-modules-macros", Version::new(0, 5, 0)),
    ("css-modules-macros", Version::new(0, 5, 1)),
    ("deploy", Version::new(0, 1, 0)),
    ("deploy", Version::new(0, 1, 1)),
    ("deploy", Version::new(0, 1, 2)),
    ("doccy", Version::new(0, 1, 0)),
    ("doccy", Version::new(0, 1, 1)),
    ("doccy", Version::new(0, 2, 0)),
    ("doccy", Version::new(0, 3, 0)),
    ("etch", Version::new(0, 1, 0)),
    ("etch", Version::new(0, 2, 0)),
    ("etch", Version::new(0, 3, 0)),
    ("etch", Version::new(0, 4, 0)),
    ("glue", Version::new(0, 1, 0)),
    ("glue", Version::new(0, 1, 1)),
    ("glue", Version::new(0, 2, 0)),
    ("glue", Version::new(0, 2, 1)),
    ("glue", Version::new(0, 3, 0)),
    ("glue", Version::new(0, 4, 0)),
    ("glue", Version::new(0, 5, 0)),
    ("glue", Version::new(0, 5, 1)),
    ("glue", Version::new(0, 5, 2)),
    ("glue", Version::new(0, 6, 0)),
    ("glue", Version::new(0, 7, 0)),
    ("glue", Version::new(0, 8, 0)),
    ("glue", Version::new(0, 8, 1)),
    ("glue", Version::new(0, 8, 2)),
    ("glue", Version::new(0, 8, 3)),
    ("peek", Version::new(0, 1, 0)),
    ("peek", Version::new(0, 2, 0)),
    ("peek", Version::new(0, 2, 1)),
    ("peek", Version::new(0, 3, 0)),
    ("peek", Version::new(0, 3, 1)),
    ("pose", Version::new(0, 1, 0)),
    ("pose", Version::new(0, 2, 0)),
    ("pose", Version::new(0, 2, 1)),
];

pub fn known_broken(name: &str, version: &Version) -> bool {
    for (broken_name, broken_version) in KNOWN_BROKEN {
        if *broken_name == name && broken_version == version {
            return true;
        }
    }
    false
}

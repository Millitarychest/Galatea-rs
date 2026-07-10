// FLAGS: Flags are simplified signature building blocks to be used for rule creation. By themself they can say anything from nothing to a full verdict.
// Flags should only ever be additive (i belive, as atm i can not think of any reason i would ever remove them).

use regex::RegexSet;
use std::sync::LazyLock;

// Predefined Flags that can are applied by the telemetry and Engine steps. These can be used for simplified Rule creation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FileFlags {
    #[default]
    None = 0,
    // General
    FileWriteSuccess,
    WhiteListed,
    BlackListed,
    // Static Results
    StaticScanMalicious,
    StaticScanSuspicious,
    StaticScanBeneign,
    // Location based
    InAutoStartLocation,
    InTempLocation,
    // Historic Activity
    RenamedToExecutable,
}

// Regex Matchers
#[derive(Debug)]
struct LocationRuleSpec {
    pattern: &'static str,
    flag: FileFlags,
}

#[derive(Debug)]
struct LocationRules {
    patterns: RegexSet,
    flags: Vec<FileFlags>,
}

static LOCATION_RULE_SPECS: &[LocationRuleSpec] = &[
    LocationRuleSpec {
        pattern: r"^c:\\users\\[^\\]+\\appdata\\local\\temp(?:\\.*|$)",
        flag: FileFlags::InTempLocation,
    },
    LocationRuleSpec {
        pattern: r"^c:\\windows\\temp(?:\\.*|$)",
        flag: FileFlags::InTempLocation,
    },
    LocationRuleSpec {
        pattern: r"^c:\\users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup(?:\\.*|$)",
        flag: FileFlags::InAutoStartLocation,
    },
    LocationRuleSpec {
        pattern: r"^c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup(?:\\.*|$)",
        flag: FileFlags::InAutoStartLocation,
    },
];

static LOCATION_RULES: LazyLock<LocationRules> = LazyLock::new(|| {
    let patterns = RegexSet::new(LOCATION_RULE_SPECS.iter().map(|rule| rule.pattern))
        .expect("location regexes must compile");

    let flags = LOCATION_RULE_SPECS.iter().map(|rule| rule.flag).collect();

    LocationRules { patterns, flags }
});

// gets all matching location based flags based on a normalized path
pub fn get_location_flags(path: &str) -> Vec<FileFlags> {
    let normalized = normalize_location_path(path);
    let rules = &*LOCATION_RULES;
    let mut flags = Vec::new();

    for index in rules.patterns.matches(&normalized) {
        let flag = rules.flags[index];
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }

    flags
}

fn normalize_location_path(path: &str) -> String {
    let path = path.replace('/', "\\").to_ascii_lowercase();

    if let Some(path) = path.strip_prefix(r"\\?\") {
        path.to_string()
    } else {
        path
    }
}


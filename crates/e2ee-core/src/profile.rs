use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId {
    name: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileParseError {
    MissingVersion,
    EmptyName,
    EmptyVersion,
    FloatingVersion,
}

impl fmt::Display for ProfileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MissingVersion => "profile must use name@version",
            Self::EmptyName => "profile name must not be empty",
            Self::EmptyVersion => "profile version must not be empty",
            Self::FloatingVersion => "floating profile versions are forbidden",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ProfileParseError {}

impl ProfileId {
    pub fn parse(value: &str) -> Result<Self, ProfileParseError> {
        let (name, version) = value
            .rsplit_once('@')
            .ok_or(ProfileParseError::MissingVersion)?;
        if name.is_empty() {
            return Err(ProfileParseError::EmptyName);
        }
        if version.is_empty() {
            return Err(ProfileParseError::EmptyVersion);
        }
        if matches!(version, "latest" | "*" | "stable") {
            return Err(ProfileParseError::FloatingVersion);
        }
        Ok(Self {
            name: name.to_owned(),
            version: version.to_owned(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundProfile {
    pub id: ProfileId,
    pub source_standard_version: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProfileSet {
    profiles: BTreeMap<String, BoundProfile>,
}

impl ProfileSet {
    pub fn insert(&mut self, profile: BoundProfile) -> Result<(), &'static str> {
        if let Some(existing) = self.profiles.get(profile.id.name()) {
            if existing.id != profile.id {
                return Err("conflicting versions of the same profile");
            }
        }
        self.profiles
            .insert(profile.id.name().to_owned(), profile);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&BoundProfile> {
        self.profiles.get(name)
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_exact_version() {
        assert!(ProfileId::parse("capsule@0.1.0").is_ok());
        assert_eq!(
            ProfileId::parse("capsule@latest"),
            Err(ProfileParseError::FloatingVersion)
        );
        assert_eq!(
            ProfileId::parse("capsule"),
            Err(ProfileParseError::MissingVersion)
        );
    }

    #[test]
    fn rejects_conflicting_profile_versions() {
        let mut set = ProfileSet::default();
        let first = BoundProfile {
            id: ProfileId::parse("identity@0.1.0").unwrap(),
            source_standard_version: "0.1".into(),
        };
        let second = BoundProfile {
            id: ProfileId::parse("identity@0.2.0").unwrap(),
            source_standard_version: "0.1".into(),
        };
        set.insert(first).unwrap();
        assert!(set.insert(second).is_err());
    }
}

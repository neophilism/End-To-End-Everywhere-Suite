use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    Empty,
    InvalidCharacter,
    MissingSeparator,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "identifier must not be empty",
            Self::InvalidCharacter => "identifier contains an invalid character",
            Self::MissingSeparator => "recipient address must use local@domain form",
        };
        f.write_str(message)
    }
}

impl std::error::Error for IdentityError {}

fn validate_component(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(IdentityError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, IdentityError> {
                validate_component(value)?;
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

typed_id!(UserId);
typed_id!(AccountId);
typed_id!(DeviceId);
typed_id!(EndpointId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub user_id: UserId,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub endpoint_id: EndpointId,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipientAddress {
    local: String,
    domain: String,
}

impl RecipientAddress {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let (local, domain) = value
            .split_once('@')
            .ok_or(IdentityError::MissingSeparator)?;
        if domain.contains('@') {
            return Err(IdentityError::InvalidCharacter);
        }
        validate_component(local)?;
        validate_component(domain)?;
        Ok(Self {
            local: local.to_owned(),
            domain: domain.to_ascii_lowercase(),
        })
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_device_and_endpoint_are_distinct_types() {
        let record = DeviceRecord {
            user_id: UserId::parse("user-1").unwrap(),
            account_id: AccountId::parse("account-1").unwrap(),
            device_id: DeviceId::parse("device-1").unwrap(),
            endpoint_id: EndpointId::parse("endpoint-1").unwrap(),
            enabled: true,
        };

        assert_eq!(record.user_id.as_str(), "user-1");
        assert_eq!(record.account_id.as_str(), "account-1");
        assert_eq!(record.device_id.as_str(), "device-1");
        assert_eq!(record.endpoint_id.as_str(), "endpoint-1");
    }

    #[test]
    fn recipient_addresses_are_canonicalized_without_changing_local_part() {
        let address = RecipientAddress::parse("Alice@EXAMPLE.org").unwrap();
        assert_eq!(address.local(), "Alice");
        assert_eq!(address.domain(), "example.org");
    }

    #[test]
    fn invalid_recipient_addresses_fail_closed() {
        assert_eq!(
            RecipientAddress::parse("alice"),
            Err(IdentityError::MissingSeparator)
        );
        assert!(RecipientAddress::parse("alice@@example.org").is_err());
        assert!(RecipientAddress::parse("@example.org").is_err());
    }
}

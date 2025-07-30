use serde::{Deserialize, Serialize};

/// Threat type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatType {
    /// Spam source (127.0.0.2, 127.0.0.9)
    Spam,
    /// Phishing website (127.0.0.3)
    Phishing,
    /// Malware (127.0.0.4, 127.0.0.6, 127.0.0.7, 127.0.0.11)
    Malware,
    /// Botnet (127.0.0.5)
    Botnet,
    /// Potentially Unwanted Program (127.0.0.10)
    Pup,
    /// Unknown threat type
    Unknown(u8),
}

impl ThreatType {
    /// Parse threat type from IP address last octet
    pub fn from_ip_last_octet(octet: u8) -> Self {
        match octet {
            2 | 9 => ThreatType::Spam,
            3 => ThreatType::Phishing,
            4 | 6 | 7 | 11 => ThreatType::Malware,
            5 => ThreatType::Botnet,
            10 => ThreatType::Pup,
            _ => ThreatType::Unknown(octet),
        }
    }

    /// Get threat type description
    pub fn description(&self) -> &'static str {
        match self {
            ThreatType::Spam => "Spam Source",
            ThreatType::Phishing => "Phishing Website",
            ThreatType::Malware => "Malware",
            ThreatType::Botnet => "Botnet",
            ThreatType::Pup => "Potentially Unwanted Program",
            ThreatType::Unknown(_) => "Unknown Threat Type",
        }
    }

    /// Get threat severity level (1-5, 5 is highest)
    pub fn severity_level(&self) -> u8 {
        match self {
            ThreatType::Malware => 5,
            ThreatType::Phishing => 4,
            ThreatType::Botnet => 4,
            ThreatType::Spam => 2,
            ThreatType::Pup => 1,
            ThreatType::Unknown(_) => 3,
        }
    }
}

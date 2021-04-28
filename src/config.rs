use std::net::Ipv4Addr;
use std::fmt;
use std::fmt::Display;
use super::Result;
use serde::Deserialize;
use async_std::fs;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Icmp,
    Arp,
}

impl Display for TargetType {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", format!("{:?}", &self).to_uppercase())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub r#type: TargetType,
    pub iface: String,
    pub addr: Ipv4Addr,
    pub source_addr: Ipv4Addr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub targets: Vec<TargetConfig>,
}

impl Config {
    pub async fn from_path(path: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(&fs::read_to_string(path).await?)?)
    }
}

use std::net::IpAddr;
use std::fmt;
use std::fmt::Display;
use anyhow::Result;
use serde::Deserialize;
use async_std::fs;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Icmp,
    Arp,
    Icmp6,
    Ndp,
}

impl Display for TargetType {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", format!("{:?}", &self).to_uppercase())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub struct TargetConfig {
    pub r#type: TargetType,
    pub iface: String,
    pub addr: IpAddr,
    pub source_addr: IpAddr,
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

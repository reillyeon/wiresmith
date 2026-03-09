use std::{fmt, net::IpAddr};

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use wireguard_keys::Pubkey;

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: Pubkey,
    pub endpoint: String,

    /// The WireGuard internal IP of the peer.
    ///
    /// It should be provided with the most specific netmask as it's meant to for only that peer.
    /// So for IPv4, use /32 and for IPv6, use /128.
    pub address: IpNet,
}

impl WgPeer {
    pub fn new(public_key: Pubkey, endpoint: &str, address: IpAddr) -> Self {
        Self {
            public_key,
            endpoint: endpoint.to_string(),
            address: address.into(),
        }
    }

    /// Add to tunnel
    #[tracing::instrument]
    pub async fn add(&self, interface: &str) -> Result<()> {
        let add_output = Command::new("wg")
            .arg("set")
            .arg(interface)
            .arg("peer")
            .arg(format!("{}", self.public_key))
            .arg("endpoint")
            .arg(format!("{}", self.endpoint))
            .arg("allowed-ips")
            .arg(format!("{}", self.address))
            .output()
            .await?;
        if !add_output.status.success() {
            let stderr = String::from_utf8_lossy(&add_output.stderr);
            return Err(anyhow!("Failed to add peer: {stderr}"));
        }
        Ok(())
    }

    /// Remove from tunnel
    #[tracing::instrument]
    pub async fn remove(&self, interface: &str) -> Result<()> {
        let remove_output = Command::new("wg")
            .arg("set")
            .arg(interface)
            .arg("peer")
            .arg(format!("{}", self.public_key))
            .arg("remove")
            .output()
            .await?;
        if !remove_output.status.success() {
            let stderr = String::from_utf8_lossy(&remove_output.stderr);
            return Err(anyhow!("Failed to remove peer: {stderr}"));
        }
        Ok(())
    }
}

impl fmt::Debug for WgPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgPeer")
            .field("public_key", &self.public_key.to_base64_urlsafe())
            .field("endpoint", &self.endpoint)
            .field("address", &self.address)
            .finish()
    }
}

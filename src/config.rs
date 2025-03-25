use clap::Parser;
use co_circom::NetworkConfig;
use mpc_net::config::NetworkConfigFile;
use std::path::PathBuf;

#[derive(Parser)]
pub struct CircomConfig {
    /// The batch size
    #[clap(long, env = "CHACHA_BATCH_SIZE")]
    pub batch_size: usize,

    /// The path to the init circuit
    #[clap(long, env = "CHACHA_CIRCUIT")]
    pub circuit: PathBuf,

    /// The path to the zkey
    #[clap(long, env = "CHACHA_ZKEY")]
    pub zkey: PathBuf,

    /// The path to the verification key
    #[clap(long, env = "CHACHA_VERIFICATION_KEY")]
    pub vk: PathBuf,

    /// The path to the network config file
    #[clap(long, env = "CHACHA_NETWORK_CONFIG")]
    pub network_config: PathBuf,
}
impl CircomConfig {
    pub fn network_config(&self) -> eyre::Result<NetworkConfig> {
        let toml = std::fs::read_to_string(&self.network_config)?;
        let config_file = toml::from_str::<NetworkConfigFile>(&toml)?;
        tracing::info!(
            "reading from config file: {}",
            self.network_config.display()
        );
        Ok(NetworkConfig::try_from(config_file)?)
    }
}

#[derive(Parser)]
pub struct NoirConfig {
    /// The batch size
    #[clap(long, env = "NOIR_BATCH_SIZE")]
    pub batch_size: usize,

    /// The path to the init circuit
    #[clap(long, env = "NOIR_CIRCUIT")]
    pub circuit: PathBuf,

    /// The path to the prover crs
    #[clap(long, env = "NOIR_PROVER_CRS")]
    pub prover_crs_path: PathBuf,

    /// The path to the verifier crs
    #[clap(long, env = "NOIR_VERIFIER_CRS")]
    pub verifier_crs_path: PathBuf,

    /// The path to the network config file
    #[clap(long, env = "CHACHA_NETWORK_CONFIG")]
    pub network_config: PathBuf,
}
impl NoirConfig {
    pub fn network_config(&self) -> eyre::Result<NetworkConfig> {
        let toml = std::fs::read_to_string(&self.network_config)?;
        let config_file = toml::from_str::<NetworkConfigFile>(&toml)?;
        tracing::info!(
            "reading from config file: {}",
            self.network_config.display()
        );
        Ok(NetworkConfig::try_from(config_file)?)
    }
}

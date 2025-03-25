use std::{collections::BTreeMap, fs::File, io::BufReader, time::Instant};

use chacha20_benches::config::NoirConfig;
use clap::Parser as _;
use co_acvm::Rep3AcvmType;
use co_noir::{Bn254, CrsParser, Poseidon2Sponge, Rep3CoUltraHonk, Rep3MpcNet, UltraHonk, Utils};
use eyre::Context as _;
use ultrahonk::prelude::ZeroKnowledge;

const CRS_SIZE: usize = 65536;

fn main() -> eyre::Result<()> {
    chacha20_benches::install_tracing();
    chacha20_benches::install_rustls_provider();

    let config = NoirConfig::parse();
    tracing::info!("Welcome to the ChaCha20 Noir bench runs!");
    tracing::info!("you want to do batch size: {}", config.batch_size);
    let network_config = config
        .network_config()
        .context("while parsing network config")?;
    tracing::info!("reading crs...");
    let party_id = network_config.my_id;

    let (prover_crs, verifier_crs) = CrsParser::<Bn254>::get_crs(
        config.prover_crs_path,
        config.verifier_crs_path,
        CRS_SIZE,
        ZeroKnowledge::Yes,
    )?
    .split();

    tracing::info!("compiling circuit...");
    let chacha_circuit =
        Utils::get_program_artifact_from_file(&config.circuit).context("while parsing circuit")?;
    let constraint_system = Utils::get_constraint_system_from_artifact(&chacha_circuit, false);

    let input_file = format!(
        "{}/data/noir/inputs/Prover.toml.{party_id}.shared",
        std::env!("CARGO_MANIFEST_DIR")
    );
    tracing::info!("reading input shares...");
    tracing::info!("reading input file: {input_file}");

    // parse input shares
    let input_share_file =
        BufReader::new(File::open(&input_file).context("while opening input share file")?);
    let input_share: BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>> =
        bincode::deserialize_from(input_share_file).context("while deserializing input share")?;

    tracing::info!("connecting to peers..");
    // connect to network
    let net = Rep3MpcNet::new(network_config).context("while connecting to other peers")?;

    tracing::info!("creating verifing key...");
    let (witness_share, net) =
        co_noir::generate_witness_rep3(input_share.clone(), chacha_circuit.clone(), net)?;
    // generate proving key and vk
    let (pk, mut net) =
        co_noir::generate_proving_key_rep3(net, &constraint_system, witness_share, false)?;

    let vk = pk.create_vk(&prover_crs, verifier_crs)?;
    tracing::info!("starting {} runs...", config.batch_size);

    let mut warmups = Vec::with_capacity(config.batch_size);
    let mut proofs = Vec::with_capacity(config.batch_size);
    let all_in_all = Instant::now();
    for _ in 0..config.batch_size {
        let start = Instant::now();
        let (witness_share, inner_net) =
            co_noir::generate_witness_rep3(input_share.clone(), chacha_circuit.clone(), net)?;

        let wtns = start.elapsed();
        // generate proving key and vk
        let (pk, inner_net) = co_noir::generate_proving_key_rep3(
            inner_net,
            &constraint_system,
            witness_share,
            false,
        )?;
        // generate proof
        let (proof, inner_net) = Rep3CoUltraHonk::<_, _, Poseidon2Sponge>::prove(
            inner_net,
            pk,
            &prover_crs,
            ZeroKnowledge::Yes,
        )?;
        let e2e = start.elapsed();

        warmups.push((wtns, e2e));
        proofs.push(proof);
        net = inner_net;
    }
    let all_in_all = all_in_all.elapsed();
    tracing::info!("verifying proofs...");
    for proof in proofs {
        assert!(
            UltraHonk::<_, Poseidon2Sponge>::verify(proof, &vk, ZeroKnowledge::Yes)
                .context("while verifying proof")?
        );
    }

    let (mut warm_up_wtns, mut warm_up_e2e) = warmups
        .into_iter()
        .reduce(|(acc_wtns, acc_e2e), (wtns, e2e)| (acc_wtns + wtns, acc_e2e + e2e))
        .unwrap();
    warm_up_wtns /= config.batch_size as u32;
    warm_up_e2e /= config.batch_size as u32;
    let warm_up_proof = warm_up_e2e - warm_up_wtns;
    tracing::info!("Done!");
    tracing::info!("These are the averaged times for a single run:");
    tracing::info!(
        "wtns extension took: {}.{:0>6}",
        warm_up_wtns.as_secs(),
        warm_up_wtns.subsec_micros()
    );
    tracing::info!(
        "prove took: {}.{:0>6}",
        warm_up_proof.as_secs(),
        warm_up_proof.subsec_micros()
    );
    tracing::info!(
        "e2e took: {}.{:0>6}",
        warm_up_e2e.as_secs(),
        warm_up_e2e.subsec_micros()
    );
    tracing::info!("===========================");
    tracing::info!(
        "In total {} runs took: {}.{:0>6}",
        config.batch_size,
        all_in_all.as_secs(),
        all_in_all.subsec_millis()
    );

    Ok(())
}

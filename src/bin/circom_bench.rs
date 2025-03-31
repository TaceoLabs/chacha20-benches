use std::{fs::File, io::BufReader, path::PathBuf, sync::Arc, time::Instant, vec};

use ark_bn254::Bn254;
use chacha20_benches::config::CircomConfig;
use clap::Parser;
use co_circom::{
    CheckElement, CoCircomCompiler, CoCircomCompilerParsed, CompilerConfig, Groth16,
    Groth16JsonVerificationKey, Groth16ZKey, Rep3CoGroth16, Rep3MpcNet, Rep3SharedInput, VMConfig,
};
use co_circom_snarks::BatchedSharedInput;
use eyre::Context;

fn read_zkey(zkey_path: PathBuf) -> eyre::Result<Groth16ZKey<Bn254>> {
    // load all the stuff
    tracing::debug!("loading zkey...");
    let reader = BufReader::new(File::open(&zkey_path)?);
    let time = Instant::now();
    let zkey = Groth16ZKey::<Bn254>::from_reader(reader, CheckElement::No)?;
    let elapsed = time.elapsed();
    tracing::debug!(
        "loaded zkey in {}.{} seconds",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );
    Ok(zkey)
}

fn read_verification_key(vk_path: PathBuf) -> eyre::Result<Groth16JsonVerificationKey<Bn254>> {
    let vk = BufReader::new(File::open(vk_path)?);
    Ok(serde_json::from_reader(vk)?)
}

fn do_batch_size(
    batch_size: usize,
    circuit: CoCircomCompilerParsed<ark_bn254::Fr>,
    zkey: Arc<Groth16ZKey<Bn254>>,
    vk: &Groth16JsonVerificationKey<Bn254>,
    input_share: &Rep3SharedInput<ark_bn254::Fr>,
    net: Rep3MpcNet,
) -> eyre::Result<Rep3MpcNet> {
    tracing::info!("doing batch {batch_size}..");
    let batch =
        BatchedSharedInput::try_from(vec![input_share.clone(); batch_size]).expect("can do batch");

    let mut proofs = vec![];
    let start = Instant::now();
    let (shared_witness, mut net) = circuit
        .clone()
        .to_batched_rep3_vm_with_network(net, VMConfig::default(), batch_size)
        .unwrap()
        .run_and_return_network(batch)
        .context("while doing batch wtns extension")?;
    let shared_witness = shared_witness.into_shared_witness().unbatch();

    let wtns = start.elapsed();

    for share in shared_witness {
        let public_input = share.public_inputs[1..].to_vec();
        let (proof, inner_net) = Rep3CoGroth16::prove(net, Arc::clone(&zkey), share)?;
        net = inner_net;
        proofs.push((proof, public_input));
    }
    let e2e = start.elapsed();
    assert_eq!(proofs.len(), batch_size);
    tracing::info!("Done!");
    for (proof, public_input) in proofs {
        Groth16::verify(vk, &proof, &public_input).context("got invalid proof")?;
    }
    tracing::info!(
        "wtns extension took: {}.{:0>6}",
        wtns.as_secs(),
        wtns.subsec_micros()
    );
    tracing::info!(
        "E2e (with proof) took: {}.{:0>6}",
        e2e.as_secs(),
        e2e.subsec_micros()
    );
    tracing::info!("===========================");
    Ok(net)
}

fn main() -> eyre::Result<()> {
    chacha20_benches::install_tracing();
    chacha20_benches::install_rustls_provider();

    let config = CircomConfig::parse();
    tracing::info!("Welcome to the ChaCha20 circom bench runs!");
    tracing::info!("you want to do batch size: {}", config.batch_size);
    let network_config = config
        .network_config()
        .context("while parsing network config")?;

    tracing::info!("reading key material...");
    let zkey = Arc::new(read_zkey(config.zkey).context("while reading zkey")?);
    let vk = read_verification_key(config.vk).context("while reading vk")?;

    let party_id = network_config.my_id;

    let input_file = format!(
        "{}/data/circom/inputs/input.json.{party_id}.shared",
        std::env!("CARGO_MANIFEST_DIR")
    );

    tracing::info!("compiling circuit...");
    let mut compiler_config = CompilerConfig::new();
    compiler_config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
    let circuit = CoCircomCompiler::<Bn254>::parse(&config.circuit, compiler_config)
        .context("while parsing circuit")?;

    tracing::info!("reading input shares...");
    tracing::info!("reading input file: {input_file}");
    let input_share_file =
        BufReader::new(File::open(&input_file).context("while opening input share file")?);
    let input_share: Rep3SharedInput<ark_bn254::Fr> =
        bincode::deserialize_from(input_share_file).context("trying to parse input share file")?;

    tracing::info!("connecting to peers..");
    let mut net = Rep3MpcNet::new(network_config).context("while connecting to other peers")?;

    tracing::info!("warming up with 5 ordinary runs...");
    let mut warmups = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let (shared_witness, inner_net) = circuit
            .clone()
            .to_rep3_vm_with_network(net, VMConfig::default())
            .unwrap()
            .run_and_return_network(input_share.clone())
            .context("while doing single wtns extension")?;

        let wtns = start.elapsed();

        let share = shared_witness.into_shared_witness();
        let public_input = share.public_inputs[1..].to_vec();
        let (proof, inner_net) = Rep3CoGroth16::prove(inner_net, Arc::clone(&zkey), share)?;

        let e2e = start.elapsed();
        Groth16::verify(&vk, &proof, &public_input).context("got invalid proof")?;
        warmups.push((wtns, e2e));
        net = inner_net;
    }

    let (mut warm_up_wtns, mut warm_up_e2e) = warmups
        .into_iter()
        .reduce(|(acc_wtns, acc_e2e), (wtns, e2e)| (acc_wtns + wtns, acc_e2e + e2e))
        .unwrap();
    warm_up_wtns /= 5;
    warm_up_e2e /= 5;
    let warm_up_proof = warm_up_e2e - warm_up_wtns;
    tracing::info!("Done!");
    tracing::info!("These are the averaged times over the 5 warm up runs:");
    tracing::info!(
        "wtns extension took: {}.{:0>6}",
        warm_up_wtns.as_secs(),
        warm_up_wtns.subsec_micros()
    );
    tracing::info!(
        "warm_up_proof  took: {}.{:0>6}",
        warm_up_proof.as_secs(),
        warm_up_proof.subsec_micros()
    );
    tracing::info!(
        "e2e took: {}.{:0>6}",
        warm_up_e2e.as_secs(),
        warm_up_e2e.subsec_micros()
    );
    tracing::info!("===========================");
    let net = do_batch_size(
        5,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let net = do_batch_size(
        10,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let net = do_batch_size(
        15,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let net = do_batch_size(
        20,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let net = do_batch_size(
        25,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let net = do_batch_size(
        30,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let net = do_batch_size(
        100,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    let _ = do_batch_size(
        1000,
        circuit.clone(),
        Arc::clone(&zkey),
        &vk,
        &input_share,
        net,
    )?;

    Ok(())
}

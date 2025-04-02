BATCH_SIZE=5

cargo run --bin noir_bench --release -- --batch-size $BATCH_SIZE --circuit data/noir/noir-chacha/chacha20_bitwise_test/target/chacha20_bitwise_test.json --prover-crs-path data/noir/bn254_g1.dat --verifier-crs-path data/noir/bn254_g2.dat --network-config data/configs/party1.toml &
RUST_LOG="warn" cargo run --bin noir_bench  --release -- --batch-size $BATCH_SIZE --circuit data/noir/noir-chacha/chacha20_bitwise_test/target/chacha20_bitwise_test.json --prover-crs-path data/noir/bn254_g1.dat --verifier-crs-path data/noir/bn254_g2.dat --network-config data/configs/party2.toml &
RUST_LOG="warn" cargo run --bin noir_bench  --release -- --batch-size $BATCH_SIZE --circuit data/noir/noir-chacha/chacha20_bitwise_test/target/chacha20_bitwise_test.json --prover-crs-path data/noir/bn254_g1.dat --verifier-crs-path data/noir/bn254_g2.dat --network-config data/configs/party3.toml 


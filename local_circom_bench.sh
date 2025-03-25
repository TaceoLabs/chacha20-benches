BATCH_SIZE=30

cargo run --bin circom_bench --release -- --batch-size $BATCH_SIZE --circuit data/circom/chacha.circom --zkey data/circom/chacha.zkey --vk data/circom/verification_key.json --network-config data/configs/party1.toml & 
RUST_LOG="warn" cargo run --bin circom_bench --release -- --batch-size $BATCH_SIZE --circuit data/circom/chacha.circom --zkey data/circom/chacha.zkey --vk data/circom/verification_key.json --network-config data/configs/party2.toml & 
RUST_LOG="warn" cargo run --bin circom_bench --release -- --batch-size $BATCH_SIZE --circuit data/circom/chacha.circom --zkey data/circom/chacha.zkey --vk data/circom/verification_key.json --network-config data/configs/party3.toml 


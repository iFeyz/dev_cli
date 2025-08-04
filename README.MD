# RUN PROJECT

Run on different provider use this .env conf : 

```
RPC_URL="http://127.0.0.1:8545"
CHAIN_ID=31337
NETWORK_NAME="Anvil-Local"
GAS_LIMIT=21000
GAS_PRICE=20000000000

```


FORK HYPE EVM 

anvil \
  --fork-url wss://hyperliquid.drpc.org \
  --fork-block-number 900000 \
  --chain-id 999 \
  --accounts 10 \
  --balance 1000000000000000000



  solc --bin --abi \
  --base-path . \
  --include-path node_modules \
  aam_factory_sol.sol \
  -o build --overwrite
  

- cargo run

# TODO

- Add better provider handler
- Create a smart contract deployer 
- Add interaction to SM 
- Add a deployer option



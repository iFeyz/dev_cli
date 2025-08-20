use alloy::primitives::{Address};
use alloy::network::{Ethereum, Network};
use std::sync::Arc;
use alloy::primitives::{U256, Bytes};
use alloy::providers::{Provider};
use alloy::primitives::B256;
use crate::universal::auto_logger::AutoLogger;
use alloy::contract::Interface;
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use alloy_json_abi::JsonAbi;
use crate::model::interaction::{ Interaction, InteractionData, RequestResult, UserCredentials, ExecutionMode};
use alloy::dyn_abi::{DynSolValue};
use alloy::network::TransactionBuilder;




//[derive(Debug,Clone)] // AutoLogger dont impl Debug cause of dyn trait
pub struct ExistingContractConnection<P, N = Ethereum> 
where
    P: Provider<N>,
    N: Network,
{
    pub name: String,
    pub address: Address,
    pub abi : Interface,
    pub provider: Arc<P>,
    pub logger: AutoLogger, // AutoLogger cannot impl Option Debug
    _phantom: std::marker::PhantomData<N>,
}

impl<P, N> ExistingContractConnection<P,N>
where
    P: Provider<N> + Send + Sync,
    N: Network,
{
    pub fn from_abi_file(
        abi_path: &str,
        address: Address,
        provider: Arc<P>,
        name: Option<String>,
    ) -> Self {
        let abi_content = std::fs::read_to_string(abi_path).unwrap();
        let json_abi: JsonAbi = serde_json::from_str(&abi_content).unwrap();
        let interface = Interface::new(json_abi);
        let contract_name = name.unwrap_or_else(|| {
            std::path::Path::new(abi_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("UknContract")
                .to_string()
        });


        // Default logger -> TODO create the good logger for the exisitng contract
        Self {
            name: contract_name,
            address,
            abi: interface,
            provider,
            logger: AutoLogger::new(),
            _phantom: std::marker::PhantomData
        }
        
    }

    // Register the contract logger
    pub fn register_logger(&mut self) {
        self.logger.register_contract(
            self.name.clone(),
            self.address,
            &self.abi
        )
    }

    //TODO TEST THE CALL FUNCTION
    pub async fn call_function(
        &mut self,
        function_name: &str,
        params: &[DynSolValue],
        credentials: UserCredentials,
        execution_mode: ExecutionMode,
    ) -> RequestResult<InteractionData> {
        println!("Calling {}::{}", self.name, function_name);

        let encoded_data = self.abi.encode_input(function_name, params).unwrap();

        let interaction : Interaction<N> = Interaction::new(
            Some(self.address),
            Bytes::from(encoded_data),
            function_name.to_string(),
            credentials,
            None,
        ).with_execution_mode(ExecutionMode::Direct);
        
        let result = interaction.execute(&self.provider).await;


        //TODO PARSE THE LOGS
        // DONE 
        self.register_logger();

        if let RequestResult { transaction_hash: Some(ref tx_hash), .. } = result {
            if let Ok(tx_hash_b256) = tx_hash.parse::<B256>() {
                if let Ok(events) = self.logger.process_transaction_logs(&*self.provider, tx_hash_b256).await {
                    for event in events {
                        println!("Event: {}::{}", event.contracts, event.name);
                    }
                }
            }
        }

        return result;
    }

    pub async fn read_state(
        &self,
        function_name: &str,
        params: &[DynSolValue],
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let encoded_data = self.abi.encode_input(function_name, params).unwrap();
        let mut call_request: <N as Network>::TransactionRequest = N::TransactionRequest::default();
        call_request.set_to(self.address);
        call_request.set_input(encoded_data);

        let result = self.provider.call(call_request).await.map_err(|e| anyhow::anyhow!("Call failed: {}", e))?;

        
        Ok(serde_json::from_slice(&result).map_err(|e| anyhow::anyhow!("Failed to parse result: {}", e))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::providers::ProviderBuilder;
    use std::fs;
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn create_test_abi() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"[
            {{
                "type": "function",
                "name": "balanceOf",
                "inputs": [
                    {{
                        "name": "account",
                        "type": "address"
                    }}
                ],
                "outputs": [
                    {{
                        "name": "",
                        "type": "uint256"
                    }}
                ],
                "stateMutability": "view"
            }}
        ]"#).unwrap();
        file
    }

    #[test]
    fn test_from_abi_file() {
        let abi_file = create_test_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let address = Address::from([0u8; 20]);
        
        let contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            address,
            provider.clone(),
            Some("TestContract".to_string())
        );
        
        assert_eq!(contract.name, "TestContract");
        assert_eq!(contract.address, address);
        //assert!(!contract.abi.abi().functions().is_empty());
    }

    #[test]
    fn test_from_abi_file_default_name() {
        let abi_file = create_test_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let address = Address::from([0u8; 20]);
        
        let contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            address,
            provider.clone(),
            None
        );
        
        assert!(contract.name.len() > 0);
        assert_ne!(contract.name, "UknContract");
    }

    #[test]
    fn test_register_logger() {
        let abi_file = create_test_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let address = Address::from([0u8; 20]);
        
        let mut contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            address,
            provider.clone(),
            Some("TestContract".to_string())
        );
        
        contract.register_logger();
        assert!(contract.logger.contracts.contains_key(&address));
    }

    fn create_erc20_abi() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"[
            {{
                "type": "function",
                "name": "balanceOf",
                "inputs": [
                    {{
                        "name": "account",
                        "type": "address"
                    }}
                ],
                "outputs": [
                    {{
                        "name": "",
                        "type": "uint256"
                    }}
                ],
                "stateMutability": "view"
            }},
            {{
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {{
                        "name": "to",
                        "type": "address"
                    }},
                    {{
                        "name": "amount",
                        "type": "uint256"
                    }}
                ],
                "outputs": [
                    {{
                        "name": "",
                        "type": "bool"
                    }}
                ],
                "stateMutability": "nonpayable"
            }},
            {{
                "type": "event",
                "name": "Transfer",
                "anonymous": false,
                "inputs": [
                    {{
                        "name": "from",
                        "type": "address",
                        "indexed": true
                    }},
                    {{
                        "name": "to",
                        "type": "address",
                        "indexed": true
                    }},
                    {{
                        "name": "value",
                        "type": "uint256",
                        "indexed": false
                    }}
                ]
            }}
        ]"#).unwrap();
        file
    }

    #[test]
    fn test_erc20_contract_creation() {
        let abi_file = create_erc20_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let address = Address::from([1u8; 20]);
        
        let contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            address,
            provider.clone(),
            Some("MockERC20".to_string())
        );
        
        assert_eq!(contract.name, "MockERC20");
        assert_eq!(contract.address, address);
        
        // Check if functions are loaded correctly
        let functions: Vec<_> = contract.abi.abi().functions().collect();
        assert!(functions.iter().any(|f| f.name == "balanceOf"));
        assert!(functions.iter().any(|f| f.name == "transfer"));
        
        // Check if events are loaded correctly
        let events: Vec<_> = contract.abi.abi().events().collect();
        assert!(events.iter().any(|e| e.name == "Transfer"));
    }

    #[test]
    fn test_function_encoding() {
        let abi_file = create_erc20_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let address = Address::from([1u8; 20]);
        
        let contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            address,
            provider.clone(),
            Some("MockERC20".to_string())
        );
        
        // Test encoding balanceOf function call
        let test_address = Address::from([2u8; 20]);
        let params = vec![alloy::dyn_abi::DynSolValue::Address(test_address)];
        
        let encoded = contract.abi.encode_input("balanceOf", &params);
        assert!(encoded.is_ok());
        
        let encoded_data = encoded.unwrap();
        assert!(!encoded_data.is_empty());
        // balanceOf function signature is 0x70a08231
        assert_eq!(&encoded_data[0..4], &[0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn test_logger_registration_with_events() {
        let abi_file = create_erc20_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let address = Address::from([1u8; 20]);
        
        let mut contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            address,
            provider.clone(),
            Some("MockERC20".to_string())
        );
        
        contract.register_logger();
        
        // Check if contract is registered in logger
        assert!(contract.logger.contracts.contains_key(&address));
        assert_eq!(contract.logger.contracts.get(&address).unwrap(), "MockERC20");
        
        // Check if events are registered
        assert!(!contract.logger.event_signatures.is_empty());
        
        // Verify Transfer event is registered
        let transfer_event = contract.abi.abi().events().find(|e| e.name == "Transfer");
        assert!(transfer_event.is_some());
        
        let event_sig = transfer_event.unwrap().selector();
        assert!(contract.logger.event_signatures.contains_key(&event_sig));
    }

    #[test]
    fn test_integration_contract_and_logger() {
        let abi_file = create_erc20_abi();
        let provider = Arc::new(ProviderBuilder::new().on_anvil_with_wallet());
        let contract_address = Address::from([1u8; 20]);
        
        let mut contract = ExistingContractConnection::from_abi_file(
            abi_file.path().to_str().unwrap(),
            contract_address,
            provider.clone(),
            Some("IntegrationTest".to_string())
        );
        
        // Register logger
        contract.register_logger();
        
        // Simulate a Transfer event log
        let transfer_event = contract.abi.abi().events().find(|e| e.name == "Transfer").unwrap();
        let event_sig = transfer_event.selector();
        
        let from_addr = Address::from([2u8; 20]);
        let to_addr = Address::from([3u8; 20]);
        
        let from_topic = B256::from_slice(&{
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(from_addr.as_slice());
            buf
        });
        let to_topic = B256::from_slice(&{
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(to_addr.as_slice());
            buf
        });
        
        let log = alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: contract_address,
                data: alloy::primitives::LogData::new_unchecked(
                    vec![event_sig, from_topic, to_topic],
                    vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8].into() // 1000 wei
                ),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        };
        
        // Test log decoding through the logger
        let decoded = contract.logger.decode_log(log, B256::with_last_byte(1), 0);
        assert!(decoded.is_some());
        
        let decoded_event = decoded.unwrap();
        assert_eq!(decoded_event.name, "Transfer");
        assert_eq!(decoded_event.contracts, contract_address);
        assert_eq!(decoded_event.signature, event_sig);
        
        // Verify the decoded data contains expected structure
        assert!(decoded_event.data.is_object());
        let data_obj = decoded_event.data.as_object().unwrap();
        assert!(data_obj.contains_key("address"));
        assert!(data_obj.contains_key("topics"));
        assert!(data_obj.contains_key("data"));
        assert_eq!(data_obj.get("contract").unwrap(), "IntegrationTest");
    }
}


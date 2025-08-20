use alloy::{contract::Interface, primitives::{Address, B256, U256, U64, }, rpc::types::trace::parity::SelfdestructAction,};
use serde_json;
use std::collections::HashMap;
use alloy::primitives::{Log as PrimitiveLog, LogData};
use alloy::{sol};
use alloy::providers::{Provider};
use alloy::network::{Network, ReceiptResponse};
use alloy::rpc::types::{Filter, Log};



/// BETTER LOGGING BY SETTING GETTER / SETTER 
/// REPLACE PUB STRUCT BY PRIVATE ONE 
/// TODO

#[derive(Debug, Clone)]
pub struct DecodedEvent {
    pub name: String,
    pub contracts: Address,
    pub signature: B256,
    pub data: serde_json::Value,
    pub block_number: U256,
    pub tx_hash: B256,
    pub log_index: U64,
}

pub trait EventHandler: Send + Sync  {
    fn handle_event(&self, event: DecodedEvent);
}

//TODO ADD MORE ACTIONS
#[derive(Debug)]
pub enum LogAction {
    Print,
    Store,
    Ignore,
} 


pub struct AutoLogger {
   pub event_signatures: HashMap<B256, EventInfo>,
   pub handlers: HashMap<String, Box<dyn EventHandler>>,
    pub contracts: HashMap<Address, String>,
}

#[derive(Debug, Clone)]
pub struct EventInfo {
    pub name: String,
    pub contract_name: String,
    pub abi_event: String,
}

impl EventInfo {
    pub fn new(name : String, contract_name: String, abi_event: String) -> Self {
        Self {
            name,
            contract_name,
            abi_event
        }
    }
}

impl AutoLogger {
    pub fn new() -> Self { 
        Self {
            event_signatures: HashMap::new(),
            handlers: HashMap::new(),
            contracts: HashMap::new(),
        }

    }

    // ABI Register for all eventsa
    pub fn register_contract(
        &mut self,
        name: String,
        address: Address,
        abi: &Interface       
        ) {
            self.contracts.insert(address, name.clone());

            for e in abi.abi().events() {
                let sig = e.selector();
                let e_ifno = EventInfo::new(e.name.clone(), name.clone(), serde_json::to_string(e).unwrap_or_default());
                self.event_signatures.insert(sig, e_ifno);
                println!("Registered event :{}::{} -> {}", name, e.name, sig);
            }
    }

    // Get all the logs of a Tx
    pub async fn process_transaction_logs<P, N>(
        &self,
        provider: &P,
        tx_hash: B256,
    ) -> Result<Vec<DecodedEvent>, Box<dyn std::error::Error>>
    where 
        P: Provider<N>,
        N: Network
    {
        let mut dec_e = Vec::new();
        

        // Get the blocks / tx from - to a certain block
        // Check if the tx is in the block
        // If it is, get the logs
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
            let filter = Filter::new().from_block(receipt.block_number().unwrap_or(0) -10).to_block(receipt.block_number().unwrap_or(0) + 10);
            

            if let Ok(logs) = provider.get_logs(&filter).await {
                let tx_logs: Vec<_> = logs.into_iter()
                    .filter(|log| log.transaction_hash == Some(tx_hash))
                    .collect();
                
                println!("📋 Found {} logs in transaction", tx_logs.len());
            }


        }

        Ok(dec_e)
    }

    //Decode a single log entry with the event info
    pub fn decode_log(
        &self,
        log: Log,
        tx_hash: B256,
        log_index: u64
    ) -> Option<DecodedEvent> {

        // If log topic empty then return no logs
        if log.topics().is_empty() {
            return None;
        }
        // Even signature is always the first topic
        let event_signature = log.topics()[0];


        if let Some(event_info) = self.event_signatures.get(&event_signature) {
            println!("Found event : {}", event_info.name);

            //Primitive log convertion to decode the data

            let primitive_log = Log {
                inner: PrimitiveLog {
                    address: log.inner.address,
                    data: LogData::new_unchecked(
                        log.inner.topics().to_vec(),
                        log.inner.data.data.clone(),
                    )
                },
                // Mock for now maybe fail
                block_hash: Some(B256::with_last_byte(0x69)),
                block_number: Some(0x69),
                block_timestamp: None,
                transaction_hash: Some(B256::with_last_byte(0x69)),
                transaction_index: Some(0x69),
                log_index: Some(0x69),
                removed: false,
                
            };

            //Try decode this event data
            if let Some(decoded_event) = self.decode_event_data(&primitive_log, event_info) {
                return Some(DecodedEvent {
                    name: event_info.name.clone(),
                    contracts: log.inner.address,
                    signature: event_signature,
                    data: decoded_event,
                    block_number: U256::from(0), // Will be filled by caller if needed
                    tx_hash,
                    log_index : U64::from(0),
                });
            }
        } else {
            println!("Unknow event sig : {}", event_signature);

            return Some(DecodedEvent { name: "UnknowEvent".to_string(), contracts: log.inner.address, signature: event_signature,                 data: serde_json::json!({
                "topics": log.topics().iter().map(|t| format!("{}", t)).collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&log.inner.data.data))
            }),
            block_number: U256::from(0),
            tx_hash,
            log_index : U64::from(log_index) })
        }
        None
    }

    //


    fn decode_event_data(&self, log: &Log, event_info: &EventInfo) -> Option<serde_json::Value> {
        // Specific decoding 
        //TODO

        Some(serde_json::json!({
            "address": format!("{}", log.address()),
            "topics": log.topics().iter().map(|t| format!("{}", t)).collect::<Vec<_>>(),
            "data": format!("0x{}", hex::encode(&log.data().data)),
            "contract": event_info.contract_name
        }))
    }

    //TODO ADD THE HANDLER FOR THE LOGS IF NEEDED



}



#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::sol_data::FixedBytes;

    #[test]
    fn test_auto_logger_new() {
        let logger = AutoLogger::new();
        assert!(logger.event_signatures.is_empty());
        assert!(logger.handlers.is_empty());
        assert!(logger.contracts.is_empty());
    }

    #[test]
    fn test_register_contract() {
        let mut logger = AutoLogger::new();
        let address = Address::from([1u8; 20]);
        
        let abi_json = r#"[{
            "type": "event",
            "name": "Transfer",
            "anonymous": false,
            "inputs": [
                {"name": "from", "type": "address", "indexed": true},
                {"name": "to", "type": "address", "indexed": true},
                {"name": "value", "type": "uint256", "indexed": false}
            ]
        }]"#;
        
        let json_abi: alloy_json_abi::JsonAbi = serde_json::from_str(abi_json).unwrap();
        let interface = Interface::new(json_abi);
        
        logger.register_contract("TestToken".to_string(), address, &interface);
        
        assert!(logger.contracts.contains_key(&address));
        assert_eq!(logger.contracts.get(&address).unwrap(), "TestToken");
        assert!(!logger.event_signatures.is_empty());
    }

    #[test]
    fn test_decode_log_empty_topics() {
        let logger = AutoLogger::new();
        let log = Log {
            inner: alloy::primitives::Log {
                address: Address::from([1u8; 20]),
                data: alloy::primitives::LogData::new_unchecked(vec![], vec![].into()),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        };
        
        let result = logger.decode_log(log, B256::with_last_byte(1), 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_log_unknown_event() {
        let logger = AutoLogger::new();
        let event_sig = B256::with_last_byte(42);
        let log = Log {
            inner: alloy::primitives::Log {
                address: Address::from([1u8; 20]),
                data: alloy::primitives::LogData::new_unchecked(
                    vec![event_sig],
                    vec![1, 2, 3, 4].into()
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
        
        let result = logger.decode_log(log, B256::with_last_byte(1), 0);
        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.name, "UnknowEvent");
    }

    #[test]
    fn test_decode_log_with_registered_event() {
        let mut logger = AutoLogger::new();
        let contract_address = Address::from([1u8; 20]);
        
        // Create a Transfer event ABI
        let abi_json = r#"[{
            "type": "event",
            "name": "Transfer",
            "anonymous": false,
            "inputs": [
                {"name": "from", "type": "address", "indexed": true},
                {"name": "to", "type": "address", "indexed": true},
                {"name": "value", "type": "uint256", "indexed": false}
            ]
        }]"#;
        
        let json_abi: alloy_json_abi::JsonAbi = serde_json::from_str(abi_json).unwrap();
        let interface = Interface::new(json_abi);
        
        logger.register_contract("TestToken".to_string(), contract_address, &interface);
        
        // Get the Transfer event signature
        let transfer_event = interface.abi().events().find(|e| e.name == "Transfer").unwrap();
        let event_sig = transfer_event.selector();
        
        // Create a mock log with Transfer event
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
        
        let log = Log {
            inner: alloy::primitives::Log {
                address: contract_address,
                data: alloy::primitives::LogData::new_unchecked(
                    vec![event_sig, from_topic, to_topic],
                    vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8].into() // 1000 in hex
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
        
        let result = logger.decode_log(log, B256::with_last_byte(1), 0);
        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.name, "Transfer");
        assert_eq!(decoded.contracts, contract_address);
        assert_eq!(decoded.signature, event_sig);
    }

    #[test]
    fn test_decode_event_data() {
        let logger = AutoLogger::new();
        let contract_address = Address::from([1u8; 20]);
        
        let log = Log {
            inner: alloy::primitives::Log {
                address: contract_address,
                data: alloy::primitives::LogData::new_unchecked(
                    vec![B256::with_last_byte(1), B256::with_last_byte(2)],
                    vec![0x01, 0x02, 0x03, 0x04].into()
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
        
        let event_info = EventInfo::new(
            "TestEvent".to_string(),
            "TestContract".to_string(),
            "test_abi".to_string()
        );
        
        let result = logger.decode_event_data(&log, &event_info);
        assert!(result.is_some());
        
        let decoded = result.unwrap();
        assert!(decoded["address"].is_string());
        assert!(decoded["topics"].is_array());
        assert!(decoded["data"].is_string());
        assert_eq!(decoded["contract"], "TestContract");
    }
}
use alloy::{
    primitives::{Address, U256, Bytes},
    rpc::types::TransactionRequest,
    providers::{Provider, ext::TraceApi},
    network::Ethereum,
};

use async_trait::async_trait;

use crate::model::interaction::{RequestError, RequestResult, Requestable, TraceInfo, Transaction, TransactionData};
use crate::contract::contract_interface::{Contract, ContractType};

#[derive(Debug, Clone)]
pub struct DeployedContract {
    pub contract_address: Address,
    pub deployment_tx: String,
    pub block_number: Option<u64>,
    pub gas_used: U256,
    pub creator: Address,
}

pub struct ContractDeployment<T: ContractType> {
    pub contract: Contract<T>,
}

impl<T: ContractType> ContractDeployment<T> {
    pub fn new(contract: Contract<T>) -> Self {
        Self { contract }
    }

    fn create_deployment_transaction(&self) -> Transaction {
        let deployment_bytecode = self.contract.info.get_deployment_bytecode();
        
        Transaction {
            to: Address::ZERO, // Contract deployment uses zero address
            value: U256::ZERO,
            data: Some(deployment_bytecode),
            config: self.contract.config.clone(),
            user_credentials: self.contract.user_credentials.clone(),
        }
    }
}

#[async_trait]
impl<T: ContractType> Requestable<DeployedContract> for ContractDeployment<T> {
    fn build_transaction_request(&self) -> TransactionRequest {
        self.create_deployment_transaction().build_transaction_request()
    }

    async fn request<P>(&self, provider: &P) -> RequestResult<DeployedContract>
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync,
    {
        let deployment_tx = self.create_deployment_transaction();
        
        // Use your Transaction type to execute the deployment
        match deployment_tx.request(provider).await {
            RequestResult { success: true, data: Some(tx_data), transaction_hash, .. } => {
                // For contract deployment, we need to get the contract address from the receipt
                // Since your Transaction doesn't return the contract address, we need to extract it
                
                // Parse the transaction hash to get the receipt and extract contract address
                if let Some(tx_hash_str) = transaction_hash {
                    // In a real implementation, you'd parse the transaction hash and get the receipt
                    // For now, we'll simulate getting the contract address
                    // This is a placeholder - you'd need to implement proper contract address calculation
                    let contract_address = self.calculate_contract_address(&tx_data);
                    
                    let deployed_contract = DeployedContract {
                        contract_address,
                        deployment_tx: tx_hash_str,
                        block_number: None, // Would be extracted from receipt
                        gas_used: tx_data.gas_used,
                        creator: tx_data.recipient, // This would be the deployer
                    };

                    RequestResult::success(deployed_contract, None, None)
                } else {
                    RequestResult::error(RequestError::ContractError("No transaction hash returned".to_string()))
                }
            }
            RequestResult { success: false, error, trace_info, .. } => {
                RequestResult {
                    success: false,
                    error,
                    data: None,
                    transaction_hash: None,
                    trace_info,
                }
            }
            _ => RequestResult::error(RequestError::ContractError("Unexpected deployment result".to_string())),
        }
    }

    fn validate(&self) -> Result<(), RequestError> {
        if self.contract.info.bytecode.is_empty() {
            return Err(RequestError::ContractError("Contract bytecode cannot be empty".to_string()));
        }
        
        if self.contract.config.gas_limit == U256::ZERO {
            return Err(RequestError::ContractError("Gas limit cannot be zero".to_string()));
        }
        
        Ok(())
    }
}

impl<T: ContractType> ContractDeployment<T> {
    // Helper method to calculate contract address
    // In practice, this would use CREATE or CREATE2 address calculation
    fn calculate_contract_address(&self, _tx_data: &TransactionData) -> Address {
        // Placeholder implementation
        // Real implementation would calculate the contract address using:
        // - Deployer address
        // - Nonce (for CREATE)
        // - Or salt + bytecode hash (for CREATE2)
        
        // For now, return a dummy address
        // You'd implement proper address calculation here
        Address::ZERO // This should be replaced with actual calculation
    }
}
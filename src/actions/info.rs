use alloy::{
    primitives::{Address, U256, B256, utils::format_ether},
    providers::Provider,
    rpc::types::{TransactionReceipt, Transaction, BlockNumberOrTag},
    consensus::Transaction as TransactionTrait,
};

use std::fmt::Display;

#[derive(Debug)]
pub struct TransactionInfo {
    pub network_chain_id: u64,
    pub from_address: Address,
    pub to_address: Option<Address>,
    pub value: U256,
    pub tx_hash: B256,
    pub block_number: Option<u64>,
    pub block_hash: Option<B256>,
    pub block_timestamp: Option<u64>,
    pub gas_limit: u64,
    pub gas_used: Option<u64>,
    pub gas_price: Option<u64>,
    pub nonce: u64,
    pub transaction_index: Option<u64>,
    pub status: Option<bool>,
}

impl Display for TransactionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
r#"📊 Transaction Information:
┌─────────────────────────────────────────────────────────────
│ Hash: {}
│ From: {}
│ To: {}
│ Value: {} ETH ({} wei)
│ Status: {}
├─────────────────────────────────────────────────────────────
│ Block Number: {}
│ Block Hash: {}
│ Transaction Index: {}
│ Nonce: {}
├─────────────────────────────────────────────────────────────
│ Gas Limit: {}
│ Gas Used: {}
│ Gas Price: {} gwei
│ Network Chain ID: {}
└─────────────────────────────────────────────────────────────"#,
            self.tx_hash,
            self.from_address,
            self.to_address.map_or("None".to_string(), |addr| format!("{}", addr)),
            format_ether(self.value),
            self.value,
            match self.status {
                Some(true) => "✅ Success",
                Some(false) => "❌ Failed", 
                None => "⏳ Pending"
            },
            self.block_number.map_or("Pending".to_string(), |n| n.to_string()),
            self.block_hash.map_or("Pending".to_string(), |h| format!("{}", h)),
            self.transaction_index.map_or("Pending".to_string(), |i| i.to_string()),
            self.nonce,
            self.gas_limit,
            self.gas_used.map_or("Pending".to_string(), |g| g.to_string()),
            self.gas_price.map_or("0".to_string(), |g| (g / 1_000_000_000).to_string()),
            self.network_chain_id
        )
    }
}

impl TransactionInfo {
    pub async fn from_hash<P>(
        provider: &P, 
        tx_hash: B256
    ) -> Result<Self, Box<dyn std::error::Error>> 
    where
        P: Provider,
    {
        // Récupérer la transaction
        let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or("Transaction not found")?;

        // Récupérer le receipt (peut être None si la transaction est pending)
        let receipt = provider.get_transaction_receipt(tx_hash).await?;

        // Récupérer les informations du bloc si la transaction est confirmée
        let (block_timestamp, block_hash) = if let Some(block_num) = tx.block_number {
            let block = provider
                .get_block_by_number(BlockNumberOrTag::Number(block_num))
                .await?;
            (
                block.as_ref().map(|b| b.header.timestamp),
                block.as_ref().map(|b| b.header.hash)
            )
        } else {
            (None, None)
        };

        // Récupérer le chain ID
        let chain_id = provider.get_chain_id().await?;

        // Extraire l'adresse to en fonction du type de transaction
        let to_address = match tx.kind() {
            alloy::primitives::TxKind::Call(addr) => Some(addr),
            alloy::primitives::TxKind::Create => None,
        };

        Ok(TransactionInfo {
            network_chain_id: chain_id,
            from_address: tx.inner.signer(),
            to_address,
            value: tx.value(),
            tx_hash,
            block_number: tx.block_number,
            block_hash,
            block_timestamp,
            gas_limit: tx.gas_limit(),
            gas_used: receipt.as_ref().map(|r| r.gas_used),
            gas_price: tx.gas_price().map(|p| p as u64),
            nonce: tx.nonce(),
            transaction_index: tx.transaction_index,
            status: receipt.as_ref().map(|r| r.status()),
        })
    }

    // Méthode pour créer depuis une transaction et son receipt
    pub async fn from_transaction_and_receipt<P>(
        provider: &P,
        tx: Transaction,
        receipt: Option<TransactionReceipt>
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        P: Provider,
    {
        let chain_id = provider.get_chain_id().await?;
        
        // Récupérer les informations du bloc si disponible
        let (block_timestamp, block_hash) = if let Some(block_num) = tx.block_number {
            let block = provider
                .get_block_by_number(BlockNumberOrTag::Number(block_num))
                .await?;
            (
                block.as_ref().map(|b| b.header.timestamp),
                block.as_ref().map(|b| b.header.hash)
            )
        } else {
            (None, None)
        };

        // Calculer le hash de la transaction
        let tx_hash = tx.inner.hash();

        // Extraire l'adresse to en fonction du type de transaction
        let to_address = match tx.kind() {
            alloy::primitives::TxKind::Call(addr) => Some(addr),
            alloy::primitives::TxKind::Create => None,
        };

        Ok(TransactionInfo {
            network_chain_id: chain_id,
            from_address: tx.inner.signer(),
            to_address,
            value: tx.value(),
            tx_hash: *tx_hash,
            block_number: tx.block_number,
            block_hash,
            block_timestamp,
            gas_limit: tx.gas_limit(),
            gas_used: receipt.as_ref().map(|r| r.gas_used),
            gas_price: tx.gas_price().map(|p| p as u64),
            nonce: tx.nonce(),
            transaction_index: tx.transaction_index,
            status: receipt.as_ref().map(|r| r.status()),
        })
    }

    // Méthodes utilitaires
    pub fn is_successful(&self) -> bool {
        self.status.unwrap_or(false)
    }

    pub fn is_pending(&self) -> bool {
        self.status.is_none()
    }

    pub fn value_in_ether(&self) -> String {
        format_ether(self.value)
    }

    pub fn gas_fee_in_ether(&self) -> Option<String> {
        match (self.gas_used, self.gas_price) {
            (Some(used), Some(price)) => {
                let total_fee = U256::from(used) * U256::from(price);
                Some(format_ether(total_fee))
            }
            _ => None
        }
    }
}
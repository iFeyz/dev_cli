use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::{Result};
use serde_json;
use alloy::{contract::Interface, primitives::Bytes};
use crate::universal::contract_spec::{ContractGeneric, DeploymentConfig};


pub struct ContractDiscovery;

impl ContractDiscovery {
    // Explore for the .bin and .json files in a selected directory
    pub fn from_abi_bin_files(abi_path: &str, bin_path: &str) -> Result<ContractGeneric> {
        // Read from the abi_path and bin_path
        let abi_content = std::fs::read_to_string(abi_path).unwrap_or_else(|_| panic!("Failed to read ABI file: {}", abi_path));
        let bin_content = std::fs::read_to_string(bin_path).unwrap_or_else(|_| panic!("Failed to read BIN file: {}", bin_path));

        // Interface the json abi
        let json_abi = serde_json::from_str(&abi_content).unwrap_or_else(|_| panic!("Failed to parse ABI file: {}", abi_path));
        let interface = Interface::new(json_abi);

        // Get the bytecode from the bin file
        let bytecode_hex = bin_content.strip_prefix("0x").unwrap_or(&bin_content);
        let bytecode = Bytes::from(hex::decode(bytecode_hex).unwrap_or_else(|_| panic!("Failed to decode bytecode: {}", bin_path)));

        // Create the contract generic strut
        Ok(ContractGeneric {
            name: Self::extract_name_from_path(abi_path),
            abi: interface,
            bytecode: bytecode,
            constructor_args: None,
            config: DeploymentConfig::default(),
        })
    }


    // Auto-discover all contracts in a directory
    pub fn scan_directory(path: &str) -> Result<Vec<ContractGeneric>> {
        let mut contracts = Vec::new();
        let path = Path::new(path);

        // Look for ABI/BIN files
        let abi_files = Self::find_files_with_extension(path, "abi");
        for abi_file in abi_files {
            let bin_file = abi_file.with_extension("bin");
            if bin_file.exists() {
                if let Ok(contract) = Self::from_abi_bin_files(&abi_file.to_str().unwrap(), &bin_file.to_str().unwrap()) {
                    contracts.push(contract);
                }
            }
        }
        Ok(contracts)
    }

    //TODO SCAN CONTRACT THAT NEED DEPS



    /////////////////////////
    /////// Helper Function /////////
    /////////////////////////

    // Find files with a specific extension
    fn find_files_with_extension(dir: &Path, extension: &str) -> Vec<PathBuf> {
        let mut files = Vec::new();

        if dir.is_dir() {
            for entry in std::fs::read_dir(dir).unwrap_or_else(|_| panic!("Failed to read directory: {}", dir.display())) {
                let path = entry.unwrap_or_else(|_| panic!("Failed to get entry: {}", dir.display())).path();
                if path.is_file() {
                    if let Some(file_extension) = path.extension() {
                        if file_extension == extension {
                            files.push(path);
                        }
                    }
                }
            }
        }
        files
    }


    // Extract the name from the path
    fn extract_name_from_path(path: &str) -> String {
        Path::new(path).file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string()
    }
}

//TODO ADD BETTER TESTING
// All test pass 
#[cfg(test)]
mod tests {
    use super::*;
    use crate::universal::contract_spec::ContractSpec;

    #[test]
    fn test_scan_director_empty() {
        let contracts = ContractDiscovery::scan_directory("tests/contract/").unwrap();
        println!("Found {} contracts", contracts.len());
        assert!(contracts.is_empty());
    }

    #[test]
    fn test_scan_directory_with_contracts() {
        let contracts = ContractDiscovery::scan_directory("tests/contracts/").unwrap();
        println!("Found {} contracts", contracts.len());
        assert!(!contracts.is_empty());
    }

    #[test]
    fn test_from_abi_bin_files() {
        let contract = ContractDiscovery::from_abi_bin_files("tests/contracts/SimpleStorage.abi", "tests/contracts/SimpleStorage.bin").unwrap();
        println!("Contract: {:?}", contract.get_name());
        assert_eq!(contract.get_name(), "SimpleStorage");
    }

}


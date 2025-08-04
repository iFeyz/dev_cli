pragma solidity ^0.8.9;

import "./aam_pool_sol.sol";

error PoolFactory__PairAlreadyExists();

contract PoolFactory {
    address[3][] private s_poolsList;
    uint256 private poolIdCounter = 0; // Counter for pool IDs

    struct PoolStruct {
        address poolAddress;
        uint8 fee;
    }

    struct PoolData {
        uint256 id; // Unique identifier for each pool
        address token0;
        address token1;
        uint256 reserve0;
        uint256 reserve1;
        uint256 totalSupply;
        address liquidityToken;
        uint8 fee;
    }

    mapping(address => mapping(address => PoolStruct)) private s_tokensToPool;

    event PoolCreated(
        uint256 indexed id,
        address indexed token0,
        address indexed token1,
        uint8 fee,
        address poolAddress
    );

    function createPool(
        address token0,
        address token1,
        uint8 fee
    ) external {
        require(fee <= 100, "Fee cannot be more than 1%");
        require(token0 != token1, "Cannot trade same token");

        require(
            s_tokensToPool[token0][token1].poolAddress == address(0) || 
            s_tokensToPool[token0][token1].fee != fee,
            "PoolFactory__PairAlreadyExists"
        );

        Pool pool = new Pool(token0, token1, fee);
        address poolAddress = address(pool);

        s_tokensToPool[token0][token1] = PoolStruct(poolAddress, fee);
        s_poolsList.push([token0, token1, poolAddress]);

        emit PoolCreated(poolIdCounter, token0, token1, fee, poolAddress);

        poolIdCounter++; // Increment the pool ID counter
    }

    function getPoolDetails() external view returns (PoolData[] memory) {
        PoolData[] memory pools = new PoolData[](s_poolsList.length);

        for (uint i = 0; i < s_poolsList.length; i++) {
            address poolAddress = s_poolsList[i][2];
            Pool pool = Pool(poolAddress);

            (uint256 reserve0, uint256 reserve1) = pool.getReserves();

            pools[i] = PoolData({
                id: i, // Use the index as an ID
                token0: s_poolsList[i][0],
                token1: s_poolsList[i][1],
                reserve0: reserve0,
                reserve1: reserve1,
                totalSupply: pool.totalSupply(),
                liquidityToken: poolAddress,
                fee: s_tokensToPool[s_poolsList[i][0]][s_poolsList[i][1]].fee
            });
        }

        return pools;
    }   

    function getPool(address token0, address token1, uint8 fee) external view returns (address) {
    PoolStruct memory p = s_tokensToPool[token0][token1];
    if (p.fee == fee) {
        return p.poolAddress;
    }
    return address(0);
} 
}
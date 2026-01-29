// ============================================================================
// EXAMPLE CONFIGURATION for test_add_liquidity.js
// ============================================================================
// Copy this to the CONFIG section in test_add_liquidity.js

const CONFIG = {
    // REQUIRED: Private key for signing
    // ⚠️  SECURITY: This key must match VERIFICATION_ADDRESS in your .env
    // ⚠️  NEVER commit real private keys to git!
    privateKey: '0xYOUR_PRIVATE_KEY_HERE',

    // RPC endpoint URL (where your node is running)
    rpcUrl: 'http://localhost:8080',

    // Solver ID (unique identifier for the solver)
    // Can be any string that identifies your solver
    solverId: 'test_solver_1',

    // Solver address (Ethereum address)
    // This is stored for reference but contract uses solverId
    solverAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',

    // Amount in smallest units
    // - For EVM: wei (1 ETH = 10^18 wei)
    // - For BTC: satoshis (1 BTC = 10^8 satoshis)
    amount: '1000000',

    // Chain ID
    // - 0: Bitcoin
    // - 9029: EVM/Qubetics
    chainId: 9029,

    // Number of requests to send
    // Use > 1 to test batch processing
    count: 1,

    // Interval between requests in milliseconds
    // Only used when count > 1
    interval: 1000,
};

// ============================================================================
// COMMON CONFIGURATIONS
// ============================================================================

// Single request test
// count: 1

// Batch test (5 requests)
// count: 5
// interval: 2000

// Load test (20 requests)
// count: 20
// interval: 500

// ============================================================================
// HARDHAT TEST KEYS (TESTNET ONLY!)
// ============================================================================
// ⚠️  WARNING: NEVER use these on mainnet!

// Hardhat Account #0
// privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

// Hardhat Account #1
// privateKey: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
// Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

// ============================================================================
// ENVIRONMENT-SPECIFIC CONFIGS
// ============================================================================

// Local Development
// rpcUrl: 'http://localhost:8080'

// Testnet
// rpcUrl: 'http://testnet.qubetics.io:8080'

// Remote Node
// rpcUrl: 'http://your-node-ip:8080'

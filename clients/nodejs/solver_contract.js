import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { time } from 'console';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up)
dotenv.config({ path: join(__dirname, '../../.env') });

// -------- CONFIG --------
const RPC_URL = process.env.SOLVER_CONTRACT_RPC_URL;
const CONTRACT_ADDRESS = process.env.SOLVER_CONTRACT_ADDRESS;

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

// Hardcoded fee-payer wallet for all onboard / validate / addLiquidity / role txns.
// Replace this with your own private key (0x-prefixed) before using in production.
// const FEE_PAYER_PRIVATE_KEY = "2f1765e04f0a5c394eb3b07ee38bf210008473f6e679a4f901f554905f7f3f89";
const solver1 = new ethers.Wallet(process.env.SOLVER1_PK, provider);

// -------- ABI (ONLY WHAT WE USE) --------
const ABI = [
  "function getNonce(address) view returns (uint256)",
  "function onboardSolver(string,string,uint256[],string[],uint256,bytes)",
  "function addLiquidityBatch(tuple(string solverId, uint256 amount, uint8 chainType)[])",
  "function validateSolverId(uint256,bytes)",
  "function isSolverActive(string) view returns (bool)",
  "function isSolverIdValidated(address) view returns (bool)",
  "function isSolverOnboarded(string) view returns (bool)",
  "function getSolverChainAmount(string,uint256) view returns (uint256)",
  "function getSolver(string) view returns (tuple(string,string,uint256[],string[],bool,bool,uint256,uint256))",
  "function MPC_ROLE() view returns (bytes32)",
  "function hasRole(bytes32,address) view returns (bool)",
  "function grantRole(bytes32,address)"
];

// -------- CONTRACT --------
const solverManager = new ethers.Contract(
  CONTRACT_ADDRESS,
  ABI,
  provider
);

// =====================================================
// UTILITY FUNCTIONS
// =====================================================

/**
 * Check if a solver is onboarded and active
 */
async function checkSolverStatus(solverId) {
  console.log(`\n🔍 Checking status for solver: ${solverId}\n`);
  
  try {
    const isOnboarded = await solverManager.isSolverOnboarded(solverId);
    const isActive = await solverManager.isSolverActive(solverId);
    
    console.log("Onboarded:", isOnboarded);
    console.log("Active:", isActive);
    
    if (isOnboarded && isActive) {
      const solverInfo = await solverManager.getSolver(solverId);
      console.log("\nSolver Info:");
      console.log("  Solver ID:", solverInfo[0]);
      console.log("  Solver Name:", solverInfo[1]);
      console.log("  Chain IDs:", solverInfo[2].map(id => id.toString()));
      console.log("  Addresses:", solverInfo[3]);
      console.log("  Active:", solverInfo[4]);
      console.log("  Validated:", solverInfo[5]);
      console.log("  Onboarded At:", new Date(solverInfo[6].toNumber() * 1000).toISOString());
      
      // Check liquidity amounts for each chain
      console.log("\n💰 Liquidity by Chain:");
      for (const chainId of solverInfo[2]) {
        const amount = await solverManager.getSolverChainAmount(solverId, chainId);
        console.log(`  Chain ${chainId}: ${amount.toString()}`);
      }
    }
    
    return { isOnboarded, isActive };
  } catch (e) {
    console.error("❌ Error checking solver:", e.message);
    return { isOnboarded: false, isActive: false };
  }
}

/**
 * Check if an address has MPC role
 */
async function checkMPCRole(address) {
  console.log(`\n🔐 Checking MPC role for: ${address}\n`);
  
  try {
    const mpcRole = await solverManager.MPC_ROLE();
    const hasRole = await solverManager.hasRole(mpcRole, address);
    
    console.log("MPC Role Hash:", mpcRole);
    console.log("Has MPC Role:", hasRole);
    
    return hasRole;
  } catch (e) {
    console.error("❌ Error checking role:", e.message);
    return false;
  }
}

/**
 * Grant MPC role to an address (requires admin)
 */
async function grantMPCRole(targetAddress) {
  console.log(`\n🔑 Granting MPC role to: ${targetAddress}\n`);
  
  try {
    const mpcRole = await solverManager.MPC_ROLE();
    const solverManagerWithSigner = solverManager.connect(solver1);
    
    const tx = await solverManagerWithSigner.grantRole(mpcRole, targetAddress);
    console.log("Transaction Hash:", tx.hash);
    console.log("Waiting for confirmation...");
    
    const receipt = await tx.wait();
    console.log("✅ Role granted! Block:", receipt.blockNumber);
    
    return true;
  } catch (e) {
    console.error("❌ Error granting role:", e.message);
    return false;
  }
}

/**
 * Onboard a solver
 */
async function onboardSolver(solverId, solverName, chainIds, solverAddresses) {
  console.log(`\n📝 Onboarding solver: ${solverId}\n`);
  
  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  
  const domain = {
    name: "SolverManager",
    version: "1",
    chainId,
    verifyingContract: CONTRACT_ADDRESS
  };
  
  // Check if solver already exists
  try {
    const status = await checkSolverStatus(solverId);
    if (status.isActive) {
      console.log("\n⚠️  WARNING: This solver ID is already onboarded and active!");
      console.log("Skipping onboarding.\n");
      return false;
    }
  } catch (e) {
    console.log("✓ Solver ID is available for onboarding\n");
  }
  
  let nonce = await solverManager.getNonce(solver1.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;
  
  console.log("Nonce:", nonce.toString());
  console.log("Deadline:", deadline.toString());
  
  const onboardTypes = {
    OnboardSolver: [
      { name: "solverId", type: "string" },
      { name: "solverName", type: "string" },
      { name: "chainIds", type: "uint256[]" },
      { name: "solverAddresses", type: "string[]" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" }
    ]
  };
  
  const onboardMessage = {
    solverId,
    solverName,
    chainIds,
    solverAddresses,
    nonce,
    deadline
  };
  
  const onboardSig = await solver1._signTypedData(domain, onboardTypes, onboardMessage);
  console.log("Onboard Signature:", onboardSig);
  
  console.log("\n🚀 Sending onboard transaction...\n");
  
  const solverManagerWithSigner = solverManager.connect(solver1);
  const tx = await solverManagerWithSigner.onboardSolver(
    solverId,
    solverName,
    chainIds,
    solverAddresses,
    deadline,
    onboardSig
  );
  
  console.log("Transaction Hash:", tx.hash);
  console.log("Waiting for confirmation...");
  
  const receipt = await tx.wait();
  console.log("✅ Onboarded! Block:", receipt.blockNumber);
  console.log("Gas Used:", receipt.gasUsed.toString());
  
  // Check final status
  await checkSolverStatus(solverId);
  
  return true;
}

/**
 * Check liquidity amounts for a solver across all chains
 */
async function checkSolverLiquidity(solverId) {
  console.log(`\n💰 Checking liquidity for solver: ${solverId}\n`);
  
  try {
    // First check if solver is onboarded
    const isOnboarded = await solverManager.isSolverOnboarded(solverId);
    if (!isOnboarded) {
      console.log("❌ Solver is not onboarded");
      return null;
    }
    
    // Get solver info to get chain IDs
    const solverInfo = await solverManager.getSolver(solverId);
    const chainIds = solverInfo[2];
    
    console.log(`Solver: ${solverInfo[0]} (${solverInfo[1]})`);
    console.log(`Active: ${solverInfo[4]}`);
    console.log(`Validated: ${solverInfo[5]}`);
    console.log(`\nLiquidity by Chain:`);
    
    const liquidityMap = {};
    let totalLiquidity = 0;
    
    for (const chainId of chainIds) {
      const amount = await solverManager.getSolverChainAmount(solverId, chainId);
      const amountNum = parseInt(amount.toString());
      liquidityMap[chainId.toString()] = amountNum;
      totalLiquidity += amountNum;
      
      const chainName = chainId.toString() === '0' ? 'BTC' : `EVM (${chainId})`;
      console.log(`  ${chainName}: ${amountNum.toLocaleString()}`);
    }
    
    console.log(`\n📊 Total Liquidity: ${totalLiquidity.toLocaleString()}`);
    
    return liquidityMap;
  } catch (e) {
    console.error("❌ Error checking liquidity:", e.message);
    return null;
  }
}

/**
 * Validate a solver (makes it active)
 */
async function validateSolver(solverId) {
  console.log(`\n🔐 Validating solver: ${solverId}\n`);
  
  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  
  const domain = {
    name: "SolverManager",
    version: "1",
    chainId,
    verifyingContract: CONTRACT_ADDRESS
  };
  
  let nonce = await solverManager.getNonce(solver1.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600; // current unix timestamp + 1 hour
  
  console.log("Nonce:", nonce.toString());
  console.log("Deadline:", deadline.toString());
  
  const validateTypes = {
    ValidateSolver: [
      { name: "solverId", type: "string" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" }
    ]
  };
  
  const validateMessage = {
    solverId,
    nonce,
    deadline
  };
  
  const validateSig = await solver1._signTypedData(domain, validateTypes, validateMessage);
  console.log("Validate Signature:", validateSig);
  
  console.log("\n🚀 Sending validate transaction...\n");
  
  const solverManagerWithSigner = solverManager.connect(solver1);
  const tx = await solverManagerWithSigner.validateSolverId(deadline, validateSig);
  
  console.log("Transaction Hash:", tx.hash);
  console.log("Waiting for confirmation...");
  
  const receipt = await tx.wait();
  console.log("✅ Validated! Block:", receipt.blockNumber);
  console.log("Gas Used:", receipt.gasUsed.toString());
  
  // Check if solver is now active
  await checkSolverStatus(solverId);
  
  return true;
}

/**
 * Test addLiquidityBatch function
 */
async function testAddLiquidityBatch(deposits) {
  console.log(`\n💧 Testing addLiquidityBatch with ${deposits.length} deposit(s)\n`);
  
  try {
    const solverManagerWithSigner = solverManager.connect(solver1);
    
    console.log("Deposits:");
    deposits.forEach((deposit, i) => {
      console.log(`  ${i + 1}. Solver: ${deposit.solverId}, Amount: ${deposit.amount}, ChainType: ${deposit.chainType}`);
    });
    
    console.log("\n🚀 Sending addLiquidityBatch transaction...\n");
    
    const tx = await solverManagerWithSigner.addLiquidityBatch(deposits);
    console.log("Transaction Hash:", tx.hash);
    console.log("Waiting for confirmation...");
    
    const receipt = await tx.wait();
    console.log("✅ Batch added! Block:", receipt.blockNumber);
    console.log("Gas Used:", receipt.gasUsed.toString());
    
    // Check updated liquidity amounts
    console.log("\n💰 Updated Liquidity:");
    for (const deposit of deposits) {
      const chainId = deposit.chainType === 0 ? 0 : 9029; // 0=BTC, 1=EVM(9029)
      const amount = await solverManager.getSolverChainAmount(deposit.solverId, chainId);
      console.log(`  ${deposit.solverId} on chain ${chainId}: ${amount.toString()}`);
    }
    
    return true;
  } catch (e) {
    console.error("❌ Error calling addLiquidityBatch:", e.message);
    if (e.error && e.error.data) {
      console.error("Revert reason:", e.error.data);
    }
    return false;
  }
}

// =====================================================
// MAIN FUNCTION
// =====================================================

async function main() {
  console.log("🚀 SolverManager Utility Script\n");
  
  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  
  console.log("Chain ID:", chainId);
  console.log("SolverManager:", CONTRACT_ADDRESS);
  console.log("Wallet:", solver1.address);
  console.log("\n" + "=".repeat(80) + "\n");
  
  // ⚠️ CONFIGURE YOUR SOLVER DETAILS HERE
  // You can now configure up to 3 different (peer-id, EVM address) pairs.
  // Use your node's libp2p peer IDs as solverId strings, and one EVM address per solver.
  const solverConfigs = [
    // {
    //   // Solver 1
    //   solverId: "12D3KooWG3BLEpXA3HRGiupN6ShTQSUpA1UKNfMUniULZkQrAgF1",
    //   solverName: "Solver_11",
    //   // For pure EVM solvers, you typically only need the EVM chain (9029)
    //   chainIds: [0,9029],
    //   solverAddresses: [
    //     // EVM address for solver 1
    //     "0x70a8cd2123ca1383d60ea0284d5a9c2416d99711",
    //     "mhXTfUQKHfjvkybjQA4Nbm776Db9kZ9SJo"
    //   ],
    // },
    // {
    //   // Solver 2
    //   solverId: "12D3KooWRPJYRDtUimxFxmEgRhVYa8GC7uRMVmvkTVLtTv9tpRYK",
    //   solverName: "Solver_22",
    //   chainIds: [0,9029],
    //   solverAddresses: [
    //     "0x6cae004444577fcdbc6c55801a60117f126b7e51",
    //     "mh9fTfU6tsqJLmMjQUZp1WvNvsBsdmLLJB"
    //   ],
    // },
    {
      // Solver 3
      solverId: "12D3KooWNgGGMigwBq9cG6mXNiLAMD4ZuX473qN9euY77AJAvsNW",
      solverName: "Solver_12679",
      chainIds: [0,9029],
      solverAddresses: [
        // EVM address for solver 3
        "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
        "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC"
      ],
    },
  ];

  // If you still want to work with a single solver, you can reference
  // solverConfigs[0] directly:
  const { solverId, solverName, chainIds, solverAddresses } = solverConfigs[0];
  
  // UNCOMMENT THE FUNCTION YOU WANT TO RUN:
  
  // 1. Check solver status (full details)
  await checkSolverStatus(solverId);
  
  // 2. Check solver liquidity only (quick check) for the first solver
  // await checkSolverLiquidity(solverId);
  
  // 3. Onboard a single solver (if not already onboarded)
  // await onboardSolver(solverId, solverName, chainIds, solverAddresses);
  
  // 4. Validate a single solver (REQUIRED to make it active!)
  // await validateSolver(solverId);

  // 5. Onboard & validate ALL configured solvers (3 peer-ids, 3 EVM addresses)
  // for (const cfg of solverConfigs) {
  //   console.log(`\n=== Onboard & validate ${cfg.solverId} (${cfg.solverName}) ===\n`);
  //   await onboardSolver(cfg.solverId, cfg.solverName, cfg.chainIds, cfg.solverAddresses);
  //   await validateSolver(cfg.solverId);
  // }
  
  // 6. Check MPC role for an address
  // const mpcAddress = "0xa37117b7285cfbc429dac7067009d6f18c73332d";
  // await checkMPCRole(mpcAddress);
  
  // 7. Grant MPC role (requires admin privileges)
  // const mpcAddress = "0xa37117b7285cfbc429dac7067009d6f18c73332d";
  // await grantMPCRole(mpcAddress);
  
  // 8. Test addLiquidityBatch
  const deposits = [
    {
      solverId: "12D3KooWNgGGMigwBq9cG6mXNiLAMD4ZuX473qN9euY77AJAvsNW",
      // Use a string for large values to avoid JS number overflow
      amount: "100000000",
      chainType: 0  // ⚠️ IMPORTANT: 0 = BTC, 1 = EVM (NOT the chain ID!)
    }
  ];
  await testAddLiquidityBatch(deposits);
  
  console.log("\n" + "=".repeat(80));
  console.log("✅ DONE!");
  console.log("=".repeat(80));
}

main().catch((err) => {
  console.error("❌ Error:", err);
  process.exit(1);
});

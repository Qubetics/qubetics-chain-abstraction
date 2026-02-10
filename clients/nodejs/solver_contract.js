import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up)
dotenv.config({ path: join(__dirname, '../../.env') });

// -------- CONFIG --------
const RPC_URL = process.env.RPC_URL;
const CONTRACT_ADDRESS = process.env.SOLVER_MANAGER_ADDRESS;

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

const solver1 = new ethers.Wallet(process.env.SOLVER1_PK, provider);

// SOLVER_004's private key for self-validation
const SOLVER_004_PK = '0x4f1dce53664453b7160cdf7f91c12539b71f4392e10f3c5c46812da97eb6a105';
const solver4 = new ethers.Wallet(SOLVER_004_PK, provider);

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
 * The solver must validate themselves using their own wallet
 */
async function validateSolver(solverId, solverWallet = solver1) {
  console.log(`\n🔐 Validating solver: ${solverId}\n`);
  console.log(`Using wallet: ${solverWallet.address}\n`);

  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);

  const domain = {
    name: "SolverManager",
    version: "1",
    chainId,
    verifyingContract: CONTRACT_ADDRESS
  };

  let nonce = await solverManager.getNonce(solverWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

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

  const validateSig = await solverWallet._signTypedData(domain, validateTypes, validateMessage);
  console.log("Validate Signature:", validateSig);

  console.log("\n🚀 Sending validate transaction...\n");

  const solverManagerWithSigner = solverManager.connect(solverWallet);
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
  const solverId = "SOLVER_004";
  const solverName = "Test_Solver_004";
  const chainIds = [0, 9029];  // 0 = BTC, 9029 = EVM/Qubetics
  const solverAddresses = [
    "tb1qgazak34uzm48srpfvmuexemjfux4znvxm8fu42",  // BTC address (testnet)
    "0x19B8C629B407D7E714F9FBF0DbbCd55085F5e7D8"   // EVM address
  ];

  // UNCOMMENT THE FUNCTION YOU WANT TO RUN:

  // 1. Check solver status (full details)
  // await checkSolverStatus(solverId);

  // 2. Check solver liquidity only (quick check)
  // await checkSolverLiquidity(solverId);

  // 3. Onboard solver (if not already onboarded)
  // await onboardSolver(solverId, solverName, chainIds, solverAddresses);

  // 4. Validate solver (REQUIRED to make it active!)
  // NOTE: The solver must validate themselves using their own wallet!
  // For SOLVER_004, we use solver4 wallet
  // await validateSolver(solverId, solver4);

  // 5. Check MPC role for addresses
  console.log("Checking MPC role for key addresses...\n");
  await checkMPCRole(solver1.address);  // SOLVER1 from .env
  await checkMPCRole(solver4.address);  // SOLVER_004
  await checkMPCRole("0xbac113cebd9CB2fBD2a01B5CBC43D0fC0EBed5e9");  // SOLVER_003
  
  // 6. Grant MPC role (requires admin privileges)
  // const mpcAddress = "0xa37117b7285cfbc429dac7067009d6f18c73332d";
  // await grantMPCRole(mpcAddress);
  
  // 7. Test addLiquidityBatch
  // const deposits = [
  //   {
  //     solverId: "SOLVER_002",
  //     amount: 1000,
  //     chainType: 1  // ⚠️ IMPORTANT: 0 = BTC, 1 = EVM (NOT the chain ID!)
  //   }
  // ];
  // await testAddLiquidityBatch(deposits);
  
  console.log("\n" + "=".repeat(80));
  console.log("✅ DONE!");
  console.log("=".repeat(80));
}

main().catch((err) => {
  console.error("❌ Error:", err);
  process.exit(1);
});

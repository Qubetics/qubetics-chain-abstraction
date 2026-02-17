import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up)
dotenv.config({ path: join(__dirname, '../../.env') });

// -------- CONFIG --------
const RPC_URL = process.env.SOLVER_CONTRACT_RPC_URL || process.env.RPC_URL;
const CONTRACT_ADDRESS = process.env.SOLVER_MANAGER_CONTRACT_ADDRESS || process.env.SOLVER_MANAGER_ADDRESS;

if (!RPC_URL) {
  console.error('❌ RPC URL required. Set SOLVER_CONTRACT_RPC_URL or RPC_URL in .env');
  process.exit(1);
}
if (!CONTRACT_ADDRESS || !CONTRACT_ADDRESS.startsWith('0x')) {
  console.error('❌ SolverManager contract address required. Set SOLVER_MANAGER_CONTRACT_ADDRESS or SOLVER_MANAGER_ADDRESS in .env');
  process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

// Three payer keys: each pays gas for its own solver (1,2,3).
const SOLVER_PAYER_KEYS = ['SOLVER1_PK', 'SOLVER2_PK', 'SOLVER3_PK'];
const payerWallets = SOLVER_PAYER_KEYS.map((key) => {
  const pk = process.env[key];
  if (!pk) {
    console.error(`❌ ${key} (payer PK) is required in .env`);
    process.exit(1);
  }
  return new ethers.Wallet(pk, provider);
});

// Single EIP-712 signer key: signs onboard/validate for ALL solvers.
const eip712Pk = process.env.EIP712_SIGNER_PK;
if (!eip712Pk) {
  console.error('❌ EIP712_SIGNER_PK is required in .env to sign onboard/validate (EIP-712)');
  process.exit(1);
}
const eip712Signer = new ethers.Wallet(eip712Pk, provider);

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
    const solverManagerWithSigner = solverManager.connect(txSender);

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
 * - signerWallet: EIP-712 signer (shared for all solvers)
 * - txWallet: pays gas (per-solver payer)
 */
async function onboardSolver(solverId, solverName, chainIds, solverAddresses, signerWallet, txWallet) {
  console.log(`\n📝 Onboarding solver: ${solverId}\n`);

  const network = await provider.getNetwork();
  const chainIdNum = Number(network.chainId);

  const domain = {
    name: "SolverManager",
    version: "1",
    chainId: chainIdNum,
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

  let nonce = await solverManager.getNonce(signerWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log("Signer:", signerWallet.address);
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

  const onboardSig = await signerWallet._signTypedData(domain, onboardTypes, onboardMessage);
  console.log("Onboard Signature:", onboardSig);

  console.log("\n🚀 Sending onboard transaction...\n");

  const solverManagerWithSigner = solverManager.connect(txWallet);
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
 * Validate a solver (makes it active).
 * - signerWallet: EIP-712 signer (shared for all solvers)
 * - txWallet: pays gas (per-solver payer)
 */
async function validateSolver(solverId, signerWallet, txWallet) {
  console.log(`\n🔐 Validating solver: ${solverId}\n`);

  const network = await provider.getNetwork();
  const chainIdNum = Number(network.chainId);

  const domain = {
    name: "SolverManager",
    version: "1",
    chainId: chainIdNum,
    verifyingContract: CONTRACT_ADDRESS
  };

  let nonce = await solverManager.getNonce(signerWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log("Signer:", signerWallet.address);
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

  const validateSig = await signerWallet._signTypedData(domain, validateTypes, validateMessage);
  console.log("Validate Signature:", validateSig);

  console.log("\n🚀 Sending validate transaction...\n");

  const solverManagerWithSigner = solverManager.connect(txWallet);
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
async function testAddLiquidityBatch(deposits, txWallet) {
  console.log(`\n💧 Testing addLiquidityBatch with ${deposits.length} deposit(s)\n`);

  try {
    const solverManagerWithSigner = solverManager.connect(txWallet);

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
// MAIN: 3 SOLVERS — ONBOARD, VALIDATE, ADD LIQUIDITY
// =====================================================

// Shared chain config for all solvers: 0 = BTC, 9029 = EVM/Qubetics
const CHAIN_IDS = [0, 9029];

/** Normalize for uniqueness check: ETH lowercase, BTC as-is. */
function normalizeAddress(addr, chain) {
  if (!addr || typeof addr !== "string") return "";
  const s = addr.trim();
  return chain === "eth" ? s.toLowerCase() : s;
}

/**
 * Ensure all 3 solvers have 2 whitelisted addresses each (1 ETH, 1 BTC) and all 6 are unique.
 */
function assertUniqueWhitelistedAddresses(solverConfigs) {
  const ethAddresses = [];
  const btcAddresses = [];
  for (const c of solverConfigs) {
    const eth = normalizeAddress(c.ethAddress, "eth");
    const btc = normalizeAddress(c.btcAddress, "btc");
    if (!eth || !btc) {
      throw new Error(
        `Solver ${c.solverId} must have both ethAddress and btcAddress set (whitelisted addresses).`
      );
    }
    ethAddresses.push(eth);
    btcAddresses.push(btc);
  }
  const ethSet = new Set(ethAddresses);
  const btcSet = new Set(btcAddresses);
  if (ethSet.size !== 3) {
    const dup = ethAddresses.filter((e, i) => ethAddresses.indexOf(e) !== i);
    throw new Error(
      `All 3 ETH whitelisted addresses must be unique. Duplicates or missing: ${dup.join(", ") || "check ethAddress per solver"}`
    );
  }
  if (btcSet.size !== 3) {
    const dup = btcAddresses.filter((e, i) => btcAddresses.indexOf(e) !== i);
    throw new Error(
      `All 3 BTC whitelisted addresses must be unique. Duplicates or missing: ${dup.join(", ") || "check btcAddress per solver"}`
    );
  }
  // Cross-check: no ETH address equals a BTC address (by value)
  const allNormalized = [...ethAddresses, ...btcAddresses];
  if (new Set(allNormalized).size !== 6) {
    throw new Error("ETH and BTC whitelisted addresses must not repeat across solvers.");
  }
  console.log("✓ All 6 whitelisted addresses (3 ETH + 3 BTC) are unique.\n");
}

async function main() {
  console.log("🚀 SolverManager — 3 Solvers: Onboard, Validate, Add Liquidity\n");

  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);

  console.log("Chain ID:", chainId);
  console.log("SolverManager:", CONTRACT_ADDRESS);
  console.log("EIP-712 signer (shared):", eip712Signer.address);
  console.log("Payers (gas senders):", payerWallets.map((w, i) => `Solver ${i + 1}: ${w.address}`).join(", "));
  console.log("\n" + "=".repeat(80) + "\n");

  // Signers: SOLVER1_PK, SOLVER2_PK, SOLVER3_PK in .env = the 3 private keys from addr_gen.js.
  // Whitelisted addresses (do not fund): 3 ETH + 3 BTC below, one pair per solver; all unique.
  const SOLVER_ETH_ADDRESSES = [
    "0x7B1a2c3D4E5f60718293a4b5C6d7E8F901234567",
    "0xA1b2C3d4E5F60718293A4b5c6D7e8F901234568",
    "0x1234567890aBCdEf1234567890abCDef12345678"
  ];
  const SOLVER_BTC_ADDRESSES = [
    "bc1q9y2u8v7d6s5r4t3p2n1m0l9k8j7h6g5f4d3c2b",
    "bc1q2w3e4r5t6y7u8i9o0pplkjhgfdsazxcvbnm123",
    "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
  ];

  const solverConfigs = [
    {
      solverId: "12D3KooWJUCBJ99wWnd2bF222XHeqRzzNeFQT9ZTD5vfwPc9sHRV",
      solverName: "Solver_Alphaaaa",
      ethAddress: process.env.SOLVER1_ETH || SOLVER_ETH_ADDRESSES[0],
      btcAddress: process.env.SOLVER1_BTC || SOLVER_BTC_ADDRESSES[0],
      signer: eip712Signer,
      txSender: payerWallets[0]
    },
    {
      solverId: "12D3KooWQLmPhQvkcG2ysWWQGBT7fuWEEwEVShbRWtLe1y3bN8oC",
      solverName: "Solver_Betaaaa",
      ethAddress: process.env.SOLVER2_ETH || SOLVER_ETH_ADDRESSES[1],
      btcAddress: process.env.SOLVER2_BTC || SOLVER_BTC_ADDRESSES[1],
      signer: eip712Signer,
      txSender: payerWallets[1]
    },
    {
      solverId: "12D3KooWBQD5KA83cpZLXi2d82XeR6YmMfJJn7iooJixkFCNnFD2",
      solverName: "Solver_Gammaaaa",
      ethAddress: process.env.SOLVER3_ETH || SOLVER_ETH_ADDRESSES[2],
      btcAddress: process.env.SOLVER3_BTC || SOLVER_BTC_ADDRESSES[2],
      signer: eip712Signer,
      txSender: payerWallets[2]
    }
  ].map((c) => ({
    ...c,
    // Order must match CHAIN_IDS [0, 9029]: index 0 = BTC, index 1 = ETH
    solverAddresses: [c.btcAddress, c.ethAddress]
  }));

  assertUniqueWhitelistedAddresses(solverConfigs);

  // Keep large wei amounts as strings to avoid JS number overflow (ethers accepts string for uint256).
  const liquidityAmountEVMStr = process.env.LIQUIDITY_AMOUNT_EVM || "10000000000000000000"; // 10 * 10^18 wei
  const liquidityAmountBTCStr = process.env.LIQUIDITY_AMOUNT_BTC || "10000";
  const liquidityAmountEVM = ethers.BigNumber.from(liquidityAmountEVMStr);
  const liquidityAmountBTC = ethers.BigNumber.from(liquidityAmountBTCStr);

  // --- 1. Onboard each solver ---
  // console.log("\n" + "=".repeat(80));
  // console.log("STEP 1: ONBOARD (3 solvers)");
  // console.log("=".repeat(80));

  // for (const cfg of solverConfigs) {
  //   await onboardSolver(
  //     cfg.solverId,
  //     cfg.solverName,
  //     CHAIN_IDS,
  //     cfg.solverAddresses,
  //     cfg.signer,
  //     cfg.txSender
  //   );
  // }

  // --- 2. Validate each solver ---
  // console.log("\n" + "=".repeat(80));
  // console.log("STEP 2: VALIDATE (3 solvers)");
  // console.log("=".repeat(80));

  // for (const cfg of solverConfigs) {
  //   await validateSolver(cfg.solverId, cfg.signer, cfg.txSender);
  // }

  // --- 3. Add liquidity (one batch: all 3 solvers) ---
  console.log("\n" + "=".repeat(80));
  console.log("STEP 3: ADD LIQUIDITY BATCH (3 solvers)");
  console.log("=".repeat(80));

  const deposits = [];
  for (const cfg of solverConfigs) {
    if (liquidityAmountEVM.gt(0)) {
      deposits.push({ solverId: cfg.solverId, amount: liquidityAmountEVM, chainType: 1 }); // 1 = EVM
    }
    if (liquidityAmountBTC.gt(0)) {
      deposits.push({ solverId: cfg.solverId, amount: liquidityAmountBTC, chainType: 0 });   // 0 = BTC
    }
  }

  if (deposits.length > 0) {
    // Use payer 1 to pay gas for the liquidity batch.
    await testAddLiquidityBatch(deposits, payerWallets[0]);
  } else {
    console.log("\n⚠️  No liquidity added (set LIQUIDITY_AMOUNT_EVM and/or LIQUIDITY_AMOUNT_BTC in .env)");
  }

  // --- 4. Final check: are all solvers active? ---
  console.log("\n" + "=".repeat(80));
  console.log("STEP 4: CHECK SOLVER STATUS (active or not)");
  console.log("=".repeat(80));

  const statuses = [];
  for (const cfg of solverConfigs) {
    const status = await checkSolverStatus(cfg.solverId);
    statuses.push({ solverId: cfg.solverId, ...status });
  }

  console.log("\n📋 Summary:");
  const active = statuses.filter((s) => s.isActive);
  const inactive = statuses.filter((s) => !s.isActive);
  for (const s of statuses) {
    console.log(`  ${s.solverId}: ${s.isActive ? "✅ ACTIVE" : "❌ NOT ACTIVE"} (onboarded: ${s.isOnboarded})`);
  }
  console.log(`\n  Total: ${active.length} active, ${inactive.length} inactive`);

  console.log("\n" + "=".repeat(80));
  console.log("✅ DONE — 3 solvers onboarded, validated, liquidity added, status checked.");
  console.log("=".repeat(80));
}

main().catch((err) => {
  console.error("❌ Error:", err);
  process.exit(1);
});
#!/usr/bin/env node

/**
 * Onboard a solver and/or add liquidity directly on the SolverManager contract (on-chain).
 * Uses SOLVER_CONTRACT_RPC_URL, SOLVER_CONTRACT_ADDRESS, SOLVER_CONTRACT_CHAIN_ID from env.
 *
 * Usage:
 *   # Onboard only (validator signs EIP-712; caller must have admin/validator role)
 *   VALIDATOR_PRIVATE_KEY=0x... SOLVER_ID=mySolver SOLVER_NAME="My Solver" \
 *     CHAIN_IDS=0,9029 SOLVER_ADDRESSES=bc1q...,0x... node onboard_and_add_liquidity_contract.js onboard
 *
 *   # Add liquidity only (caller must have MPC_ROLE)
 *   MPC_PRIVATE_KEY=0x... SOLVER_ID=mySolver AMOUNT=1000000000000000000 CHAIN_TYPE=1 \
 *     node onboard_and_add_liquidity_contract.js add
 *
 *   # Both: onboard then add liquidity
 *   VALIDATOR_PRIVATE_KEY=0x... MPC_PRIVATE_KEY=0x... SOLVER_ID=... SOLVER_NAME=... \
 *     CHAIN_IDS=0,9029 SOLVER_ADDRESSES=... AMOUNT=... CHAIN_TYPE=1 \
 *     node onboard_and_add_liquidity_contract.js both
 *
 * Env:
 *   SOLVER_CONTRACT_RPC_URL, SOLVER_CONTRACT_ADDRESS, SOLVER_CONTRACT_CHAIN_ID
 *   VALIDATOR_PRIVATE_KEY - for onboarding (must be validatorAddress on contract)
 *   MPC_PRIVATE_KEY - for addLiquidityBatch (must have MPC_ROLE)
 *   SOLVER_ID, SOLVER_NAME - for onboarding
 *   CHAIN_IDS - comma-separated (e.g. 0,9029 for BTC, TICS)
 *   SOLVER_ADDRESSES - comma-separated, same order as chainIds (e.g. btcAddr,ethAddr)
 *   AMOUNT - wei/sats string for add liquidity
 *   CHAIN_TYPE - 0 = BTC, 1 = TICS (SolverManager.ChainType)
 */

import { ethers } from 'ethers';

const SOLVER_MANAGER_ABI = [
  'function onboardSolver(string solverId, string solverName, uint256[] chainIds, string[] solverAddresses, uint256 deadline, bytes signature)',
  'function addLiquidityBatch(tuple(string solverId, uint256 amount, uint8 chainType)[] deposits)',
  'function getDomainSeparator() view returns (bytes32)',
  'function getSolverId(address solver) view returns (string)',
  'function getMinimumLiquidityTICS() view returns (uint256)',
  'function getMinimumLiquidityBTC() view returns (uint256)',
  'function eip712Domain() view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)',
];

const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
};

function getEnv(name, def) {
  const v = process.env[name];
  if (v !== undefined && v !== '') return v;
  return def;
}

async function getEip712Domain(contract) {
  try {
    const d = await contract.eip712Domain();
    return {
      name: d.name,
      version: d.version,
      chainId: d.chainId.toNumber ? d.chainId.toNumber() : Number(d.chainId),
      verifyingContract: d.verifyingContract,
    };
  } catch (e) {
    console.warn(`${colors.yellow}Could not read eip712Domain from contract, using defaults: ${e.message}${colors.reset}`);
    const network = await contract.provider.getNetwork();
    const chainId = network.chainId;
    return {
      name: 'SolverManager',
      version: '1',
      chainId: chainId.toNumber ? chainId.toNumber() : Number(chainId),
      verifyingContract: contract.address,
    };
  }
}

/**
 * EIP-712 typed data for OnboardSolver.
 * Struct must match contract's ONBOARD_SOLVER_TYPEHASH.
 */
function buildOnboardTypedData(domain, solverId, solverName, chainIds, solverAddresses, deadline) {
  return {
    types: {
      OnboardSolver: [
        { name: 'solverId', type: 'string' },
        { name: 'solverName', type: 'string' },
        { name: 'chainIds', type: 'uint256[]' },
        { name: 'solverAddresses', type: 'string[]' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'OnboardSolver',
    domain,
    message: {
      solverId,
      solverName,
      chainIds: chainIds.map(n => ethers.BigNumber.from(n)),
      solverAddresses,
      deadline: ethers.BigNumber.from(deadline),
    },
  };
}

async function runOnboard(provider, contract, wallet) {
  const solverId = getEnv('SOLVER_ID', '');
  const solverName = getEnv('SOLVER_NAME', 'Solver');
  const chainIdsStr = getEnv('CHAIN_IDS', '9029');
  const addressesStr = getEnv('SOLVER_ADDRESSES', '');
  if (!solverId) {
    throw new Error('SOLVER_ID is required for onboard');
  }
  const chainIds = chainIdsStr.split(',').map(s => parseInt(s.trim(), 10));
  const solverAddresses = addressesStr.split(',').map(s => s.trim()).filter(Boolean);
  if (solverAddresses.length !== chainIds.length) {
    throw new Error('SOLVER_ADDRESSES length must match CHAIN_IDS length');
  }

  const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour

  const domain = await getEip712Domain(contract);
  const typedData = buildOnboardTypedData(domain, solverId, solverName, chainIds, solverAddresses, deadline);

  const signature = await wallet._signTypedData(
    typedData.domain,
    { OnboardSolver: typedData.types.OnboardSolver },
    typedData.message
  );

  console.log(`${colors.blue}Onboarding solver ${solverId}...${colors.reset}`);
  const signerContract = contract.connect(wallet);
  const tx = await signerContract.onboardSolver(
    solverId,
    solverName,
    chainIds,
    solverAddresses,
    deadline,
    signature
  );
  const receipt = await tx.wait();
  console.log(`${colors.green}✅ OnboardSolver tx: ${receipt.transactionHash}${colors.reset}`);
  return receipt;
}

async function runAddLiquidity(contract, wallet) {
  const solverId = getEnv('SOLVER_ID', '');
  const amountStr = getEnv('AMOUNT', '1000000000000000000');
  const chainType = parseInt(getEnv('CHAIN_TYPE', '1'), 10); // 0 = BTC, 1 = TICS
  if (!solverId) {
    throw new Error('SOLVER_ID is required for add');
  }
  const amount = ethers.BigNumber.from(amountStr);

  const deposits = [{ solverId, amount, chainType }];
  console.log(`${colors.blue}Calling addLiquidityBatch: solverId=${solverId}, amount=${amountStr}, chainType=${chainType}${colors.reset}`);
  const tx = await contract.addLiquidityBatch(deposits);
  const receipt = await tx.wait();
  console.log(`${colors.green}✅ addLiquidityBatch tx: ${receipt.transactionHash}${colors.reset}`);
  return receipt;
}

async function main() {
  const rpcUrl = getEnv('SOLVER_CONTRACT_RPC_URL', 'http://127.0.0.1:8545');
  const contractAddress = getEnv('SOLVER_CONTRACT_ADDRESS', '');
  const chainId = getEnv('SOLVER_CONTRACT_CHAIN_ID', '9029');

  if (!contractAddress) {
    console.error(`${colors.red}SOLVER_CONTRACT_ADDRESS is required${colors.reset}`);
    process.exit(1);
  }

  const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(contractAddress, SOLVER_MANAGER_ABI, provider);

  const cmd = (process.argv[2] || 'both').toLowerCase();

  if (cmd === 'onboard') {
    const pk = getEnv('VALIDATOR_PRIVATE_KEY', '');
    if (!pk) {
      console.error(`${colors.red}VALIDATOR_PRIVATE_KEY is required for onboard${colors.reset}`);
      process.exit(1);
    }
    const wallet = new ethers.Wallet(pk, provider);
    await runOnboard(provider, contract, wallet);
    return;
  }

  if (cmd === 'add') {
    const pk = getEnv('MPC_PRIVATE_KEY', getEnv('VALIDATOR_PRIVATE_KEY', ''));
    if (!pk) {
      console.error(`${colors.red}MPC_PRIVATE_KEY is required for add (wallet must have MPC_ROLE)${colors.reset}`);
      process.exit(1);
    }
    const wallet = new ethers.Wallet(pk, provider);
    const signerContract = contract.connect(wallet);
    await runAddLiquidity(signerContract, wallet);
    return;
  }

  if (cmd === 'both') {
    const validatorPk = getEnv('VALIDATOR_PRIVATE_KEY', '');
    const mpcPk = getEnv('MPC_PRIVATE_KEY', validatorPk);
    if (!validatorPk) {
      console.error(`${colors.red}VALIDATOR_PRIVATE_KEY is required for both${colors.reset}`);
      process.exit(1);
    }
    const validatorWallet = new ethers.Wallet(validatorPk, provider);
    await runOnboard(provider, contract, validatorWallet);
    const mpcWallet = new ethers.Wallet(mpcPk, provider);
    const signerContract = contract.connect(mpcWallet);
    await runAddLiquidity(signerContract, mpcWallet);
    return;
  }

  console.error(`${colors.red}Unknown command: ${cmd}. Use onboard | add | both${colors.reset}`);
  process.exit(1);
}

main().catch((err) => {
  console.error(`${colors.red}${err.message}${colors.reset}`);
  process.exit(1);
});

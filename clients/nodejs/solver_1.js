import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import http from 'http';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up) - same as solver_contract.js
dotenv.config({ path: join(__dirname, '../../.env') });

// -------- CONFIG (aligned with solver_contract.js) --------
const RPC_URL = process.env.RPC_URL;
const CONTRACT_ADDRESS = process.env.SOLVER_MANAGER_ADDRESS;

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

// Solver identity: from SOLVER1_PK (same as solver_contract.js EIP-712 signer) or env
const signerWallet = process.env.SOLVER1_PK
  ? new ethers.Wallet(process.env.SOLVER1_PK, provider)
  : null;

const SOLVER_ID = process.env.SOLVER_ID || 'SOLVER_xxx';
const SOLVER_ETH_ADDRESS = process.env.SOLVER_ETH_ADDRESS || (signerWallet && signerWallet.address) || null;
const SOLVER_BTC_ADDRESS = process.env.SOLVER_BTC_ADDRESS || null;

// MPC node RPC for unclaimed rewards / intents solved
const MPC_RPC_URL = process.env.MPC_RPC_URL || 'http://127.0.0.1:8082';
const API_KEY = process.env.RPC_API_KEY || '';

// -------- ABI --------
const ABI = [
  "function getSolverClaimedReward(string solverId, uint256 chainId) view returns (uint256)",
  "function getSolverChainAmount(string solverId, uint256 chainId) view returns (uint256)",
  "function getSolver(string solverId) view returns (tuple(string,string,uint256[],string[],bool,bool,uint256,uint256))",
  "function isSolverOnboarded(string solverId) view returns (bool)",
  "function isSolverActive(string solverId) view returns (bool)",
  "function VALIDATED_REWARD_PERCENTAGE() view returns (uint256)",
  "function NON_VALIDATED_REWARD_PERCENTAGE() view returns (uint256)",
  "function PERCENTAGE_DIVISOR() view returns (uint256)"
];

const solverManager = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

// -------- COLORS --------
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

// -------- HTTP HELPER --------
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: API_KEY ? { 'x-api-key': API_KEY } : {}
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// -------- FORMATTING HELPERS --------
function formatBTC(sats) {
  const btc = Number(sats) / 100000000;
  return `${Number(sats).toLocaleString()} sats (${btc.toFixed(8)} BTC)`;
}

function formatTICS(wei) {
  const tics = ethers.utils.formatEther(wei);
  return `${Number(tics).toLocaleString()} TICS`;
}

function printHeader(title) {
  console.log('\n' + colors.cyan + '='.repeat(70) + colors.reset);
  console.log(colors.bright + colors.cyan + ' ' + title + colors.reset);
  console.log(colors.cyan + '='.repeat(70) + colors.reset);
}

function printSection(title) {
  console.log('\n' + colors.yellow + '▸ ' + title + colors.reset);
  console.log(colors.yellow + '-'.repeat(40) + colors.reset);
}

// -------- MAIN FUNCTIONS --------

async function checkSolverStatus() {
  printSection('Solver Status');

  try {
    const isOnboarded = await solverManager.isSolverOnboarded(SOLVER_ID);
    const isActive = await solverManager.isSolverActive(SOLVER_ID);

    console.log(`  Solver ID:     ${colors.bright}${SOLVER_ID}${colors.reset}`);
    console.log(`  Onboarded:     ${isOnboarded ? colors.green + '✓ Yes' : colors.red + '✗ No'}${colors.reset}`);
    console.log(`  Active:        ${isActive ? colors.green + '✓ Yes' : colors.red + '✗ No'}${colors.reset}`);

    if (isOnboarded) {
      const solverInfo = await solverManager.getSolver(SOLVER_ID);
      const chainIds = solverInfo[2] || [];
      const addresses = solverInfo[3] || [];
      console.log(`  ${colors.cyan}(Contract: addresses[i] is for chainIds[i]; 0 = BTC, 9029 = EVM)${colors.reset}`);
      if (addresses.length > 0 && addresses.length === chainIds.length) {
        for (let i = 0; i < chainIds.length; i++) {
          const cid = chainIds[i].toString();
          const label = cid === '0' ? 'BTC' : cid === '9029' ? 'EVM' : `chain ${cid}`;
          console.log(`  ${label} (chain ${cid}): ${addresses[i]}`);
        }
      } else {
        console.log(`  ${colors.yellow}chainIds: [${chainIds.map(c => c.toString()).join(', ')}]${colors.reset}`);
        console.log(`  ${colors.yellow}addresses: [${addresses.join(', ')}]${colors.reset}`);
      }
      if (SOLVER_ETH_ADDRESS) {
        const evmIdx = chainIds.findIndex(c => c.toString() === '9029');
        const contractEvm = evmIdx >= 0 && addresses[evmIdx] ? addresses[evmIdx] : null;
        const match = contractEvm && contractEvm.toLowerCase() === SOLVER_ETH_ADDRESS.toLowerCase();
        console.log(`  Your .env (SOLVER1_PK): ${SOLVER_ETH_ADDRESS} ${match ? colors.green + '✓ matches contract EVM' : colors.red + '✗ does NOT match contract EVM above'}${colors.reset}`);
      }
      console.log(`  Validated:     ${solverInfo[5] ? colors.green + '✓ Yes' : colors.red + '✗ No'}${colors.reset}`);
      console.log(`  Onboarded At:  ${new Date(solverInfo[6].toNumber() * 1000).toISOString()}`);
    }

    return { isOnboarded, isActive };
  } catch (e) {
    console.log(`  ${colors.red}Error: ${e.message}${colors.reset}`);
    return { isOnboarded: false, isActive: false };
  }
}

async function checkLiquidity() {
  printSection('Liquidity (sats / TICS)');

  try {
    const btcLiquidity = await solverManager.getSolverChainAmount(SOLVER_ID, 0);
    const ticsLiquidity = await solverManager.getSolverChainAmount(SOLVER_ID, 9029);

    console.log(`  BTC (chain 0):     ${colors.green}${formatBTC(btcLiquidity)}${colors.reset}`);
    console.log(`  TICS (chain 9029): ${colors.green}${formatTICS(ticsLiquidity)}${colors.reset}`);

    return { btc: btcLiquidity, tics: ticsLiquidity };
  } catch (e) {
    console.log(`  ${colors.red}Error: ${e.message}${colors.reset}`);
    return { btc: 0, tics: 0 };
  }
}

async function checkClaimedRewards() {
  printSection('Claimed Rewards (sats / TICS)');

  try {
    const btcClaimed = await solverManager.getSolverClaimedReward(SOLVER_ID, 0);
    const ticsClaimed = await solverManager.getSolverClaimedReward(SOLVER_ID, 9029);

    console.log(`  BTC Claimed:   ${btcClaimed.gt(0) ? colors.green : colors.yellow}${formatBTC(btcClaimed)}${colors.reset}`);
    console.log(`  TICS Claimed:  ${ticsClaimed.gt(0) ? colors.green : colors.yellow}${formatTICS(ticsClaimed)}${colors.reset}`);

    return { btc: btcClaimed, tics: ticsClaimed };
  } catch (e) {
    console.log(`  ${colors.red}Error: ${e.message}${colors.reset}`);
    return { btc: 0, tics: 0 };
  }
}

async function checkUnclaimedRewards() {
  printSection('Unclaimed Rewards (Pending/Batched)');

  if (!SOLVER_ETH_ADDRESS) {
    console.log(`  ${colors.yellow}Set SOLVER_ETH_ADDRESS or SOLVER1_PK in .env to fetch from MPC${colors.reset}`);
    return [];
  }

  try {
    const response = await httpGet(`${MPC_RPC_URL}/solver_rewards?solver_address=${SOLVER_ETH_ADDRESS}`);

    if (response.status === 'success') {
      const unclaimed = response.unclaimed_rewards || [];
      console.log(`  Total Pending: ${unclaimed.length} request(s)`);

      if (unclaimed.length > 0) {
        console.log('');
        unclaimed.forEach((reward, idx) => {
          console.log(`  ${colors.magenta}[${idx + 1}] Request ID: ${reward.request_id}${colors.reset}`);
          console.log(`      Status:   ${reward.status}`);
          if (reward.tics_address) console.log(`      TICS Addr: ${reward.tics_address}`);
          if (reward.btc_address) console.log(`      BTC Addr: ${reward.btc_address}`);
          if (reward.tx_id) console.log(`      TX ID:    ${reward.tx_id}`);
        });
      } else {
        console.log(`  ${colors.yellow}No pending reward claims${colors.reset}`);
      }

      return unclaimed;
    } else {
      console.log(`  ${colors.red}Error: ${response.message || 'Unknown error'}${colors.reset}`);
      return [];
    }
  } catch (e) {
    console.log(`  ${colors.red}Error fetching from MPC: ${e.message}${colors.reset}`);
    return [];
  }
}

async function checkIntentsSolved() {
  printSection('Intents Solved');

  if (!SOLVER_ETH_ADDRESS) {
    console.log(`  ${colors.yellow}Set SOLVER_ETH_ADDRESS or SOLVER1_PK in .env to fetch from MPC${colors.reset}`);
    return 0;
  }

  try {
    const response = await httpGet(`${MPC_RPC_URL}/intents_solved_count?solver_address=${SOLVER_ETH_ADDRESS}`);

    const count = response.count || 0;
    console.log(`  Total Intents Solved: ${count > 0 ? colors.green : colors.yellow}${count}${colors.reset}`);

    if (count === 0) {
      console.log(`  ${colors.yellow}ℹ No intents solved yet - rewards are earned by solving user intents${colors.reset}`);
    }

    return count;
  } catch (e) {
    console.log(`  ${colors.red}Error fetching intents count: ${e.message}${colors.reset}`);
    return 0;
  }
}

async function checkRewardPercentages() {
  printSection('Reward Configuration');

  try {
    const validatedPct = await solverManager.VALIDATED_REWARD_PERCENTAGE();
    const nonValidatedPct = await solverManager.NON_VALIDATED_REWARD_PERCENTAGE();
    const divisor = await solverManager.PERCENTAGE_DIVISOR();

    console.log(`  Validated Solver Reward:     ${validatedPct.toString()}% (of total reward pool)`);
    console.log(`  Non-Validated Solver Reward: ${nonValidatedPct.toString()}% (of total reward pool)`);
    console.log(`  Percentage Divisor:          ${divisor.toString()}`);

    return { validatedPct, nonValidatedPct, divisor };
  } catch (e) {
    console.log(`  ${colors.red}Error: ${e.message}${colors.reset}`);
    return {};
  }
}

async function printSummary(data) {
  printHeader('SOLVER STATS SUMMARY');

  const { status, liquidity, claimed, unclaimed, intentsSolved } = data;

  console.log(`
  ${colors.bright}Solver:${colors.reset} ${SOLVER_ID} (${status.isActive ? colors.green + 'Active' : colors.red + 'Inactive'}${colors.reset})
  ${SOLVER_ETH_ADDRESS ? `${colors.bright}ETH:${colors.reset} ${SOLVER_ETH_ADDRESS}` : ''}

  ${colors.bright}Liquidity:${colors.reset}
    • BTC (sats):  ${formatBTC(liquidity.btc)}
    • TICS:        ${formatTICS(liquidity.tics)}

  ${colors.bright}Rewards:${colors.reset}
    • Intents Solved:    ${intentsSolved}
    • BTC Claimed:      ${formatBTC(claimed.btc)}
    • TICS Claimed:     ${formatTICS(claimed.tics)}
    • Pending Claims:   ${unclaimed.length}
  `);

  if (intentsSolved === 0) {
    console.log(`  ${colors.yellow}💡 Tip: Start solving user intents to earn rewards!${colors.reset}`);
  }
}

// -------- MAIN --------
async function main() {
  printHeader(`SOLVER STATS / REWARDS - ${SOLVER_ID}`);

  console.log(`\n  ${colors.blue}Contract:${colors.reset} ${CONTRACT_ADDRESS}`);
  console.log(`  ${colors.blue}MPC RPC:${colors.reset}  ${MPC_RPC_URL}`);
  console.log(`  ${colors.blue}EVM RPC:${colors.reset}  ${RPC_URL}`);
  if (signerWallet) {
    console.log(`  ${colors.blue}Solver identity (SOLVER1_PK):${colors.reset} ${signerWallet.address}`);
  } else if (!SOLVER_ETH_ADDRESS) {
    console.log(`  ${colors.yellow}Set SOLVER_ETH_ADDRESS or SOLVER1_PK in .env for MPC reward lookups${colors.reset}`);
  }

  const status = await checkSolverStatus();
  const liquidity = await checkLiquidity();
  const claimed = await checkClaimedRewards();
  const unclaimed = await checkUnclaimedRewards();
  const intentsSolved = await checkIntentsSolved();
  await checkRewardPercentages();

  await printSummary({ status, liquidity, claimed, unclaimed, intentsSolved });

  console.log(colors.cyan + '='.repeat(70) + colors.reset + '\n');
}

main().catch((err) => {
  console.error(`${colors.red}Error: ${err.message}${colors.reset}`);
  process.exit(1);
});
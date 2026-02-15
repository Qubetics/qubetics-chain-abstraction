import { ethers } from 'ethers';
import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../../.env') });

const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_URL);

// Target address (where transfers are sent to in test_sequencer_parallel.js)
const TARGET_ADDRESS = '0x052e109a83bce9217270ca2880035c9d7de9065e';

// Parse command line arguments
const WATCH_MODE = process.argv.includes('--watch');
const WATCH_INTERVAL = parseInt(process.argv.find(arg => arg.startsWith('--interval='))?.split('=')[1] || '10');

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

async function getBalances() {
  const data = JSON.parse(fs.readFileSync(join(__dirname, 'registered_eth_addresses.json'), 'utf8'));
  const usersWithDerived = data.filter(u => u.derivedEthAddress !== null && u.derivedEthAddress !== undefined);

  let totalDerivedBalance = ethers.BigNumber.from(0);
  let totalNonce = 0;

  for (const user of usersWithDerived) {
    const balance = await provider.getBalance(user.derivedEthAddress);
    const nonce = await provider.getTransactionCount(user.derivedEthAddress);
    totalDerivedBalance = totalDerivedBalance.add(balance);
    totalNonce += nonce;
  }

  const targetBalance = await provider.getBalance(TARGET_ADDRESS);
  const targetNonce = await provider.getTransactionCount(TARGET_ADDRESS);

  return {
    derivedCount: usersWithDerived.length,
    totalDerivedBalance,
    totalNonce,
    targetBalance,
    targetNonce,
    timestamp: new Date()
  };
}

function formatBalance(balance) {
  return parseFloat(ethers.utils.formatEther(balance)).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });
}

function printBalances(balances, label = 'Current') {
  console.log('');
  console.log(`${colors.bold}${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bold}${label} Balances - ${balances.timestamp.toLocaleTimeString()}${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log('');
  console.log(`${colors.bold}Derived Addresses (${balances.derivedCount}):${colors.reset}`);
  console.log(`  Total Balance: ${colors.cyan}${formatBalance(balances.totalDerivedBalance)} TICS${colors.reset}`);
  console.log(`  Total Nonce:   ${balances.totalNonce}`);
  console.log('');
  console.log(`${colors.bold}Target Address:${colors.reset}`);
  console.log(`  ${TARGET_ADDRESS}`);
  console.log(`  Balance: ${colors.cyan}${formatBalance(balances.targetBalance)} TICS${colors.reset}`);
  console.log(`  Nonce:   ${balances.targetNonce}`);
}

function printComparison(before, after) {
  const targetIncrease = after.targetBalance.sub(before.targetBalance);
  const derivedDecrease = before.totalDerivedBalance.sub(after.totalDerivedBalance);
  const nonceIncrease = after.totalNonce - before.totalNonce;

  const targetIncreaseFormatted = formatBalance(targetIncrease);
  const derivedDecreaseFormatted = formatBalance(derivedDecrease);

  console.log('');
  console.log(`${colors.bold}${colors.yellow}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bold}Transaction Summary${colors.reset}`);
  console.log(`${colors.yellow}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log('');

  console.log(`${colors.bold}Target Address:${colors.reset}`);
  console.log(`  Before:   ${formatBalance(before.targetBalance)} TICS`);
  console.log(`  After:    ${formatBalance(after.targetBalance)} TICS`);
  if (targetIncrease.gt(0)) {
    console.log(`  Change:   ${colors.green}+${targetIncreaseFormatted} TICS${colors.reset}`);
  } else if (targetIncrease.lt(0)) {
    console.log(`  Change:   ${colors.red}${targetIncreaseFormatted} TICS${colors.reset}`);
  } else {
    console.log(`  Change:   ${colors.gray}0.00 TICS${colors.reset}`);
  }

  console.log('');
  console.log(`${colors.bold}Derived Addresses (Total):${colors.reset}`);
  console.log(`  Before:   ${formatBalance(before.totalDerivedBalance)} TICS`);
  console.log(`  After:    ${formatBalance(after.totalDerivedBalance)} TICS`);
  if (derivedDecrease.gt(0)) {
    console.log(`  Change:   ${colors.red}-${derivedDecreaseFormatted} TICS${colors.reset}`);
  } else if (derivedDecrease.lt(0)) {
    console.log(`  Change:   ${colors.green}+${formatBalance(derivedDecrease.abs())} TICS${colors.reset}`);
  } else {
    console.log(`  Change:   ${colors.gray}0.00 TICS${colors.reset}`);
  }

  console.log('');
  console.log(`${colors.bold}Nonce Change:${colors.reset} ${before.totalNonce} → ${after.totalNonce} (+${nonceIncrease})`);

  // Calculate confirmed transactions
  if (derivedDecrease.gt(0)) {
    const confirmedTxCount = Math.round(parseFloat(ethers.utils.formatEther(derivedDecrease)) / 0.5);
    console.log('');
    console.log(`${colors.bold}${colors.green}════════════════════════════════════════════════════════${colors.reset}`);
    console.log(`${colors.bold}${colors.green}✓ Confirmed Transactions: ${confirmedTxCount}${colors.reset}`);
    console.log(`${colors.gray}  (based on ${derivedDecreaseFormatted} TICS decrease @ 0.5 TICS/tx)${colors.reset}`);
    console.log(`${colors.bold}${colors.green}════════════════════════════════════════════════════════${colors.reset}`);
  } else {
    console.log('');
    console.log(`${colors.yellow}No confirmed transactions detected.${colors.reset}`);
  }
  console.log('');
}

async function interactiveMode() {
  console.log(`${colors.bold}${colors.cyan}Balance Tracker - Interactive Mode${colors.reset}`);
  console.log(`${colors.gray}This will take a snapshot, wait for you to run transactions, then compare.${colors.reset}`);
  console.log('');

  // Take initial snapshot
  console.log(`${colors.yellow}Taking initial snapshot...${colors.reset}`);
  const beforeBalances = await getBalances();
  printBalances(beforeBalances, 'BEFORE (Snapshot)');

  console.log('');
  console.log(`${colors.bold}${colors.yellow}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bold}Press ENTER after running your transactions to see the comparison${colors.reset}`);
  console.log(`${colors.yellow}═══════════════════════════════════════════════════════════${colors.reset}`);

  // Wait for user input
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  await new Promise(resolve => {
    rl.question('', () => {
      rl.close();
      resolve();
    });
  });

  // Take final snapshot
  console.log(`${colors.yellow}Taking final snapshot...${colors.reset}`);
  const afterBalances = await getBalances();
  printBalances(afterBalances, 'AFTER');

  // Print comparison
  printComparison(beforeBalances, afterBalances);
}

async function watchMode() {
  console.log(`${colors.bold}${colors.cyan}Balance Tracker - Watch Mode${colors.reset}`);
  console.log(`${colors.gray}Checking every ${WATCH_INTERVAL} seconds. Press Ctrl+C to stop.${colors.reset}`);
  console.log('');

  // Take initial snapshot
  console.log(`${colors.yellow}Taking initial snapshot...${colors.reset}`);
  const initialBalances = await getBalances();
  printBalances(initialBalances, 'INITIAL');

  let previousBalances = initialBalances;

  // Check periodically
  const checkInterval = setInterval(async () => {
    try {
      const currentBalances = await getBalances();

      const targetChanged = !currentBalances.targetBalance.eq(previousBalances.targetBalance);
      const derivedChanged = !currentBalances.totalDerivedBalance.eq(previousBalances.totalDerivedBalance);

      if (targetChanged || derivedChanged) {
        console.log('');
        console.log(`${colors.bold}${colors.green}*** CHANGE DETECTED ***${colors.reset}`);
        printBalances(currentBalances, 'UPDATED');
        printComparison(initialBalances, currentBalances);
        previousBalances = currentBalances;
      } else {
        process.stdout.write(`${colors.gray}[${new Date().toLocaleTimeString()}] No changes...${colors.reset}\r`);
      }
    } catch (error) {
      console.error(`${colors.red}Error checking balances: ${error.message}${colors.reset}`);
    }
  }, WATCH_INTERVAL * 1000);

  // Handle Ctrl+C
  process.on('SIGINT', () => {
    clearInterval(checkInterval);
    console.log('');
    console.log(`${colors.yellow}Watch mode stopped.${colors.reset}`);
    console.log('');
    console.log(`${colors.bold}Final Summary:${colors.reset}`);
    getBalances().then(finalBalances => {
      printComparison(initialBalances, finalBalances);
      process.exit(0);
    });
  });
}

async function simpleMode() {
  // Simple one-time check showing current balances
  const balances = await getBalances();

  const data = JSON.parse(fs.readFileSync(join(__dirname, 'registered_eth_addresses.json'), 'utf8'));
  const usersWithDerived = data.filter(u => u.derivedEthAddress !== null && u.derivedEthAddress !== undefined);

  console.log('');
  console.log(`${colors.bold}Balance Check${colors.reset}`);
  console.log(`${colors.cyan}${usersWithDerived.length} Registered Addresses${colors.reset}`);
  console.log('');
  console.log(`${colors.bold}Derived ETH Address\t\t\t\t\tBalance (TICS)\tNonce${colors.reset}`);

  for (const user of usersWithDerived) {
    const balance = await provider.getBalance(user.derivedEthAddress);
    const nonce = await provider.getTransactionCount(user.derivedEthAddress);
    const balanceFormatted = parseFloat(ethers.utils.formatEther(balance)).toFixed(2);
    console.log(`${user.derivedEthAddress}\t${balanceFormatted}\t\t${nonce}`);
  }

  console.log(`${colors.bold}TOTAL (${balances.derivedCount} addresses)\t\t\t\t\t${formatBalance(balances.totalDerivedBalance)}\t\t${balances.totalNonce}${colors.reset}`);

  console.log('');
  console.log(`${colors.bold}Target Address${colors.reset}`);
  console.log(`${colors.bold}Address\t\t\t\t\t\t\tBalance (TICS)\tNonce${colors.reset}`);
  console.log(`${TARGET_ADDRESS}\t${formatBalance(balances.targetBalance)}\t\t${balances.targetNonce}`);
  console.log('');
}

async function main() {
  if (WATCH_MODE) {
    await watchMode();
  } else if (process.argv.includes('--simple')) {
    await simpleMode();
  } else {
    await interactiveMode();
  }
}

main().catch(console.error);

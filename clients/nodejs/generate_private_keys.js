#!/usr/bin/env node

/**
 * Generate N Random Private Keys
 * 
 * Usage:
 *   node generate_private_keys.js 10
 *   node generate_private_keys.js 20 --output keys.json
 */

import { Wallet } from 'ethers';
import fs from 'fs';
import path from 'path';

// Colors
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function showHelp() {
  log('\n📝 Generate Random Private Keys', 'bright');
  log('\nUsage:', 'yellow');
  log('  node generate_private_keys.js <count> [options]', 'cyan');
  log('\nArguments:', 'yellow');
  log('  count          Number of private keys to generate (required)', 'cyan');
  log('\nOptions:', 'yellow');
  log('  --output FILE  Output JSON file (default: private_keys.json)', 'cyan');
  log('  --help, -h     Show this help message', 'cyan');
  log('\nExamples:', 'yellow');
  log('  node generate_private_keys.js 10', 'cyan');
  log('  node generate_private_keys.js 20 --output test_keys.json', 'cyan');
  log('', 'reset');
}

async function generatePrivateKeys(count, outputFile) {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('🔑 GENERATING RANDOM PRIVATE KEYS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  log(`📝 Generating ${count} random private keys...`, 'magenta');
  log('', 'reset');

  const keys = [];

  for (let i = 0; i < count; i++) {
    const wallet = Wallet.createRandom();
    const privateKey = wallet.privateKey.slice(2); // Remove 0x prefix
    const address = wallet.address;

    keys.push({
      id: i + 1,
      privateKey: privateKey,
      address: address
    });

    log(`[${i + 1}/${count}] ${address}`, 'cyan');
    log(`       Private Key: ${privateKey}`, 'yellow');
  }

  log('', 'reset');
  log(`✅ Generated ${count} private keys`, 'green');
  log('', 'reset');

  // Save to JSON file
  const output = {
    generated: new Date().toISOString(),
    count: count,
    keys: keys
  };

  fs.writeFileSync(outputFile, JSON.stringify(output, null, 2));
  log(`💾 Saved to: ${outputFile}`, 'green');
  log('', 'reset');

  // Show array format for easy copy-paste
  log('📋 Array format (for copy-paste into scripts):', 'blue');
  log('', 'reset');
  const keysArray = keys.map(k => `  "${k.privateKey}",`).join('\n');
  console.log('[');
  console.log(keysArray.slice(0, -1)); // Remove trailing comma
  console.log(']');
  log('', 'reset');

  log('═══════════════════════════════════════════════════════════', 'bright');
  log('✅ COMPLETE', 'green');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');
}

// Parse command line arguments
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  showHelp();
  process.exit(0);
}

if (args.length === 0) {
  log('❌ Error: Please specify the number of keys to generate', 'red');
  log('   Example: node generate_private_keys.js 10', 'yellow');
  log('   Use --help for more information', 'yellow');
  process.exit(1);
}

const count = parseInt(args[0]);
if (isNaN(count) || count <= 0) {
  log('❌ Error: Invalid count. Please provide a positive number', 'red');
  log('   Example: node generate_private_keys.js 10', 'yellow');
  process.exit(1);
}

if (count > 100) {
  log('⚠️  Warning: Generating more than 100 keys. This might take a while...', 'yellow');
}

// Parse output file option
let outputFile = 'private_keys.json';
const outputIndex = args.indexOf('--output');
if (outputIndex !== -1 && args[outputIndex + 1]) {
  outputFile = args[outputIndex + 1];
}

const outputPath = path.join(process.cwd(), outputFile);

// Run
generatePrivateKeys(count, outputPath).catch(error => {
  log(`\n❌ Error: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});


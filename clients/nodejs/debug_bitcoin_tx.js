#!/usr/bin/env node

/**
 * Debug Bitcoin Transaction Format
 * 
 * Analyze the transaction that's failing to broadcast
 */

const tx_hex = "0200000001cacd84cc59c9a7638d21b7c7dc7df9c50da7ea1216718284fe7bec06eecf8f1a000000006a473044022024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c02200abb10e3d42e0f2370f053bd1cbb17328884a163a87e3da5234610aa35b91d8a01210367d1ea081adbd2c3ad29357918f4f000f8b10eb43b7bdad952dc99cb2161e572feffffff01f5010000000000001976a91454dafe2d131c33d9e3f702963f5c1702f9889cbb88ac00000000";

console.log('🔍 Bitcoin Transaction Analysis\n');
console.log(`📄 Transaction Hex: ${tx_hex}`);
console.log(`📏 Transaction Length: ${tx_hex.length / 2} bytes\n`);

// Parse the transaction manually
let offset = 0;

// Version (4 bytes)
const version = parseInt(tx_hex.substr(offset, 8), 16);
console.log(`🔢 Version: ${version}`);
offset += 8;

// Input count (1 byte - assuming varint < 253)
const input_count = parseInt(tx_hex.substr(offset, 2), 16);
console.log(`📥 Input Count: ${input_count}`);
offset += 2;

// Parse first input
console.log('\n📥 INPUT 0:');
// Previous output hash (32 bytes, reversed)
const prev_hash = tx_hex.substr(offset, 64);
console.log(`  🔗 Previous Hash: ${prev_hash}`);
offset += 64;

// Previous output index (4 bytes)
const prev_index = parseInt(tx_hex.substr(offset, 8), 16);
console.log(`  📍 Previous Index: ${prev_index}`);
offset += 8;

// Script length (1 byte)
const script_len = parseInt(tx_hex.substr(offset, 2), 16);
console.log(`  📜 Script Length: ${script_len} bytes`);
offset += 2;

// Script
const script = tx_hex.substr(offset, script_len * 2);
console.log(`  📜 Script: ${script}`);
offset += script_len * 2;

// Sequence (4 bytes)
const sequence = tx_hex.substr(offset, 8);
console.log(`  🔄 Sequence: ${sequence}`);
offset += 8;

// Output count (1 byte)
const output_count = parseInt(tx_hex.substr(offset, 2), 16);
console.log(`\n📤 Output Count: ${output_count}`);
offset += 2;

// Parse first output
console.log('\n📤 OUTPUT 0:');
// Value (8 bytes)
const value_hex = tx_hex.substr(offset, 16);
const value = parseInt(value_hex, 16);
console.log(`  💰 Value: ${value} satoshis`);
offset += 16;

// Script length (1 byte)
const out_script_len = parseInt(tx_hex.substr(offset, 2), 16);
console.log(`  📜 Script Length: ${out_script_len} bytes`);
offset += 2;

// Script
const out_script = tx_hex.substr(offset, out_script_len * 2);
console.log(`  📜 Script: ${out_script}`);
offset += out_script_len * 2;

// Lock time (4 bytes)
const lock_time = tx_hex.substr(offset, 8);
console.log(`\n🔒 Lock Time: ${lock_time}`);
offset += 8;

console.log(`\n🔍 ANALYSIS RESULTS:`);
console.log(`📏 Parsed ${offset / 2} bytes out of ${tx_hex.length / 2} total`);

// Check output script type
if (out_script.startsWith('0014')) {
    console.log(`\n❌ PROBLEM IDENTIFIED:`);
    console.log(`🎯 Output script starts with '0014' - This is a P2WPKH (SegWit) script!`);
    console.log(`📜 P2WPKH format: OP_0 <20-byte-pubkey-hash>`);
    console.log(`🚨 SegWit transactions require witness data, but this transaction has none!`);
    
    console.log(`\n🔧 SOLUTIONS:`);
    console.log(`1. 🏗️  Add witness data section to the transaction`);
    console.log(`2. 🔄 Use P2PKH output format instead of P2WPKH`);
    console.log(`3. 🛠️  Implement proper SegWit transaction construction`);
    
    console.log(`\n📖 SegWit Transaction Format:`);
    console.log(`Version + Marker(00) + Flag(01) + Inputs + Outputs + Witness + LockTime`);
    console.log(`Current transaction is missing: Marker + Flag + Witness sections`);
    
} else if (out_script.startsWith('76a914') && out_script.endsWith('88ac')) {
    console.log(`\n✅ Output script is P2PKH format - should work fine`);
} else {
    console.log(`\n❓ Unknown output script format: ${out_script}`);
}

console.log(`\n💡 RECOMMENDATION:`);
console.log(`The transaction is trying to send to a SegWit address but isn't properly formatted.`);
console.log(`Either fix the output script to use P2PKH or implement proper SegWit support.`);

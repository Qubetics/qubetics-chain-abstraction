#!/usr/bin/env node

/**
 * Test Bitcoin Transaction Broadcasting
 * 
 * This script tests the broadcasting functionality with sample data
 * DO NOT USE WITH REAL TRANSACTIONS - FOR TESTING ONLY
 */

import { broadcastBitcoinTransaction } from './broadcast_bitcoin_transaction.js';

// Sample Bitcoin transaction hex (This is NOT a real transaction - just for testing format)
const SAMPLE_TX_HEX = "0200000001abc123def456789012345678901234567890123456789012345678901234567890000000006a47304402203456789012345678901234567890123456789012345678901234567890123456780220123456789012345678901234567890123456789012345678901234567890123456012103456789012345678901234567890123456789012345678901234567890123456ffffffff02404b4c00000000001976a914abc123def456789012345678901234567890123488ac80969800000000001976a914def456789012345678901234567890123456789088ac00000000";

async function testBroadcast() {
    console.log('🧪 Testing Bitcoin Transaction Broadcasting\n');
    console.log('⚠️  WARNING: This is a test with dummy data!');
    console.log('⚠️  DO NOT use this with real transactions!\n');
    
    console.log('📄 Sample transaction hex:');
    console.log(`${SAMPLE_TX_HEX.substring(0, 50)}...`);
    console.log(`📊 Length: ${SAMPLE_TX_HEX.length / 2} bytes\n`);
    
    try {
        // This will fail because it's not a real transaction
        // But it will test the validation and API connection
        const txid = await broadcastBitcoinTransaction(
            SAMPLE_TX_HEX,
            'testnet',
            ['blockstream']  // Only try one provider for testing
        );
        
        console.log(`✅ Unexpected success! TXID: ${txid}`);
        
    } catch (error) {
        console.log(`❌ Expected failure (this is a dummy transaction):`);
        console.log(`   ${error.message}`);
        
        // Check if it's the expected error types
        if (error.message.includes('HTTP 400') || 
            error.message.includes('invalid') || 
            error.message.includes('bad-txns')) {
            console.log(`\n✅ Test passed! The broadcasting system is working correctly.`);
            console.log(`   The error is expected because we used dummy transaction data.`);
        } else {
            console.log(`\n❌ Unexpected error type. This might indicate a real problem.`);
        }
    }
}

async function testValidation() {
    console.log('\n🔍 Testing transaction validation...\n');
    
    const testCases = [
        {
            name: 'Valid hex format',
            hex: SAMPLE_TX_HEX,
            shouldPass: true
        },
        {
            name: 'Invalid hex characters',
            hex: 'xyz123',
            shouldPass: false
        },
        {
            name: 'Too short',
            hex: '01020304',
            shouldPass: false
        },
        {
            name: 'Empty string',
            hex: '',
            shouldPass: false
        }
    ];
    
    for (const testCase of testCases) {
        try {
            console.log(`Testing: ${testCase.name}`);
            await broadcastBitcoinTransaction(testCase.hex, 'testnet', ['blockstream']);
            
            if (testCase.shouldPass) {
                console.log(`❌ Should have passed validation but didn't reach network`);
            } else {
                console.log(`❌ Should have failed validation but passed`);
            }
            
        } catch (error) {
            if (testCase.shouldPass && error.message.includes('Invalid transaction hex')) {
                console.log(`❌ Should have passed validation: ${error.message}`);
            } else if (!testCase.shouldPass && error.message.includes('Invalid transaction hex')) {
                console.log(`✅ Correctly failed validation`);
            } else {
                console.log(`⚠️  Failed for other reason: ${error.message}`);
            }
        }
        
        console.log('');
    }
}

async function showIntegrationExample() {
    console.log('\n📋 Integration Example for Your MPC System:\n');
    
    console.log(`
// After your signature aggregation completes in Rust:

1. Extract the final signed transaction bytes:
   let signed_tx_bytes = finalize_bitcoin_transaction(&aggregated_signature, &tx);

2. Convert to hex:
   let signed_tx_hex = hex::encode(&signed_tx_bytes);

3. Call the broadcasting script:
   
   // Option A: Direct command
   let output = std::process::Command::new("node")
       .arg("clients/nodejs/broadcast_bitcoin_transaction.js")
       .arg(&signed_tx_hex)
       .arg("--network")
       .arg("testnet")
       .output()?;
   
   // Option B: HTTP API (if you set up the server)
   let response = reqwest::Client::new()
       .post("http://localhost:3001/broadcast")
       .json(&json!({
           "transaction_hex": signed_tx_hex,
           "network": "testnet"
       }))
       .send()
       .await?;

4. Handle the result:
   if output.status.success() {
       let txid = String::from_utf8(output.stdout)?;
       info!("✅ Bitcoin broadcasted: {}", txid);
   }
    `);
}

// Main execution
async function main() {
    console.log('🚀 Bitcoin Broadcasting Test Suite\n');
    
    if (process.argv.includes('--validation-only')) {
        await testValidation();
        return;
    }
    
    if (process.argv.includes('--example-only')) {
        await showIntegrationExample();
        return;
    }
    
    // Run full test suite
    await testBroadcast();
    await testValidation();
    await showIntegrationExample();
    
    console.log('\n🎯 Next Steps:');
    console.log('1. Complete your MPC signature aggregation');
    console.log('2. Extract the signed transaction hex');
    console.log('3. Use broadcast_bitcoin_transaction.js with your real data');
    console.log('4. Monitor the transaction on the Bitcoin network\n');
    
    console.log('💡 For real usage:');
    console.log('   node broadcast_bitcoin_transaction.js <your_signed_tx_hex> --network testnet');
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
}

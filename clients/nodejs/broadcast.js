/**
 * Qubetics Transaction Broadcast Script
 * Simple script to broadcast raw transactions to Qubetics testnet
 */

const RPC_URL = "https://rpc-testnet.qubetics.work";

/**
 * Broadcast raw transaction
 */
async function broadcastTransaction(rawTx) {
    try {
        // Validate raw transaction format
        if (!rawTx.startsWith('0x') || !/^0x[0-9a-fA-F]+$/.test(rawTx)) {
            throw new Error('Invalid raw transaction format');
        }

        console.log(`Broadcasting transaction: ${rawTx.slice(0, 20)}...`);

        const payload = {
            jsonrpc: "2.0",
            method: "eth_sendRawTransaction",
            params: [rawTx],
            id: 1
        };

        const response = await fetch(RPC_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (result.error) {
            throw new Error(`RPC Error: ${result.error.message}`);
        }

        const txHash = result.result;
        console.log(`✅ Transaction broadcast successful!`);
        console.log(`Transaction Hash: ${txHash}`);
        console.log(`Explorer URL: https://explorer-testnet.qubetics.work/tx/${txHash}`);
        
        return txHash;

    } catch (error) {
        console.error(`❌ Broadcast failed: ${error.message}`);
        throw error;
    }
}

/**
 * Check transaction status
 */
async function checkTransaction(txHash) {
    try {
        if (!txHash.startsWith('0x') || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
            throw new Error('Invalid transaction hash format');
        }

        const payload = {
            jsonrpc: "2.0",
            method: "eth_getTransactionByHash",
            params: [txHash],
            id: 1
        };

        const response = await fetch(RPC_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        
        if (result.error) {
            throw new Error(`RPC Error: ${result.error.message}`);
        }

        return result.result;

    } catch (error) {
        console.error(`❌ Check transaction failed: ${error.message}`);
        return null;
    }
}

/**
 * Get transaction receipt
 */
async function getReceipt(txHash) {
    try {
        const payload = {
            jsonrpc: "2.0",
            method: "eth_getTransactionReceipt",
            params: [txHash],
            id: 1
        };

        const response = await fetch(RPC_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        
        if (result.error) {
            throw new Error(`RPC Error: ${result.error.message}`);
        }

        return result.result;

    } catch (error) {
        console.error(`❌ Get receipt failed: ${error.message}`);
        return null;
    }
}

// Usage examples:
// Example 1: Broadcast a raw transaction
async function example1() {
    const rawTx = "0xf9042c80843b9aca00830493e094d74682aec7e962351e7ea6655282fbda5c14e9aa80b903c48545e4dc0000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000002540be400000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000360000000000000000000000000000000000000000000000000000000000000002a30783765663131383835313834326332633065313566366263323038373738613234333837376635633600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a307863366441353362436139303735333639396364313935323144643535393936343439304336383232000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008717562657469637300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000087175626574696373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000454494353000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004544943530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000423078346361363861356138653438393235303439666464303235346363636665323064366439363031386134653339656435666463366436643466353062353066310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040396137363662626631313338656338353163633831323438353965653666303362373561306265326663333738303938363865353736313836613438366364348246ada024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca05d910ed3ad1cc15cbbb979c60de9531a2b8395e352b3c183810a87e10465e122";
    
    try {
        const txHash = await broadcastTransaction(rawTx);
        
        // Wait a bit then check status
        setTimeout(async () => {
            const tx = await checkTransaction(txHash);
            console.log('Transaction status:', tx ? 'Found' : 'Pending');
            
            const receipt = await getReceipt(txHash);
            if (receipt) {
                console.log('Transaction confirmed! Status:', receipt.status === '0x1' ? 'Success' : 'Failed');
            }
        }, 5000);
        
    } catch (error) {
        console.error('Example failed:', error.message);
    }
}

example1();

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        broadcastTransaction,
        checkTransaction,
        getReceipt
    };
}

// For browser usage, attach to window
if (typeof window !== 'undefined') {
    window.QubeticsRPC = {
        broadcastTransaction,
        checkTransaction,
        getReceipt
    };
}

console.log('Qubetics RPC functions loaded. Use broadcastTransaction(rawTx) to broadcast.');
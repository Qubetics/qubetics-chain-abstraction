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
    const rawTx = "0xf86a03843b9aca00830493e09457934fb5932fec454599f9aaccc559d2715a9d06843b9aca00808246aea024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca06ff29179213dca442fc518ede88d21812695458b0134200ef51754062ca364a0";
    
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
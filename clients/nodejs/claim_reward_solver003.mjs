import http from 'http';
import secp256k1 from 'secp256k1';
import keccak from 'keccak';

// Configuration - use local RPC endpoint
const RPC_BASE_URL = 'http://127.0.0.1:8082';
const CLAIM_REWARD_ENDPOINT = RPC_BASE_URL + '/claim_reward';
const API_KEY = '2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45';

// SOLVER_003 private key
const TEST_PRIVATE_KEY = process.env.TEST_PRIVATE_KEY;
// SOLVER_003 BTC address
const SOLVER_BTC_ADDRESS = 'tb1qy2hqhhnv645vrfkusy5jga8pppytq3dw6awdn8';

function getEthereumAddress(privateKeyHex) {
    const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const privateKeyBuffer = Buffer.from(privateKey, 'hex');
    const publicKey = secp256k1.publicKeyCreate(privateKeyBuffer, false);
    const publicKeyWithoutPrefix = Buffer.from(publicKey.slice(1));
    const hash = keccak('keccak256').update(publicKeyWithoutPrefix).digest();
    return '0x' + hash.slice(-20).toString('hex');
}

function createSignature(message, privateKeyHex) {
    const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const privateKeyBuffer = Buffer.from(privateKey, 'hex');
    const prefix = '\x19Ethereum Signed Message:\n' + message.length;
    const prefixedMessage = prefix + message;
    const messageHash = keccak('keccak256').update(Buffer.from(prefixedMessage, 'utf8')).digest();
    const signature = secp256k1.ecdsaSign(messageHash, privateKeyBuffer);
    const v = 27 + signature.recid;
    const r = signature.signature.slice(0, 32);
    const s = signature.signature.slice(32, 64);
    const vBuffer = Buffer.from([v]);
    const fullSignature = Buffer.concat([r, s, vBuffer]);
    return '0x' + fullSignature.toString('hex');
}

function makeRequest(url, data) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                'X-API-KEY': API_KEY
            }
        };
        const req = http.request(options, (res) => {
            let responseData = '';
            res.on('data', (chunk) => { responseData += chunk; });
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(responseData) });
                } catch (e) {
                    resolve({ status: res.statusCode, data: responseData });
                }
            });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

async function main() {
    const ethAddress = getEthereumAddress(TEST_PRIVATE_KEY);
    console.log('SOLVER_003 ETH Address:', ethAddress);
    console.log('SOLVER_003 BTC Address:', SOLVER_BTC_ADDRESS);
    
    // Claim both TICS and BTC rewards
    console.log('\n--- Claiming Rewards (TICS + BTC) ---');
    const message = 'hello';
    const signature = createSignature(message, TEST_PRIVATE_KEY);
    
    const payload = {
        signature: signature,
        message: message,
        ethereum_address: ethAddress,
        btc_address: SOLVER_BTC_ADDRESS
    };
    
    console.log('Endpoint:', CLAIM_REWARD_ENDPOINT);
    console.log('Payload:', JSON.stringify(payload, null, 2));
    
    const response = await makeRequest(CLAIM_REWARD_ENDPOINT, JSON.stringify(payload));
    console.log('\nResponse Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
}

main().catch(console.error);

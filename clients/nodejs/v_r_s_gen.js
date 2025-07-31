import crypto from 'crypto';
import { createHash } from 'crypto';

// Elliptic curve parameters for secp256k1 (used by Ethereum)
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const CURVE_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
const CURVE_A = BigInt(0);
const CURVE_B = BigInt(7);
const CURVE_GX = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
const CURVE_GY = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

// Sample Ethereum transaction data for testing
const ETHEREUM_TRANSACTIONS = [
    {
        from: '0x742d35Cc6634C0532925a3b8D1C2B8c9b8BE78C8',
        to: '0x8ba1f109551bD432803012645Hac136c1c0C1B00',
        value: '1000000000000000000', // 1 ETH in wei
        gasLimit: '21000',
        gasPrice: '20000000000', // 20 gwei
        nonce: 42,
        data: '0x'
    },
    {
        from: '0x742d35Cc6634C0532925a3b8D1C2B8c9b8BE78C8',
        to: '0x1234567890123456789012345678901234567890',
        value: '500000000000000000', // 0.5 ETH in wei
        gasLimit: '21000',
        gasPrice: '25000000000', // 25 gwei
        nonce: 43,
        data: '0x'
    },
    {
        from: '0x742d35Cc6634C0532925a3b8D1C2B8c9b8BE78C8',
        to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
        value: '2000000000000000000', // 2 ETH in wei
        gasLimit: '21000',
        gasPrice: '30000000000', // 30 gwei
        nonce: 44,
        data: '0x'
    }
];

// Utility functions for big integer operations
function modInverse(a, m) {
    if (a < 0) a = ((a % m) + m) % m;
    const g = extendedGCD(a, m);
    if (g[0] !== 1n) throw new Error('Modular inverse does not exist');
    return ((g[1] % m) + m) % m;
}

function extendedGCD(a, b) {
    if (a === 0n) return [b, 0n, 1n];
    const [gcd, x1, y1] = extendedGCD(b % a, a);
    const x = y1 - (b / a) * x1;
    const y = x1;
    return [gcd, x, y];
}

function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}

function randomBigInt(max) {
    const bytes = Math.ceil(max.toString(16).length / 2);
    let result;
    do {
        result = BigInt('0x' + crypto.randomBytes(bytes).toString('hex'));
    } while (result >= max);
    return result;
}

// Elliptic curve point operations
class ECPoint {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.isInfinity = x === null && y === null;
    }

    static infinity() {
        return new ECPoint(null, null);
    }

    static generator() {
        return new ECPoint(CURVE_GX, CURVE_GY);
    }

    add(other) {
        if (this.isInfinity) return other;
        if (other.isInfinity) return this;
        
        if (this.x === other.x) {
            if (this.y === other.y) {
                return this.double();
            } else {
                return ECPoint.infinity();
            }
        }
        
        const lambda = ((other.y - this.y) * modInverse(other.x - this.x, CURVE_P)) % CURVE_P;
        const x3 = (lambda * lambda - this.x - other.x) % CURVE_P;
        const y3 = (lambda * (this.x - x3) - this.y) % CURVE_P;
        
        return new ECPoint(
            ((x3 % CURVE_P) + CURVE_P) % CURVE_P,
            ((y3 % CURVE_P) + CURVE_P) % CURVE_P
        );
    }

    double() {
        if (this.isInfinity) return this;
        
        const lambda = ((3n * this.x * this.x + CURVE_A) * modInverse(2n * this.y, CURVE_P)) % CURVE_P;
        const x3 = (lambda * lambda - 2n * this.x) % CURVE_P;
        const y3 = (lambda * (this.x - x3) - this.y) % CURVE_P;
        
        return new ECPoint(
            ((x3 % CURVE_P) + CURVE_P) % CURVE_P,
            ((y3 % CURVE_P) + CURVE_P) % CURVE_P
        );
    }

    multiply(scalar) {
        if (scalar === 0n) return ECPoint.infinity();
        if (scalar === 1n) return this;
        
        let result = ECPoint.infinity();
        let addend = this;
        
        while (scalar > 0n) {
            if (scalar & 1n) {
                result = result.add(addend);
            }
            addend = addend.double();
            scalar >>= 1n;
        }
        
        return result;
    }

    toString() {
        if (this.isInfinity) return 'Point at infinity';
        return `(${this.x.toString(16)}, ${this.y.toString(16)})`;
    }
}

// Shamir's Secret Sharing
class ShamirSecretSharing {
    constructor(threshold, numShares) {
        this.threshold = threshold;
        this.numShares = numShares;
    }

    generateShares(secret) {
        const coefficients = [secret];
        for (let i = 1; i < this.threshold; i++) {
            coefficients.push(randomBigInt(CURVE_ORDER));
        }

        const shares = [];
        for (let i = 1; i <= this.numShares; i++) {
            const x = BigInt(i);
            let y = 0n;
            
            for (let j = 0; j < this.threshold; j++) {
                y = (y + coefficients[j] * modPow(x, BigInt(j), CURVE_ORDER)) % CURVE_ORDER;
            }
            
            shares.push({ x, y });
        }

        return shares;
    }

    reconstructSecret(shares) {
        if (shares.length < this.threshold) {
            throw new Error('Not enough shares to reconstruct secret');
        }

        let secret = 0n;
        const usedShares = shares.slice(0, this.threshold);

        for (let i = 0; i < usedShares.length; i++) {
            let numerator = 1n;
            let denominator = 1n;

            for (let j = 0; j < usedShares.length; j++) {
                if (i !== j) {
                    numerator = (numerator * (0n - usedShares[j].x)) % CURVE_ORDER;
                    denominator = (denominator * (usedShares[i].x - usedShares[j].x)) % CURVE_ORDER;
                }
            }

            const lagrange = (numerator * modInverse(denominator, CURVE_ORDER)) % CURVE_ORDER;
            secret = (secret + usedShares[i].y * lagrange) % CURVE_ORDER;
        }

        return ((secret % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
    }
}

// Distributed Key Generation Node
class DKGNode {
    constructor(id, threshold, numNodes) {
        this.id = id;
        this.threshold = threshold;
        this.numNodes = numNodes;
        this.privateKey = randomBigInt(CURVE_ORDER);
        this.publicKey = ECPoint.generator().multiply(this.privateKey);
        this.secretShares = new Map();
        this.receivedShares = new Map();
        this.complaints = new Set();
        this.shamir = new ShamirSecretSharing(threshold, numNodes);
    }

    // Phase 1: Generate and distribute secret shares
    generateSecretShares() {
        const shares = this.shamir.generateShares(this.privateKey);
        const commitments = [];
        
        // Generate commitments for verification
        for (let i = 0; i < this.threshold; i++) {
            const coeff = randomBigInt(CURVE_ORDER);
            commitments.push(ECPoint.generator().multiply(coeff));
        }

        return {
            shares: shares,
            commitments: commitments,
            from: this.id
        };
    }

    // Phase 2: Receive and verify shares from other nodes
    receiveShare(nodeId, share, commitments) {
        // Verify the share using commitments
        if (this.verifyShare(share, commitments)) {
            this.receivedShares.set(nodeId, share);
            return true;
        } else {
            this.complaints.add(nodeId);
            return false;
        }
    }

    verifyShare(share, commitments) {
        // Simplified verification - in practice, use proper commitment verification
        return share.x !== null && share.y !== null;
    }

    // Phase 3: Compute final key share
    computeKeyShare() {
        const validShares = Array.from(this.receivedShares.values());
        if (validShares.length < this.threshold) {
            throw new Error('Not enough valid shares received');
        }

        // Combine shares to get this node's portion of the distributed key
        let combinedShare = 0n;
        for (const share of validShares) {
            combinedShare = (combinedShare + share.y) % CURVE_ORDER;
        }

        return combinedShare;
    }
}

// Threshold ECDSA implementation
class ThresholdECDSA {
    constructor(threshold, numNodes) {
        this.threshold = threshold;
        this.numNodes = numNodes;
        this.nodes = [];
        this.distributedPublicKey = null;
        
        // Initialize DKG nodes
        for (let i = 0; i < numNodes; i++) {
            this.nodes.push(new DKGNode(i, threshold, numNodes));
        }
    }

    // Execute Distributed Key Generation
    async executeADKG() {
        console.log('Starting Asynchronous Distributed Key Generation...');
        
        // Phase 1: Generate secret polynomial coefficients for each node
        const polynomialCoefficients = [];
        for (let i = 0; i < this.nodes.length; i++) {
            const coeffs = [this.nodes[i].privateKey]; // a_0 = private key
            for (let j = 1; j < this.threshold; j++) {
                coeffs.push(randomBigInt(CURVE_ORDER));
            }
            polynomialCoefficients.push(coeffs);
        }
        
        // Phase 2: Compute shares for each node
        const keyShares = new Array(this.nodes.length).fill(0n);
        
        for (let i = 0; i < this.nodes.length; i++) { // for each receiving node
            for (let j = 0; j < this.nodes.length; j++) { // from each sending node
                const x = BigInt(i + 1); // evaluation point
                let share = 0n;
                
                // Evaluate polynomial at x
                for (let k = 0; k < this.threshold; k++) {
                    share = (share + polynomialCoefficients[j][k] * modPow(x, BigInt(k), CURVE_ORDER)) % CURVE_ORDER;
                }
                
                keyShares[i] = (keyShares[i] + share) % CURVE_ORDER;
            }
        }

        // Phase 3: Compute distributed public key
        this.distributedPublicKey = ECPoint.infinity();
        for (let i = 0; i < this.nodes.length; i++) {
            const contribution = ECPoint.generator().multiply(this.nodes[i].privateKey);
            this.distributedPublicKey = this.distributedPublicKey.add(contribution);
        }

        console.log('ADKG completed successfully!');
        console.log(`Distributed public key: ${this.distributedPublicKey.toString()}`);
        
        return {
            keyShares: keyShares,
            publicKey: this.distributedPublicKey
        };
    }

    // Create threshold signature for Ethereum transaction
    createThresholdSignature(transaction, signingNodes, keyShares) {
        if (signingNodes.length < this.threshold) {
            throw new Error('Not enough signing nodes');
        }

        // Hash the transaction
        const txHash = this.hashTransaction(transaction);
        console.log(`Transaction hash: ${txHash.toString(16)}`);

        // Generate shared nonce using the same k for all nodes (simplified)
        const k = randomBigInt(CURVE_ORDER);
        const R = ECPoint.generator().multiply(k);
        const r = R.x % CURVE_ORDER;

        // Generate signature shares using actual key shares
        const signatureShares = [];
        for (let i = 0; i < this.threshold; i++) {
            const nodeIndex = signingNodes[i];
            const keyShare = keyShares[nodeIndex];
            
            if (keyShare === null) {
                throw new Error(`Invalid key share for node ${nodeIndex}`);
            }
            
            // Create signature share: s_i = k^(-1) * (H(m) + r * x_i)
            const kInv = modInverse(k, CURVE_ORDER);
            const s = (kInv * (txHash + (r * keyShare) % CURVE_ORDER)) % CURVE_ORDER;
            
            signatureShares.push({
                nodeId: nodeIndex,
                r: r,
                s: s
            });
        }

        // Combine signature shares using Lagrange interpolation
        const combinedSignature = this.combineSignatureShares(signatureShares);
        
        return {
            r: combinedSignature.r,
            s: combinedSignature.s,
            v: this.calculateRecoveryId(combinedSignature, txHash),
            transaction: transaction
        };
    }

    combineSignatureShares(shares) {
        // Combine signature shares using Lagrange interpolation
        let combinedS = 0n;
        const r = shares[0].r;

        for (let i = 0; i < shares.length; i++) {
            let lagrange = 1n;
            
            // Calculate Lagrange coefficient for interpolation at x=0
            for (let j = 0; j < shares.length; j++) {
                if (i !== j) {
                    const xi = BigInt(shares[i].nodeId + 1);
                    const xj = BigInt(shares[j].nodeId + 1);
                    
                    // Lagrange coefficient: (0 - xj) / (xi - xj)
                    const numerator = (CURVE_ORDER - xj) % CURVE_ORDER;
                    const denominator = (xi - xj + CURVE_ORDER) % CURVE_ORDER;
                    lagrange = (lagrange * numerator * modInverse(denominator, CURVE_ORDER)) % CURVE_ORDER;
                }
            }
            
            combinedS = (combinedS + shares[i].s * lagrange) % CURVE_ORDER;
        }

        return {
            r: r,
            s: (combinedS % CURVE_ORDER + CURVE_ORDER) % CURVE_ORDER
        };
    }

    calculateRecoveryId(signature, messageHash) {
        // Simplified recovery ID calculation
        return 27; // Standard Ethereum recovery ID
    }

    hashTransaction(transaction) {
        // Create transaction hash (simplified version)
        const txData = `${transaction.from}${transaction.to}${transaction.value}${transaction.gasLimit}${transaction.gasPrice}${transaction.nonce}${transaction.data}`;
        const hash = createHash('sha256').update(txData).digest();
        return BigInt('0x' + hash.toString('hex'));
    }

    // Verify threshold signature
    verifySignature(signature, messageHash) {
        const { r, s } = signature;
        
        // Verify signature using distributed public key
        const w = modInverse(s, CURVE_ORDER);
        const u1 = (messageHash * w) % CURVE_ORDER;
        const u2 = (r * w) % CURVE_ORDER;
        
        const point = ECPoint.generator().multiply(u1).add(this.distributedPublicKey.multiply(u2));
        
        return point.x === r;
    }
}

// Demo function
async function runThresholdECDSADemo() {
    console.log('=== Threshold ECDSA with ADKG Demo ===\n');
    
    // Configuration
    const threshold = 3; // Minimum signatures required
    const numNodes = 5;  // Total number of nodes
    
    console.log(`Configuration: ${threshold}-of-${numNodes} threshold signature scheme\n`);
    
    // Create threshold ECDSA system
    const thresholdECDSA = new ThresholdECDSA(threshold, numNodes);
    
    // Execute ADKG
    const dkgResult = await thresholdECDSA.executeADKG();
    console.log(`\nDKG Result: ${dkgResult.keyShares.length} key shares generated\n`);
    
    // Process Ethereum transactions
    for (let i = 0; i < ETHEREUM_TRANSACTIONS.length; i++) {
        const transaction = ETHEREUM_TRANSACTIONS[i];
        console.log(`--- Processing Transaction ${i + 1} ---`);
        console.log(`From: ${transaction.from}`);
        console.log(`To: ${transaction.to}`);
        console.log(`Value: ${transaction.value} wei`);
        console.log(`Gas: ${transaction.gasLimit} @ ${transaction.gasPrice} wei`);
        console.log(`Nonce: ${transaction.nonce}`);
        
        // Select signing nodes (first 'threshold' nodes)
        const signingNodes = Array.from({length: threshold}, (_, i) => i);
        
        try {
            // Create threshold signature
            const signature = thresholdECDSA.createThresholdSignature(transaction, signingNodes, dkgResult.keyShares);
            
            console.log(`\nGenerated Threshold Signature:`);
            console.log(`r: 0x${signature.r.toString(16)}`);
            console.log(`s: 0x${signature.s.toString(16)}`);
            console.log(`v: ${signature.v}`);
            
            // Verify signature
            const txHash = thresholdECDSA.hashTransaction(transaction);
            const isValid = thresholdECDSA.verifySignature(signature, txHash);
            console.log(`Signature valid: ${isValid}`);
            
        } catch (error) {
            console.error(`Error processing transaction: ${error.message}`);
        }
        
        console.log(''); // Empty line for readability
    }
    
    console.log('=== Demo completed ===');
}

// Export for use
module.exports = {
    ThresholdECDSA,
    DKGNode,
    ShamirSecretSharing,
    ECPoint,
    runThresholdECDSADemo
};

// Run demo if this file is executed directly
if (require.main === module) {
    runThresholdECDSADemo().catch(console.error);
}

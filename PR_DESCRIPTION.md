# feat: Solver Reward Claim System

## Overview

This PR implements a complete reward claim system that allows solvers to claim their accumulated rewards (BTC and TICS tokens) through an independent MPC-based transaction flow separate from the existing intent processing pipeline.

## Key Features

### 1. **RPC Endpoint for Reward Claims**
- New `/claim_reward` HTTP endpoint allows solvers to claim their rewards
- Signature-based authentication using EIP-191 personal sign
- Supports claiming both BTC and TICS (Ethereum) rewards
- Flexible destination addresses for each reward type

### 2. **Independent MPC Transaction Flow**
Unlike intent-based transactions, reward claims implement a **dedicated MPC signing flow**:

**Intent Flow:**
- User deposits → Network processes → Vault payments → Target chain execution

**Reward Claim Flow:**
- Solver signs claim message → RPC validates signature → Fetches stored rewards 
- Broadcasts claim to network → Each node creates transactions independently
- Uses MPC to sign and send rewards from network addresses to solver destinations

### 3. **Network Protocol Changes**

#### New Topics
- Added `"claim-rewards"` topic to gossipsub for peer coordination

#### Message Types
- `ChannelMessage::ClaimReward` - Triggers local reward processing
- `GossipsubMessage::ClaimReward` - Broadcasts claim across P2P network

### 4. **MPC Transaction Processing**

The reward claim flow creates and signs transactions independently:

**For TICS (Ethereum) Rewards:**
- Derives network Ethereum address from DKG group public key
- Creates Ethereum transaction (from network → solver destination)
- Signs using MPC with DKG secret shares
- Processes via `sign_message()` with solver_address tracking

**For BTC Rewards:**
- Derives network Bitcoin address from DKG group public key
- Creates Bitcoin transaction (from network → solver destination)
- Signs using `sign_bitcoin_transaction()` with MPC
- Uses Bitcoin-specific chain handler and transaction format

### 5. **Security & Validation**

- **Signature Recovery**: Verifies solver identity via ECDSA signature recovery
- **Address Validation**: Checks destination addresses are valid Ethereum/Bitcoin formats
- **Reward Verification**: Fetches stored rewards from database, validates amounts
- **Solver Authentication**: Only registered solvers with accumulated rewards can claim

## Technical Implementation

### New Components

1. **RPC Handler** (`src/rpc_server/mod.rs`)
   - `handle_claim_reward()` - Processes HTTP claim requests
   - Recovers signer address from Ethereum signature
   - Validates rewards and broadcasts to network

2. **Network Handler** (`src/network/mod.rs`)
   - `ChannelMessage::ClaimReward` - Local reward processing trigger
   - `GossipsubMessage::ClaimReward` - Distributed claim broadcasting
   - Independent transaction creation and MPC signing

3. **Client Test Suite** (`clients/nodejs/test_claim_reward.cjs`)
   - Complete test harness for reward claims
   - Signature generation and validation
   - Address derivation verification

## Bug Fixes Included

1. **Signature Recovery**: Fixed address derivation in test scripts (Uint8Array to Buffer conversion)
2. **Address Lookup**: Corrected signer address lookup to use recovered address consistently
3. **Topic Subscription**: Added "claim-rewards" to default topic subscriptions
4. **Error Handling**: Improved error messages and validation

## API Usage

### Request
```json
POST /claim_reward
{
  "signature": "0x...",
  "message": "Claim reward for Ethereum: 0x...",
  "ethereum_address": "0x...",
  "btc_address": null
}
```

### Response
```json
{
  "status": "success",
  "ethereum_address": "0x...",
  "btc_address": null,
  "reward_btc": null,
  "reward_tics": "2600000000000000000",
  "total_reward": "2600000000000000000",
  "message": "Reward claim processed successfully"
}
```

## Benefits

1. **Decoupled Processing**: Reward claims don't interfere with intent processing
2. **Distributed**: Each node independently processes claims via P2P broadcast
3. **Secure**: MPC signing ensures no single point of failure
4. **Flexible**: Supports multiple reward types and destination addresses
5. **Efficient**: Direct network-to-solver payments without intermediate steps

## Testing

Run the test suite:
```bash
node clients/nodejs/test_claim_reward.cjs
```

## Migration Notes

- Requires network restart to subscribe to new "claim-rewards" topic
- Existing stored rewards are automatically available for claim
- No database migration required



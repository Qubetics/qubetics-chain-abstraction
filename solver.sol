// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

interface ITreasuryVault {
function batchTransfer(
address[] memory recipients,
uint256[] memory amounts
) external;
}

contract SolverManager is Initializable, AccessControlUpgradeable, UUPSUpgradeable, EIP712Upgradeable {
bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
bytes32 public constant MPC_ROLE = keccak256("MPC_ROLE");
bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
bytes32 public constant INTENT_MANAGER_ROLE = keccak256("INTENT_MANAGER_ROLE");

// Required chains for solver activation
uint256 public constant REQUIRED_CHAIN_BTC = 0;
uint256 public constant REQUIRED_CHAIN_TICS = 9029;

// EIP-712 Type Hash for Solver Onboarding
bytes32 public constant ONBOARD_SOLVER_TYPEHASH = keccak256(
"OnboardSolver(string solverId,string solverName,uint256[] chainIds,string[] solverAddresses,uint256 nonce,uint256 deadline)"
);

bytes32 public constant VALIDATE_SOLVER_TYPEHASH = keccak256(
"ValidateSolver(string solverId,uint256 nonce,uint256 deadline)"
);

enum ChainType {
BTC,
TICS
}

struct Solver {
string solverId;
string solverName;
uint256[] chainIds;
string[] solverAddresses;
bool isActive;
bool isOnboarded;
uint256 onboardedAt;
uint256 offboardedAt;
}

struct LiquidityDeposit {
uint256 amount;
uint256 chainId;
uint256 timestamp;
bool isDeposit;
}

struct RemoveLiquidity {
string solverId;
uint256 amount;
ChainType chainType;
string transactionHash;
}

struct RewardClaim {
address solver;
uint256 amount;
ChainType chainType;
}

struct AddLiquidityBatch {
string solverId;
uint256 amount;
ChainType chainType;
string txId;
}

struct SolverUnclaimedRewards {
string solverId;
uint256 btcUnclaimed;
uint256 ticsUnclaimed;
}

// Storage variables
mapping(string => Solver) private solvers;
mapping(string => bool) private solverExists;
mapping(address => bool) private solverOnboarded;
mapping(string => string) private addressToSolverId;
mapping(string => uint256) private solverTotalAmounts;
mapping(string => mapping(uint256 => uint256)) private solverChainAmounts;
mapping(string => bool) private authorizedAddresses;
mapping(string => address) private solverEvmAddress;
mapping(address => string) private solverAccount;
// EIP-712 nonces for replay protection
mapping(address => uint256) private nonces;
// Counter for auto-generated solver IDs
uint256 private solverIdCounter;
// Mapping to track if solver address has validated their ID
mapping(address => bool) private solverIdValidated;
// solverId => chainId => claimed reward amount
mapping(string => mapping(uint256 => uint256)) private solverClaimedRewards;
mapping(string => mapping(uint256 => uint256)) private solverRewards;

// Reward percentage constants
uint256 public constant VALIDATED_REWARD_PERCENTAGE = 100; // 100% for validated solvers
uint256 public constant NON_VALIDATED_REWARD_PERCENTAGE = 75; // 75% for non-validated solvers
uint256 public constant PERCENTAGE_DIVISOR = 100;
uint256 public solverFeePercentage;

// Minimum liquidity thresholds for required chains (stored but not enforced yet)
uint256 private minLiquidityBTC;
uint256 private minLiquidityTICS;
string[] private activeSolverIds;
uint256 private totalActiveSolvers;
// Treasury Vault address
address public treasuryVault;
address public validatorAddress;
// Reserve storage slots for future upgrades
uint256[40] private __gap;
// Events
event SolverOnboarded(
string solverId,
string solverName,
uint256[] chainIds,
string[] solverAddresses,
uint256 timestamp
);

event SolverActivated(
string solverId,
uint256 timestamp
);
event SolverDeactivated(
string solverId,
string reason,
uint256 timestamp
);
event LiquidityAdded(
string solverId,
uint256 chainId,
uint256 amount,
uint256 timestamp,
string txId
);
event LiquidityRemoved(
string solverId,
uint256 chainId,
uint256 amount,
uint256 timestamp,
string transactionHash
);

event SolverFeeUpdated(
uint256 oldFee,
uint256 newFee,
uint256 timestamp
);

event ContractUpgraded(address indexed newImplementation, uint256 timestamp);

event MinimumLiquidityUpdated(
uint256 chainId,
uint256 oldMinimum,
uint256 newMinimum,
uint256 timestamp
);

event SolverIdInvalidated(string solverId, address solverAddress, uint256 timestamp);


// Custom errors
error SolverAlreadyExists(string solverId);
error SolverNotFound(string solverId);
error SolverNotActive(string solverId);
error SolverNotOnboarded(string solverId);
error InvalidSolverAddress();
error InsufficientBalance();
error UnauthorizedSolver();
error InvalidAmount();
error EmptyString();
error EmptyAddressList();
error EmptyChainIdsList();
error EmptyAmountsList();
error ArrayLengthMismatch();
error AddressAlreadyAssigned(string addr);
error UnauthorizedCaller();
error InvalidSignature();
error SignatureExpired();
error InvalidNonce();
error SolverIdAlreadyValidated();
error SolverIdNotMatching();
error NoLiquidityOnTargetChain();
error SolverNotValidated(string solverId);

/**
* @dev Initializer function (replaces constructor for upgradeable contracts)
*/
function initialize(address _admin, address _treasuryVault, address _validator, address _intentmanager) external initializer {
__AccessControl_init();
__UUPSUpgradeable_init();
__EIP712_init("SolverManager", "1");
_grantRole(DEFAULT_ADMIN_ROLE, _admin);
_grantRole(ADMIN_ROLE, _admin);
_grantRole(UPGRADER_ROLE, _admin);
_grantRole(MPC_ROLE, _admin);
_grantRole(MPC_ROLE, _intentmanager);

// Initialize minimum liquidity thresholds with defaults (can be updated by admin)
minLiquidityBTC = 600; // 600 satoshi
minLiquidityTICS = 10 * 10**18; // 10 TICS (with 18 decimals)
// Initialize solver ID counter
solverIdCounter = 1;
treasuryVault = _treasuryVault;
validatorAddress = _validator;
}

/**
* @dev Required by UUPSUpgradeable - only UPGRADER_ROLE can authorize upgrades
*/
function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {
emit ContractUpgraded(newImplementation, block.timestamp);
}

// Modifiers
modifier onlyOnboardedSolver(string memory solverId) {
if (!solverExists[solverId]) revert SolverNotFound(solverId);
if (!solvers[solverId].isOnboarded) revert SolverNotOnboarded(solverId);
_;
}

modifier onlyActiveSolver(string memory solverId) {
if (!solverExists[solverId]) revert SolverNotFound(solverId);
if (!solvers[solverId].isActive) revert SolverNotActive(solverId);
_;
}

modifier onlyAuthorizedAddress(string memory solverAddress) {
if (!authorizedAddresses[solverAddress]) revert UnauthorizedCaller();
_;
}


/**
* @dev Check if solver meets required chain liquidity conditions
* NOTE: Currently checks for > 0, NOT against minimum thresholds
* @param solverId Solver's unique identifier
* @return bool True if solver has liquidity on all required chains
*/
function _meetsRequiredChainLiquidity(string memory solverId) internal view returns (bool) {
// Check if solver has minimum required liquidity on BTC (chainId = 0)
if (solverChainAmounts[solverId][REQUIRED_CHAIN_BTC] < minLiquidityBTC) {
return false;
}
// Check if solver has minimum required liquidity on TICS (chainId = 9029)
if (solverChainAmounts[solverId][REQUIRED_CHAIN_TICS] < minLiquidityTICS) {
return false;
}
return true;
}

/**
* @dev Activate solver if requirements are met
* @param solverId Solver's unique identifier
*/
function _activateSolverIfEligible(string memory solverId) internal {
// Only activate if currently inactive and meets requirements
if (!solvers[solverId].isActive && _meetsRequiredChainLiquidity(solverId)) {
solvers[solverId].isActive = true;
activeSolverIds.push(solverId);
totalActiveSolvers++;
emit SolverActivated(solverId, block.timestamp);
}
}

/**
* @dev Deactivate solver if required chain liquidity drops to zero
* @param solverId Solver's unique identifier
* @param reason Reason for deactivation
*/
function _deactivateSolverIfNeeded(string memory solverId, string memory reason) internal {
// Only deactivate if currently active and doesn't meet requirements
if (solvers[solverId].isActive && !_meetsRequiredChainLiquidity(solverId)) {
solvers[solverId].isActive = false;
_removeFromActiveSolvers(solverId);
totalActiveSolvers--;
emit SolverDeactivated(solverId, reason, block.timestamp);
}
}

function _removeFromActiveSolvers(string memory solverId) internal {
for (uint256 i = 0; i < activeSolverIds.length; i++) {
if (keccak256(abi.encodePacked(activeSolverIds[i])) == keccak256(abi.encodePacked(solverId))) {
activeSolverIds[i] = activeSolverIds[activeSolverIds.length - 1];
activeSolverIds.pop();
break;
}
}
}

/**
* @dev Hash array of strings for EIP-712
*/
function _hashStringArray(string[] memory arr) internal pure returns (bytes32) {
bytes32[] memory hashes = new bytes32[](arr.length);
for (uint256 i = 0; i < arr.length; i++) {
hashes[i] = keccak256(bytes(arr[i]));
}
return keccak256(abi.encodePacked(hashes));
}

/**
* @dev Hash array of uint256 for EIP-712
*/
function _hashUint256Array(uint256[] memory arr) internal pure returns (bytes32) {
return keccak256(abi.encodePacked(arr));
}

/**
* @dev Verify EIP-712 signature for solver onboarding
*/
function _verifyOnboardSignature(
address signer,
string memory solverId,
string memory solverName,
uint256[] memory chainIds,
string[] memory solverAddresses,
uint256 nonce,
uint256 deadline,
bytes memory signature
) internal view returns (bool) {
if (block.timestamp > deadline) revert SignatureExpired();
if (nonce != nonces[signer]) revert InvalidNonce();

bytes32 structHash = keccak256(
abi.encode(
ONBOARD_SOLVER_TYPEHASH,
keccak256(bytes(solverId)),
keccak256(bytes(solverName)),
_hashUint256Array(chainIds),
_hashStringArray(solverAddresses),
nonce,
deadline
)
);

bytes32 hash = _hashTypedDataV4(structHash);
address recoveredSigner = _recoverSigner(hash, signature);
return recoveredSigner == signer;
}

function _verifyValidateSolverSignature(
address signer,
string memory solverId,
uint256 nonce,
uint256 deadline,
bytes memory signature
) internal view returns (bool) {
if (block.timestamp > deadline) revert SignatureExpired();
if (nonce != nonces[signer]) revert InvalidNonce();

bytes32 structHash = keccak256(
abi.encode(
VALIDATE_SOLVER_TYPEHASH,
keccak256(bytes(solverId)),
nonce,
deadline
)
);

bytes32 digest = _hashTypedDataV4(structHash);
address recoveredSigner = _recoverSigner(digest, signature);

return recoveredSigner == signer;
}

/**
* @dev Recover signer from signature
*/
function _recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
require(signature.length == 65, "Invalid signature length");

bytes32 r;
bytes32 s;
uint8 v;

assembly {
r := mload(add(signature, 32))
s := mload(add(signature, 64))
v := byte(0, mload(add(signature, 96)))
}

if (v < 27) {
v += 27;
}

require(v == 27 || v == 28, "Invalid signature 'v' value");

return ecrecover(hash, v, r, s);
}

/**
* @dev Onboard a new solver with EIP-712 signature verification
* @param solverId Unique identifier for the solver (will be set to empty string/null internally)
* @param solverName Name of the solver
* @param chainIds Array of chain IDs where solver operates
* @param solverAddresses Array of string addresses belonging to the solver
* @param deadline Signature expiration timestamp
* @param signature EIP-712 signature
*/
//same account no more than one solver onboared
function onboardSolver(
string memory solverId,
string memory solverName,
uint256[] memory chainIds,
string[] memory solverAddresses,
uint256 deadline,
bytes memory signature
)
external
{
if (chainIds.length == 0) revert EmptyChainIdsList();
if (solverAddresses.length == 0) revert EmptyAddressList();
require(!solverOnboarded[msg.sender], "solver with this evm address already onboarded" );

// Verify EIP-712 signature
bool isValidSignature = _verifyOnboardSignature(
validatorAddress,
solverId,
solverName,
chainIds,
solverAddresses,
nonces[validatorAddress],
deadline,
signature
);

if (!isValidSignature) revert InvalidSignature();

// Increment nonce for replay protection
nonces[validatorAddress]++;

solverEvmAddress[solverId] = msg.sender;
// Validate addresses
for (uint256 i = 0; i < solverAddresses.length; i++) {
if (bytes(solverAddresses[i]).length == 0) revert InvalidSolverAddress();
if (bytes(addressToSolverId[solverAddresses[i]]).length != 0) {
revert AddressAlreadyAssigned(solverAddresses[i]);
}
}
// Create solver struct - STARTS AS INACTIVE BUT ONBOARDED
solvers[solverId] = Solver({
solverId: solverId,
solverName: solverName,
chainIds: chainIds,
solverAddresses: solverAddresses,
isActive: false, // Solver starts as INACTIVE
isOnboarded: true, // But is ONBOARDED
onboardedAt: block.timestamp,
offboardedAt: 0
});
// Update mappings for all addresses
for (uint256 i = 0; i < solverAddresses.length; i++) {
addressToSolverId[solverAddresses[i]] = solverId;
authorizedAddresses[solverAddresses[i]] = true;
}
// Update state
solverExists[solverId] = true;
solverAccount[msg.sender] = solverId;
solverOnboarded[msg.sender] = true;
emit SolverOnboarded(solverId, solverName, chainIds, solverAddresses, block.timestamp);
}

function validateSolverId(
uint256 deadline,
bytes calldata signature
) external {
if (solverIdValidated[msg.sender]) revert SolverIdAlreadyValidated();

string memory solverId = solverAccount[msg.sender];
require(bytes(solverId).length != bytes("").length, "solver has onboarded without running the node");
if (bytes(solverId).length == 0) revert UnauthorizedSolver();

bool valid = _verifyValidateSolverSignature(
validatorAddress,
solverId,
nonces[validatorAddress],
deadline,
signature
);

if (!valid) revert InvalidSignature();

nonces[validatorAddress]++; // replay protection
solverIdValidated[msg.sender] = true;
}

function invalidateSolverIds(
string[] calldata solverIds
)
external
// onlyRole(MPC_ROLE)
{
if (solverIds.length == 0) revert EmptyChainIdsList();

for (uint256 i = 0; i < solverIds.length; i++) {
string memory solverId = solverIds[i];

if (!solverExists[solverId]) revert SolverNotFound(solverId);

address solverAddr = solverEvmAddress[solverId];
if (solverAddr == address(0)) revert UnauthorizedSolver();

if (!solverIdValidated[solverAddr]) {
revert SolverNotValidated(solverId);
}

solverIdValidated[solverAddr] = false;

emit SolverIdInvalidated(
solverId,
solverAddr,
block.timestamp
);
}
}

/**
* @dev Add liquidity to the pool
*/
//add solver id validation check
function addLiquidityBatch(
AddLiquidityBatch[] calldata deposits
)
external
{
if (deposits.length == 0) revert EmptyAmountsList();

for (uint256 i = 0; i < deposits.length; i++) {
AddLiquidityBatch calldata dep = deposits[i];

string memory solverId = dep.solverId;
uint256 amount = dep.amount;
ChainType chainType = dep.chainType;
string memory txId = dep.txId;

if (amount == 0) revert InvalidAmount();
if (!solverExists[solverId]) revert SolverNotFound(solverId);
if (!solvers[solverId].isOnboarded) revert SolverNotOnboarded(solverId);
if (!solverIdValidated[solverEvmAddress[solverId]]) {
revert SolverNotValidated(solverId);
}

uint256 chainId = (chainType == ChainType.BTC)
? REQUIRED_CHAIN_BTC
: REQUIRED_CHAIN_TICS;

// Accounting update
solverChainAmounts[solverId][chainId] += amount;
solverTotalAmounts[solverId] += amount;

emit LiquidityAdded(
solverId,
chainId,
amount,
block.timestamp,
txId
);

// Activate solver if now eligible
_activateSolverIfEligible(solverId);
}
}

function removeLiquidity(
RemoveLiquidity[] calldata requests
)
external
{
if (requests.length == 0) revert EmptyAmountsList();

// Max possible size = requests.length (upper bound)
address[] memory recipients = new address[](requests.length);
uint256[] memory amounts = new uint256[](requests.length);
uint256 ticsCount = 0;

for (uint256 i = 0; i < requests.length; i++) {
RemoveLiquidity calldata req = requests[i];

string memory solverId = req.solverId;
uint256 amount = req.amount;
ChainType chainType = req.chainType;

if (amount == 0) revert InvalidAmount();
if (!solverExists[solverId]) revert SolverNotFound(solverId);
if (!solvers[solverId].isOnboarded) revert SolverNotOnboarded(solverId);

uint256 chainId = (chainType == ChainType.BTC)
? REQUIRED_CHAIN_BTC
: REQUIRED_CHAIN_TICS;

uint256 currentBalance = solverChainAmounts[solverId][chainId];
if (currentBalance < amount) revert InsufficientBalance();

// Accounting update
solverChainAmounts[solverId][chainId] = currentBalance - amount;
solverTotalAmounts[solverId] -= amount;

emit LiquidityRemoved(
solverId,
chainId,
amount,
block.timestamp,
req.transactionHash
);

// Collect TICS transfers only
if (chainType == ChainType.TICS) {
recipients[ticsCount] = solverEvmAddress[solverId];
amounts[ticsCount] = amount;
ticsCount++;
}

// Deactivate solver if needed
_deactivateSolverIfNeeded(
solverId,
"Required chain liquidity below minimum"
);
}

// Execute batch transfer only for TICS
if (ticsCount > 0) {
address[] memory finalRecipients = new address[](ticsCount);
uint256[] memory finalAmounts = new uint256[](ticsCount);

for (uint256 i = 0; i < ticsCount; i++) {
finalRecipients[i] = recipients[i];
finalAmounts[i] = amounts[i];
}

ITreasuryVault(treasuryVault).batchTransfer(
finalRecipients,
finalAmounts
);
}
}

/**
* @dev Calculate solvers reward based on liquidity and validation status
* @param targetChainId Intent target chain ID
* @param intentSourceAmount Total reward amount to distribute
*/
function solverRewardUpdation(
uint256 sourceChainId,
uint256 targetChainId,
uint256 intentSourceAmount
)
external
// onlyRole(INTENT_MANAGER_ROLE)
{
if (intentSourceAmount == 0) revert InvalidAmount();

// Calculate total liquidity on target chain
uint256 totalTargetChainLiquidity = 0;
for (uint256 i = 0; i < activeSolverIds.length; i++) {
string memory solverId = activeSolverIds[i];
if (solvers[solverId].isActive) {
totalTargetChainLiquidity += solverChainAmounts[solverId][targetChainId];
}
}

for (uint256 i = 0; i < activeSolverIds.length; i++) {
string memory solverId = activeSolverIds[i];

if (!solvers[solverId].isActive) continue;

uint256 solverLiquidity = solverChainAmounts[solverId][targetChainId];
if (solverLiquidity == 0) continue;

uint256 weightedReward =
(solverLiquidity * intentSourceAmount) / totalTargetChainLiquidity;

address solverAddr = solverEvmAddress[solverId];

uint256 finalReward = solverIdValidated[solverAddr]
? weightedReward
: (weightedReward * NON_VALIDATED_REWARD_PERCENTAGE) / PERCENTAGE_DIVISOR;

solverRewards[solverId][sourceChainId] += finalReward;
}
}


function claimRewardsBatch(
RewardClaim[] calldata claims
)
external
// onlyRole(MPC_ROLE)
{
if (claims.length == 0) revert EmptyAmountsList();

address[] memory recipients = new address[](claims.length);
uint256[] memory amounts = new uint256[](claims.length);
uint256 ticsCount = 0;

for (uint256 i = 0; i < claims.length; i++) {
RewardClaim calldata claim = claims[i];

address solverAddr = claim.solver;
uint256 amount = claim.amount;
ChainType chainType = claim.chainType;

if (amount == 0) revert InvalidAmount();

string memory solverId = solverAccount[solverAddr];
if (bytes(solverId).length == 0) revert SolverNotFound("");

uint256 chainId = (chainType == ChainType.BTC)
? REQUIRED_CHAIN_BTC
: REQUIRED_CHAIN_TICS;

// Update claimed rewards accounting
solverClaimedRewards[solverId][chainId] += amount;

// Collect TICS transfers only
if (chainType == ChainType.TICS) {
recipients[ticsCount] = solverAddr;
amounts[ticsCount] = amount;
ticsCount++;
}
}

// Execute vault transfer only for TICS
if (ticsCount > 0) {
address[] memory finalRecipients = new address[](ticsCount);
uint256[] memory finalAmounts = new uint256[](ticsCount);

for (uint256 i = 0; i < ticsCount; i++) {
finalRecipients[i] = recipients[i];
finalAmounts[i] = amounts[i];
}

ITreasuryVault(treasuryVault).batchTransfer(
finalRecipients,
finalAmounts
);
}
}


function changeValidatorAddress(address _validatorAddress) external onlyRole(DEFAULT_ADMIN_ROLE){
validatorAddress = _validatorAddress;
}

function setMinimumLiquidityBTC(uint256 newMinimum)
external
{
uint256 oldMinimum = minLiquidityBTC;
minLiquidityBTC = newMinimum;
emit MinimumLiquidityUpdated(REQUIRED_CHAIN_BTC, oldMinimum, newMinimum, block.timestamp);
}

function setMinimumLiquidityTICS(uint256 newMinimum)
external
onlyRole(ADMIN_ROLE)
{
uint256 oldMinimum = minLiquidityTICS;
minLiquidityTICS = newMinimum;
emit MinimumLiquidityUpdated(REQUIRED_CHAIN_TICS, oldMinimum, newMinimum, block.timestamp);
}

function setSolverFeePercentage(uint256 newFee)
external
onlyRole(ADMIN_ROLE)
{

uint256 oldFee = solverFeePercentage;
solverFeePercentage = newFee;

emit SolverFeeUpdated(
oldFee,
newFee,
block.timestamp
);
}

// View functions

/**
* @dev Get current nonce for an address
* @param account Address to check nonce for
* @return uint256 Current nonce
*/
function getNonce(address account) external view returns (uint256) {
return nonces[account];
}

/**
* @dev Get the domain separator for EIP-712
* @return bytes32 Domain separator
*/
function getDomainSeparator() external view returns (bytes32) {
return _domainSeparatorV4();
}

/**
* @dev Get solver details
*/
function getSolver(string memory solverId) external view returns (Solver memory) {
if (!solverExists[solverId]) revert SolverNotFound(solverId);
return solvers[solverId];
}

/**
* @dev Check if solver has validated their ID
* @param solver Solver address to check
* @return bool True if solver has validated their ID
*/
function isSolverIdValidated(address solver) external view returns (bool) {
return solverIdValidated[solver];
}

/**
* @dev Get all unique chain IDs across all active solvers
* @return chainIds Array of unique chain IDs
*/
function getAllActiveChainIds() external view returns (uint256[] memory) {
uint256[] memory tempChainIds = new uint256[](1000);
uint256 uniqueCount = 0;
for (uint256 i = 0; i < activeSolverIds.length; i++) {
string memory solverId = activeSolverIds[i];
if (solvers[solverId].isActive) {
uint256[] memory solverChainIds = solvers[solverId].chainIds;
for (uint256 j = 0; j < solverChainIds.length; j++) {
uint256 chainId = solverChainIds[j];
bool exists = false;
for (uint256 k = 0; k < uniqueCount; k++) {
if (tempChainIds[k] == chainId) {
exists = true;
break;
}
}
if (!exists) {
tempChainIds[uniqueCount] = chainId;
uniqueCount++;
}
}
}
}
uint256[] memory chainIds = new uint256[](uniqueCount);
for (uint256 i = 0; i < uniqueCount; i++) {
chainIds[i] = tempChainIds[i];
}
return chainIds;
}


function getSolverEvmAddress(string memory solverId) external view returns(address){
return solverEvmAddress[solverId];
}

/**
* @dev Get total liquidity for all chains
* @return liquidities Array of corresponding liquidity amounts
*/
function getAllChainLiquidities()
external
view
returns (uint256[] memory liquidities)
{
uint256[] memory chainIds = this.getAllActiveChainIds();
liquidities = new uint256[](chainIds.length);
for (uint256 i = 0; i < chainIds.length; i++) {
uint256 chainLiquidity = 0;
for (uint256 j = 0; j < activeSolverIds.length; j++) {
string memory solverId = activeSolverIds[j];
if (solvers[solverId].isActive) {
chainLiquidity += solverChainAmounts[solverId][chainIds[i]];
}
}
liquidities[i] = chainLiquidity;
}
return liquidities;
}

function getSolverClaimedReward(
string memory solverId,
uint256 chainId
)
external
view
returns (uint256)
{
return solverClaimedRewards[solverId][chainId];
}

function getSolverChainAmount(string memory solverId, uint256 chainId)
external
view
returns (uint256)
{
return solverChainAmounts[solverId][chainId];
}

function getSolverAddresses(string memory solverId)
external
view
returns (string[] memory)
{
if (!solverExists[solverId]) revert SolverNotFound(solverId);
return solvers[solverId].solverAddresses;
}

function getSolverAllChainAmounts(string memory solverId)
external
view
returns (uint256[] memory amounts)
{
if (!solverExists[solverId]) revert SolverNotFound(solverId);
uint256[] memory chainIds = solvers[solverId].chainIds;
amounts = new uint256[](chainIds.length);
for (uint256 i = 0; i < chainIds.length; i++) {
amounts[i] = solverChainAmounts[solverId][chainIds[i]];
}
return amounts;
}

function getActiveSolvers() external view returns (string[] memory) {
return activeSolverIds;
}

function isSolverActive(string memory solverId) external view returns (bool) {
return solverExists[solverId] && solvers[solverId].isActive;
}

function isSolverOnboarded(string memory solverId) external view returns (bool) {
return solverExists[solverId] && solvers[solverId].isOnboarded;
}

function getTotalActiveSolvers() external view returns (uint256) {
return totalActiveSolvers;
}

function getSolverId(address solver) external view returns (string memory){
return solverAccount[solver];
}

function getMinimumLiquidityBTC() external view returns (uint256) {
return minLiquidityBTC;
}

function getMinimumLiquidityTICS() external view returns (uint256) {
return minLiquidityTICS;
}

function getSolverFeePercentage() external view returns (uint256) {
return solverFeePercentage;
}


function getSolversUnclaimedRewards(
string[] calldata solverIds
)
external
view
returns (SolverUnclaimedRewards[] memory rewards)
{
rewards = new SolverUnclaimedRewards[](solverIds.length);

for (uint256 i = 0; i < solverIds.length; i++) {
string memory solverId = solverIds[i];

if (!solverExists[solverId]) {
rewards[i] = SolverUnclaimedRewards({
solverId: solverId,
btcUnclaimed: 0,
ticsUnclaimed: 0
});
continue;
}

uint256 btcAccrued = solverRewards[solverId][REQUIRED_CHAIN_BTC];
uint256 btcClaimed = solverClaimedRewards[solverId][REQUIRED_CHAIN_BTC];

uint256 ticsAccrued = solverRewards[solverId][REQUIRED_CHAIN_TICS];
uint256 ticsClaimed = solverClaimedRewards[solverId][REQUIRED_CHAIN_TICS];

rewards[i] = SolverUnclaimedRewards({
solverId: solverId,
btcUnclaimed: btcAccrued > btcClaimed ? btcAccrued - btcClaimed : 0,
ticsUnclaimed: ticsAccrued > ticsClaimed ? ticsAccrued - ticsClaimed : 0
});
}
}

}
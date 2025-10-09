
const nodeHexValues = {
  1: '3F0082BF39F75AA8FF1B4D2E5C91A03B24FC90561A30BA62CC473FF247F01BE7', //3rd
  2: '3F5EA75B25B002B3DDE8573F07B424B0ACBFDEAD4075787976C247A88886890E', //2nd
  3: 'A3931F0C2680E4D7131AF97A702C73D57C566B300B045A2EAD8FCDC8F058506A', //1st
  4: '6B9DE9D23C6A01129EB333E095FA8DAAD91158F7CA94BF46B0DD73C6AF2F30BA', //4th
  5: '977F07AD676B576680B10671791E722F7D9F84EB2E6F47FD407D982E95416B3F'  //5th 
};

//private-key with four shares = 0x6e3fa81a1f0f6c9f372d2158113da3b36d40635489b9a33916f3f335b958cece
//private-key with five shares = 0xa278b1386356ecb676b3db486ec4e674e50c802a98361feaae1eb6a62e9508f5

// BLS12-381 Fr modulus (prime)
const CURVE_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
// Complete JavaScript code with detailed Lagrange Y calculation steps

// Convert hex to decimal using BigInt
function hexToDecimal(hexString) {
  return BigInt('0x' + hexString);
}

// Convert all node values to decimal
const nodeDecimalValues = {};
for (let nodeId in nodeHexValues) {
  nodeDecimalValues[nodeId] = hexToDecimal(nodeHexValues[nodeId]);
}

console.log('=== Node Values Conversion ===');
for (let nodeId in nodeDecimalValues) {
  console.log(`Node ${nodeId}:`);
  console.log(`  Hex: 0x${nodeHexValues[nodeId]}`);
  console.log(`  Decimal: ${nodeDecimalValues[nodeId].toString()}`);
  console.log('');
}

// Modular inverse function using Extended Euclidean Algorithm
function modInverse(a, m) {
  if (a < 0n) a = ((a % m) + m) % m;

  let [oldR, r] = [m, a % m];
  let [oldS, s] = [0n, 1n];

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }

  if (oldR !== 1n) {
    throw new Error('Modular inverse does not exist');
  }

  return ((oldS % m) + m) % m;
}

// Enhanced Lagrange interpolation with detailed step logging
function lagrangeInterpolationDetailed(shares) {
  let result = 0n;
  const detailedSteps = [];

  console.log(`🔢 Lagrange Formula: P(0) = Σⱼ yⱼ × λⱼ`);
  console.log(`🔢 Where λⱼ = ∏(m≠j) [(0-xₘ)/(xⱼ-xₘ)] mod N`);
  console.log('─'.repeat(60));

  for (let j = 0; j < shares.length; j++) {
    const [xj, yj] = shares[j];
    let numerator = 1n;
    let denominator = 1n;
    const numeratorFactors = [];
    const denominatorFactors = [];

    console.log(`\n🧮 CALCULATING λ${xj} for Node ${xj}:`);
    console.log(`   yⱼ = ${yj.toString()}`);

    // Build Lagrange coefficient step by step
    for (let m = 0; m < shares.length; m++) {
      if (m !== j) {
        const [xm] = shares[m];
        const numFactor = -xm;
        const denFactor = xj - xm;

        numeratorFactors.push(`(0-${xm})`);
        denominatorFactors.push(`(${xj}-${xm})`);

        numerator = (numerator * numFactor) % CURVE_ORDER;
        denominator = (denominator * denFactor) % CURVE_ORDER;

        console.log(`   Factor: (0-${xm})/(${xj}-${xm}) = ${numFactor}/${denFactor}`);
      }
    }

    // Handle negative values
    if (numerator < 0n) {
      numerator = ((numerator % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
    }
    if (denominator < 0n) {
      denominator = ((denominator % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
    }

    console.log(`   📊 Numerator = ${numeratorFactors.join(' × ')} = ${numerator.toString()}`);
    console.log(`   📊 Denominator = ${denominatorFactors.join(' × ')} = ${denominator.toString()}`);

    const denomInverse = modInverse(denominator, CURVE_ORDER);
    console.log(`   📊 Denominator⁻¹ = ${denomInverse.toString()}`);

    const lambda = (numerator * denomInverse) % CURVE_ORDER;
    console.log(`   🎯 λ${xj} = ${numerator.toString()} × ${denomInverse.toString()} = ${lambda.toString()}`);

    const contribution = (lambda * yj) % CURVE_ORDER;
    console.log(`   ⚡ Contribution = λ${xj} × y${xj} = ${contribution.toString()}`);

    result = (result + contribution) % CURVE_ORDER;
    console.log(`   📈 Running Total = ${result.toString()}`);

    detailedSteps.push({
      nodeId: Number(xj),
      yValue: yj.toString(),
      numeratorFactors: numeratorFactors.join(' × '),
      numerator: numerator.toString(),
      denominatorFactors: denominatorFactors.join(' × '),
      denominator: denominator.toString(),
      denominatorInverse: denomInverse.toString(),
      lambda: lambda.toString(),
      contribution: contribution.toString(),
      runningTotal: result.toString(),
    });
  }

  return { result: result.toString(), steps: detailedSteps };
}

// Generate all possible 3-node combinations
function getAllCombinations(nodes, k) {
  const combinations = [];
  const n = nodes.length;

  function backtrack(start, current) {
    if (current.length === k) {
      combinations.push([...current]);
      return;
    }

    for (let i = start; i < n; i++) {
      current.push(nodes[i]);
      backtrack(i + 1, current);
      current.pop();
    }
  }

  backtrack(0, []);
  return combinations;
}

// Main calculation function with enhanced display
function performDetailedThresholdCalculation() {
  const nodeIds = [1, 2, 3, 4, 5];
  const threshold = 3;

  // Create shares array: [(x, y), ...]
  const shares = nodeIds.map((id) => [BigInt(id), nodeDecimalValues[id]]);

  // Get all 3-node combinations
  const combinations = getAllCombinations(shares, threshold);

  console.log('\n' + '='.repeat(80));
  console.log('🚀 DETAILED LAGRANGE INTERPOLATION CALCULATIONS');
  console.log('='.repeat(80));

  const results = [];

  combinations.forEach((combo, index) => {
    const nodeSet = combo.map(([x, y]) => Number(x)).sort();
    const setName = `{${nodeSet.join(',')}}`;

    console.log(`\n🎯 SET ${index + 1}: Nodes ${setName}`);
    console.log('═'.repeat(80));

    const calculation = lagrangeInterpolationDetailed(combo);

    console.log(`\n🏆 FINAL RECONSTRUCTED SECRET FOR SET ${setName}:`);
    console.log(`   Decimal: ${calculation.result}`);
    console.log(`   Hex: 0x${BigInt(calculation.result).toString(16)}`);
    console.log('═'.repeat(80));

    results.push({
      set: setName,
      secret: calculation.result,
      hex: '0x' + BigInt(calculation.result).toString(16),
    });
  });

  return results;
}

// Execute the detailed calculation
console.log('🔍 Starting Detailed Threshold Cryptography Calculation...\n');
const results = performDetailedThresholdCalculation();

// Final verification with detailed summary
console.log('\n' + '🔍 FINAL VERIFICATION SUMMARY'.padStart(50));
console.log('─'.repeat(80));

const uniqueSecrets = [...new Set(results.map((r) => r.secret))];

console.log('📋 Results Summary:');
results.forEach((result, i) => {
  console.log(`   Set ${result.set}: ${result.hex}`);
});

console.log('\n🎯 Verification:');
if (uniqueSecrets.length === 1) {
  console.log('✅ SUCCESS: All 3-node subsets produce IDENTICAL results!');
  console.log(`✅ Consistent Secret (Decimal): ${uniqueSecrets[0]}`);
  console.log(`✅ Consistent Secret (Hex): 0x${BigInt(uniqueSecrets).toString(16)}`);
  console.log('✅ Your threshold shares are mathematically VALID!');
  console.log('✅ Perfect (3,4)-threshold cryptography implementation!');
} else {
  console.log('❌ FAILURE: Different subsets produce different results!');
  console.log('❌ Your shares are NOT from the same polynomial!');
  uniqueSecrets.forEach((secret, i) => {
    console.log(`   Result ${i + 1}: ${secret}`);
  });
}

console.log('\n🎉 Detailed Calculation Complete!');
console.log('─'.repeat(80));
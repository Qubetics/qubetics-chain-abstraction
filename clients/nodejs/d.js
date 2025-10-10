import { ethers } from "ethers";

const tx = ethers.Transaction.from("0xf86b8007830493e09404cb44cfd8bbac13bfc25dc00d64bd6b7212815189017da3a04c7b3e0000808246ada024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca018a425d984a7c525fccf8463ec5839513364f4fa48a612306848766adbc2e3a8");

console.log("Signer Address:", tx.from);
console.log("Chain ID:", tx.chainId);
console.log("Transaction Details:", {
    nonce: tx.nonce,
    gasPrice: tx.gasPrice?.toString(),
    gasLimit: tx.gasLimit?.toString(),
    to: tx.to,
    value: ethers.formatEther(tx.value),
    signature: tx.signature
});

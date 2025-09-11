import { ethers } from "ethers";

const tx = ethers.Transaction.from("0xf86601843b9aca00830493e094c16abb6e296b89b4cc573083fe96f2480172ff0680808246aea024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca016572c929df17a6762ec70c84f4063415c819839c1f22d6544698c4ab44e47eb");

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

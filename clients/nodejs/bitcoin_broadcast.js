// broadcast-tx-blockstream.js
import fetch from 'node-fetch'; // npm install node-fetch@2

// Replace with your signed raw transaction hex
const RAW_TX_HEX = "<your_raw_transaction_hex_here>";

async function broadcastTx() {
  const url = "https://blockstream.info/api/tx"; 
  // For testnet: https://blockstream.info/testnet/api/tx

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: RAW_TX_HEX
  });

  if (!res.ok) {
    console.error(`Error: ${res.status} ${res.statusText}`);
    console.error(await res.text());
    return;
  }

  const txid = await res.text();
  console.log("Broadcasted TXID:", txid);
}

broadcastTx().catch(console.error);

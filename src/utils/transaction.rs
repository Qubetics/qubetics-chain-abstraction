use crate::rpc_server::DummyTransaction;
// use rlp::RlpStream;

/// RLP encoder for Ethereum transaction signing (EIP-155)
pub struct RlpEncoder {
    pub data: Vec<u8>,
}

// impl RlpEncoder {
//     pub fn new() -> Self {
//         Self { data: Vec::new() }
//     }

//     pub fn encode_u64(&mut self, value: u64) {
//         if value == 0 {
//             self.data.push(0x80);
//         } else {
//             let bytes = value.to_be_bytes();
//             let start = bytes.iter().position(|&x| x != 0).unwrap_or(bytes.len() - 1);
//             self.encode_bytes(&bytes[start..]);
//         }
//     }

//     pub fn encode_hex_string(&mut self, hex_str: &str) {
//         // Remove "0x" prefix if present
//         let clean_hex = if hex_str.starts_with("0x") {
//             &hex_str[2..]
//         } else {
//             hex_str
//         };

//         // Convert hex string to bytes
//         let bytes = hex::decode(clean_hex).unwrap_or_else(|_| {
//             // If hex decoding fails, try to parse as decimal string
//             let value = clean_hex.parse::<u128>().unwrap_or(0);
//             value.to_be_bytes().to_vec()
//         });

//         let mut stream = RlpStream::new();
//         stream.append(&bytes);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn encode_address(&mut self, address: &str) {
//         // Remove "0x" prefix if present
//         let clean_address = if address.starts_with("0x") {
//             &address[2..]
//         } else {
//             address
//         };

//         // Convert hex address to bytes
//         let bytes = hex::decode(clean_address).unwrap_or_else(|_| vec![0u8; 20]);

//         let mut stream = RlpStream::new();
//         stream.append(&bytes);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn encode_bytes(&mut self, bytes: &[u8]) {
//         let mut stream = RlpStream::new();
//         stream.append(&bytes);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn encode_list_header(&mut self, content_len: usize) {
//         let mut stream = RlpStream::new();
//         stream.begin_list(content_len);
//         self.data.extend_from_slice(&stream.out());
//     }

//     pub fn finalize(self) -> Vec<u8> {
//         self.data
//     }
// }
impl RlpEncoder {
    fn new() -> Self {
        RlpEncoder { data: Vec::new() }
    }

    fn encode_bytes(&mut self, bytes: &[u8]) {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            self.data.push(bytes[0]);
        } else if bytes.len() < 56 {
            self.data.push(0x80 + bytes.len() as u8);
            self.data.extend_from_slice(bytes);
        } else {
            let length_bytes = (bytes.len() as u64).to_be_bytes();
            let length_start = length_bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(length_bytes.len() - 1);
            let length_slice = &length_bytes[length_start..];

            self.data.push(0xb7 + length_slice.len() as u8);
            self.data.extend_from_slice(length_slice);
            self.data.extend_from_slice(bytes);
        }
    }

    fn encode_u64(&mut self, value: u64) {
        if value == 0 {
            self.data.push(0x80);
        } else {
            let bytes = value.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(bytes.len() - 1);
            self.encode_bytes(&bytes[start..]);
        }
    }

    fn encode_hex_string(&mut self, hex_str: &str) {
        let bytes = encode_hex_to_bytes(hex_str);
        self.encode_bytes(&bytes);
    }

    fn encode_address(&mut self, address: &str) {
        let bytes = hex::decode(&address[2..]).expect("Invalid address");
        self.encode_bytes(&bytes);
    }

    fn encode_list_header(&mut self, content_length: usize) {
        if content_length < 56 {
            self.data.push(0xc0 + content_length as u8);
        } else {
            let length_bytes = (content_length as u64).to_be_bytes();
            let length_start = length_bytes
                .iter()
                .position(|&x| x != 0)
                .unwrap_or(length_bytes.len() - 1);
            let length_slice = &length_bytes[length_start..];

            self.data.push(0xf7 + length_slice.len() as u8);
            self.data.extend_from_slice(length_slice);
        }
    }

    fn finalize(self) -> Vec<u8> {
        self.data
    }
}

fn encode_hex_to_bytes(hex_str: &str) -> Vec<u8> {
    let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let trimmed = clean_hex.trim_start_matches('0');
    let mut final_hex = if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    };

    if final_hex.len() % 2 == 1 {
        final_hex = format!("0{}", final_hex);
    }

    hex::decode(&final_hex).expect("Invalid hex string")
}

/// Create transaction for signing using RLP encoding (EIP-155)
pub fn create_transaction_for_signing(tx: &DummyTransaction) -> Vec<u8> {
    let mut content = Vec::new();

    // Encode transaction fields for signing (EIP-155)
    let mut encoder = RlpEncoder::new();

    // Nonce
    encoder.encode_u64(tx.nonce);
    content.extend_from_slice(&encoder.finalize());

    // Gas limit
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.gas_limit);
    content.extend_from_slice(&encoder.finalize());

     // Gas price
     encoder = RlpEncoder::new();
     encoder.encode_hex_string(&tx.gas_price.to_string());
     content.extend_from_slice(&encoder.finalize());

    // To address
    encoder = RlpEncoder::new();
    encoder.encode_address(&tx.to);
    content.extend_from_slice(&encoder.finalize());

    // Value (amount)
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.value.to_string());
    content.extend_from_slice(&encoder.finalize());

    // Data (empty)
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    // Chain ID
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.chain_id);
    content.extend_from_slice(&encoder.finalize());

    // Empty r and s for EIP-155
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());

    // Create final RLP with list header
    let mut final_encoder = RlpEncoder::new();
    final_encoder.encode_list_header(content.len());
    final_encoder.data.extend_from_slice(&content);

    final_encoder.finalize()
}

pub fn create_signed_transaction(tx: &DummyTransaction, r: &[u8], s: &[u8], v: u64) -> Vec<u8> {
    let mut content = Vec::new();
    
    // Encode transaction fields
    let mut encoder = RlpEncoder::new();
    
    // Nonce
    encoder.encode_u64(tx.nonce);
    content.extend_from_slice(&encoder.finalize());
    
    // Gas price
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.gas_price);
    content.extend_from_slice(&encoder.finalize());
    
    // Gas limit
    encoder = RlpEncoder::new();
    encoder.encode_u64(tx.gas_limit);
    content.extend_from_slice(&encoder.finalize());
    
    // To address
    encoder = RlpEncoder::new();
    encoder.encode_address(&tx.to);
    content.extend_from_slice(&encoder.finalize());
    
    // Value
    encoder = RlpEncoder::new();
    encoder.encode_hex_string(&tx.value);
    content.extend_from_slice(&encoder.finalize());
    
    // Data (empty)
    encoder = RlpEncoder::new();
    encoder.encode_bytes(&[]);
    content.extend_from_slice(&encoder.finalize());
    
    // v
    encoder = RlpEncoder::new();
    encoder.encode_u64(v); // ✅ proper RLP encoding for large v
    content.extend_from_slice(&encoder.finalize());
    
    // r
    encoder = RlpEncoder::new();
    encoder.encode_bytes(r);
    content.extend_from_slice(&encoder.finalize());
    
    // s
    encoder = RlpEncoder::new();
    encoder.encode_bytes(s);
    content.extend_from_slice(&encoder.finalize());
    
    // Create final RLP with list header
    let mut final_encoder = RlpEncoder::new();
    final_encoder.encode_list_header(content.len());
    final_encoder.data.extend_from_slice(&content);
    
    final_encoder.finalize()
}


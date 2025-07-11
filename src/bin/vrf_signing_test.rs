use mpc_node::signing::SigningNode;
use mpc_node::types::ChannelMessage;
use tokio::sync::mpsc;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("🚀 Starting VRF + Signing Integration Test");

    // Create a channel for messages
    let (message_tx, mut message_rx) = mpsc::channel(100);

    // Create a signing node
    let mut signing_node = SigningNode::new("test_node_1".to_string(), 2, message_tx);

    // Generate BLS key pair
    signing_node.generate_key_pair()?;

    // Get VRF public key
    if let Some(vrf_pubkey) = signing_node.get_vrf_public_key() {
        info!("🎲 VRF Public Key: {}", vrf_pubkey);
    }

    // Test message to sign
    let test_message = b"Hello, VRF + BLS signing integration!";
    info!("📝 Test message: {}", String::from_utf8_lossy(test_message));

    // Sign the message (this will also generate VRF proof)
    info!("✍️ Signing message with VRF proof generation...");
    signing_node.sign_message(test_message).await?;

    // Generate a separate VRF proof for demonstration
    info!("🎲 Generating additional VRF proof for demonstration...");
    if let Some(vrf_output) = signing_node.generate_vrf_proof(b"additional_vrf_input") {
        info!(
            "🎲 VRF Output - Value: {}, Hash: {}",
            vrf_output.value,
            hex::encode(&vrf_output.hash[..8])
        );
    }

    // Verify VRF proof (self-verification)
    info!("🔍 Testing VRF proof verification...");
    if let (Some(vrf_output), Some(pubkey_bytes)) = (
        signing_node.generate_vrf_proof(b"verification_test"),
        signing_node.get_vrf_public_key_bytes(),
    ) {
        let is_valid =
            signing_node.verify_vrf_proof(&pubkey_bytes, b"verification_test", &vrf_output);
        info!("✅ VRF proof verification result: {}", is_valid);
    }

    // Process any broadcasted messages
    while let Ok(message) = message_rx.try_recv() {
        match message {
            ChannelMessage::Broadcast { topic, data } => {
                info!(
                    "📤 Received broadcast on topic '{}': {} bytes",
                    topic,
                    data.len()
                );
            }
            ChannelMessage::Unicast { .. } | ChannelMessage::LocalTransaction { .. } => {
                info!("ℹ️ Received unhandled channel message variant");
            },
            ChannelMessage::ScheduledDKGStart => {
                info!("⏳ Received scheduled DKG start message");
            }
            _ => {
                info!("ℹ️ Received unknown channel message variant");    
            }
        }
    }

    info!("✅ VRF + Signing integration test completed successfully!");
    Ok(())
}

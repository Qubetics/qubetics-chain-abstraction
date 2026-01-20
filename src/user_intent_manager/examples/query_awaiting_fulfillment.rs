// Example: Query intents awaiting network fulfillment
//
// This code shows how to use the new get_intents_awaiting_network_fulfillment() function
// to find all intents where users have deposited funds (UserToVault transaction completed)
// but the network hasn't yet fulfilled the withdrawal (NetworkToTarget transaction pending)

use crate::user_intent_manager::UserIntentManager;

async fn example_query_awaiting_intents(user_intent_manager: &UserIntentManager) {
    // Example 1: Get ALL intents awaiting network fulfillment (no time filter)
    let all_awaiting = user_intent_manager
        .get_intents_awaiting_network_fulfillment(None)
        .await;

    println!(
        "Found {} intents awaiting network fulfillment (all)",
        all_awaiting.len()
    );

    // Example 2: Get only intents that haven't been updated in the last 10 seconds
    // This is useful to avoid re-processing the same intent too frequently
    let stale_intents = user_intent_manager
        .get_intents_awaiting_network_fulfillment(Some(10))
        .await;

    println!(
        "Found {} intents awaiting fulfillment (stale >10s)",
        stale_intents.len()
    );

    for (intent_hash, intent, tx_ids) in stale_intents {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Intent Hash: {}", intent_hash);
        println!("Amount: {} {}", intent.amount, intent.source_chain);
        println!("Source Chain: {}", intent.source_chain);
        println!("Target Chain: {}", intent.target_chain);
        println!("Target Address: {}", intent.target_address);

        // Transaction status
        println!("\n📊 Transaction Status:");
        println!(
            "  ✅ UserToVault TX: {}",
            tx_ids.user_to_network_tx_id.as_ref().unwrap()
        );
        println!("  ⏳ NetworkToTarget TX: Pending");

        // Timing information
        println!("\n⏰ Timing:");
        println!("  Created: {}", tx_ids.created_at);
        println!("  Last Updated: {}", tx_ids.updated_at);

        // Calculate wait time since last update
        let wait_duration = chrono::Utc::now().signed_duration_since(tx_ids.updated_at);
        println!(
            "  ⏱️  Time since last update: {} seconds",
            wait_duration.num_seconds()
        );

        // Solver information
        if let Some(solver_id) = &tx_ids.final_solver_id {
            println!("\n🧮 Solver: {}", solver_id);
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}

// Alternative: Using the IntentStorage directly
async fn example_query_via_storage(
    intent_storage: &crate::database::storage::user_storage::IntentStorage,
) {
    // Get intents not updated in the last 15 seconds
    match intent_storage
        .get_intents_awaiting_network_fulfillment(Some(15))
        .await
    {
        Ok(awaiting_intents) => {
            println!(
                "Found {} intents not updated in last 15 seconds",
                awaiting_intents.len()
            );
            for (intent_hash, intent, tx_ids) in awaiting_intents {
                let wait_time = chrono::Utc::now().signed_duration_since(tx_ids.updated_at);
                println!(
                    "Intent {} is awaiting fulfillment ({} seconds old)",
                    intent_hash,
                    wait_time.num_seconds()
                );
                println!(
                    "  User deposited: {}",
                    tx_ids.user_to_network_tx_id.unwrap()
                );
                println!("  Amount: {}", intent.amount);
            }
        }
        Err(e) => {
            eprintln!("Error querying intents: {}", e);
        }
    }
}

// Example: Check if a specific intent is awaiting fulfillment and is stale
async fn example_check_specific_intent_is_stale(
    user_intent_manager: &UserIntentManager,
    intent_hash: &str,
    min_wait_seconds: i64,
) -> bool {
    if let Some(tx_ids) = user_intent_manager
        .get_intent_transaction_ids(intent_hash)
        .await
    {
        // Has UserToVault but missing NetworkToTarget
        let is_awaiting =
            tx_ids.user_to_network_tx_id.is_some() && tx_ids.network_to_target_tx_id.is_none();

        if !is_awaiting {
            return false;
        }

        // Check if enough time has passed since last update
        let now = chrono::Utc::now();
        let time_since_update = now.signed_duration_since(tx_ids.updated_at);
        return time_since_update.num_seconds() >= min_wait_seconds;
    }
    false
}

// Example: Periodic processing of stale intents
async fn example_process_stale_intents(user_intent_manager: &UserIntentManager) {
    // Only process intents that haven't been updated in the last 30 seconds
    // This avoids hammering the same intent repeatedly
    let stale_intents = user_intent_manager
        .get_intents_awaiting_network_fulfillment(Some(30))
        .await;

    println!(
        "Processing {} stale intents (>30s old)",
        stale_intents.len()
    );

    for (intent_hash, intent, tx_ids) in stale_intents {
        println!("Processing intent {}", intent_hash);

        // Your processing logic here...
        // For example: retry network transaction, notify solvers, etc.
    }
}

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::types::ChannelMessage;

use crate::network::transport::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Schedule DKG to start at a specific Unix timestamp
    pub(crate) fn schedule_dkg_at(&mut self, start_time_unix: u64) {
        if let Some(prev) = self.scheduled_dkg_task.take() {
            info!("⏰ Cancelling previous scheduled DKG task");
            prev.abort();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let delay = start_time_unix.saturating_sub(now);

        // clone only the sender
        let tx = self.message_tx.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(delay)).await;
            // send the one "start now" message back into your main loop
            let _ = tx.send(ChannelMessage::ScheduledDKGStart).await;
        });

        self.scheduled_dkg_task = Some(handle);
        info!("✅ Scheduled DKG to start at {}", start_time_unix);
    }
}

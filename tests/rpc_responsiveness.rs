use std::time::Duration;

use adkg::database::{Database, DatabaseConfig};
use anyhow::Result;
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_database_wrappers_keep_handlers_responsive() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config = DatabaseConfig {
        path: temp_dir.path().to_string_lossy().to_string(),
        ..DatabaseConfig::default()
    };

    let db = Database::new(config)?;

    let writer_db = db.clone();
    let writer = tokio::spawn(async move {
        for i in 0..500usize {
            let key = format!("key-{i}");
            writer_db.put_string_async(&key, &i).await?;
        }
        Result::<_, anyhow::Error>::Ok(())
    });

    let reader_db = db.clone();
    let reader = tokio::spawn(async move {
        for i in 0..500usize {
            let key = format!("key-{i}");
            let _ = reader_db.get_string_async::<usize>(&key).await?;
        }
        Result::<_, anyhow::Error>::Ok(())
    });

    let count_db = db.clone();
    let responsiveness_check = tokio::time::timeout(Duration::from_millis(500), async move {
        // Poll counts while writes are happening and ensure timer still fires quickly.
        let mut iterations = 0;
        while iterations < 25 {
            let _ = count_db.count_entries_with_prefix_async("key-").await?;
            tokio::time::sleep(Duration::from_millis(5)).await;
            iterations += 1;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;

    assert!(
        responsiveness_check.is_ok(),
        "async database wrapper blocked the runtime"
    );

    writer.await??;
    reader.await??;

    Ok(())
}

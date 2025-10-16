use crate::EnvVars;
use rust_decimal::Decimal;
use std::{collections::HashMap, str::FromStr};
use serde_json::Value;

pub async fn fetch_crypto_prices() -> Result<HashMap<String, Decimal>, String> {
	use tracing::{debug, error, info};

	let vars = EnvVars::load_with_dotenv()
		.map_err(|e| format!("Failed to load environment variables: {}", e))?;
	let base_url = vars.backend_api_url;

	let url = format!("{}/api/v1/cryptos/prices?symbols=BTC,TICS", base_url);
	let client = reqwest::Client::new();

	info!("Fetching crypto prices from URL: {}", url);

	let resp = client.get(&url).send().await.map_err(|e| {
		error!("Failed to fetch crypto prices: {}", e);
		format!("Failed to fetch crypto prices: {}", e)
	})?;

	let status = resp.status();
	debug!("Crypto prices API response status: {}", status);

	let resp_text = resp.text().await.map_err(|e| {
		error!("Failed to read crypto prices response text: {}", e);
		format!("Failed to read crypto prices response text: {}", e)
	})?;

	debug!("Crypto prices API response body: {}", resp_text);

	if !status.is_success() {
		error!("Crypto prices API returned non-success status {}: {}", status, resp_text);
		return Err(format!(
			"Crypto prices API returned non-success status {}: {}",
			status, resp_text
		));
	}

	let resp_json: Value = serde_json::from_str(&resp_text).map_err(|e| {
		error!("Failed to parse crypto prices response: {}", e);
		format!("Failed to parse crypto prices response: {}", e)
	})?;

	debug!("Crypto prices API response JSON: {:?}", resp_json);

	if resp_json.get("error").and_then(|v| v.as_bool()) == Some(true) {
		let msg = resp_json.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error");
		error!("Crypto prices API error: {}", msg);
		return Err(format!("Crypto prices API error: {}", msg));
	}

	let data = resp_json.get("data").ok_or_else(|| {
		error!("No 'data' field in crypto prices response");
		"No 'data' field in crypto prices response".to_string()
	})?;

	let mut prices: HashMap<String, Decimal> = HashMap::new();

	// Tolerant parsing: accept string or number for price fields
	let to_decimal = |v: &Value| -> Option<Decimal> {
		match v {
			Value::String(s) => Decimal::from_str(s).ok(),
			Value::Number(n) => Decimal::from_str(&n.to_string()).ok(),
			_ => None,
		}
	};

	if let Some(obj) = data.as_object() {
		for (symbol, value) in obj {
			if let Some(price) = to_decimal(value) {
				debug!("Parsed Decimal price for {}: {}", symbol, price);
				prices.insert(symbol.clone(), price);
			} else {
				// Last-ditch: log and skip
				debug!("Could not parse Decimal price for {}: {:?}", symbol, value);
			}
		}
	} else {
		debug!("'data' field is not an object in crypto prices response");
	}

	info!("Fetched crypto prices (Decimal): {:?}", prices);
	Ok(prices)
}

/// Encode calldata for invalidateSolverIds(string[] solverIds)
pub fn encode_invalidate_solver_ids_calldata(solver_ids: &[String]) -> Option<Vec<u8>> {
    if solver_ids.is_empty() {
        return None;
    }

    #[allow(deprecated)]
    let f = Function {
        name: "invalidateSolverIds".to_owned(),
        inputs: vec![Param {
            name: "solverIds".into(),
            kind: ParamType::Array(Box::new(ParamType::String)),
            internal_type: None,
        }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };

    let solver_id_tokens: Vec<Token> = solver_ids
        .iter()
        .map(|id| Token::String(id.clone()))
        .collect();

    let tokens = vec![Token::Array(solver_id_tokens)];

    f.encode_input(&tokens).ok()
}

/// Create a ChainTransaction for invalidateSolverIds contract call
pub async fn create_invalidate_solver_ids_transaction(
    from_address: &str,
    solver_ids: &[String],
    contract_address: &str,
    chain_id: u64,
) -> Result<ChainTransaction> {
    let normalized_contract_address = if contract_address.starts_with("0x") {
        contract_address.to_string()
    } else {
        format!("0x{contract_address}")
    };

    info!(
        "🔧 [CONTRACT] Creating invalidateSolverIds for {} solver IDs on chain {} via {}",
        solver_ids.len(),
        chain_id,
        normalized_contract_address
    );

    let calldata = encode_invalidate_solver_ids_calldata(solver_ids)
        .ok_or_else(|| anyhow::anyhow!("Failed to encode calldata for encode_invalidate_solver_ids_calldata (solver_ids={:?}, chain_id={})", solver_ids, chain_id))?;
    let calldata_hex = format!("0x{}", hex::encode(&calldata));

    info!(
        "🔧 [CONTRACT] invalidateSolverIds calldata prepared (len={} bytes)",
        calldata.len()
    );

    let estimated_gas = estimate_gas_for_deposit_intent(
        from_address,
        &normalized_contract_address,
        &calldata_hex,
        chain_id,
    )
    .await?;
    let gas_limit = estimated_gas + (estimated_gas / 10);

    let gas_price = get_gas_price_for_chain("qubetics", chain_id)
        .await
        .unwrap_or_else(|e| {
            warn!(
                "⚠️ Failed to get dynamic gas price for invalidateSolverIds: {}, using fallback",
                e
            );
            get_default_gas_price_for_chain("qubetics")
        });

    info!("🔧 [CONTRACT] invalidateSolverIds gas price: {}", gas_price);
    info!("🔧 [CONTRACT] invalidateSolverIds gas limit: {}", gas_limit);
    let nonce = fetch_tics_nonce(from_address, chain_id).await?;

    let tics_tx = TicsTransaction {
        to: normalized_contract_address,
        value: "0x0".to_string(),
        gas_limit,
        gas_price,
        nonce,
        data: Some(calldata),
        chain_id,
    };

    Ok(ChainTransaction::Tics(tics_tx))
}

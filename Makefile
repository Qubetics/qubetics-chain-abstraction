RUSTFLAGS := -A dead_code -A unused_imports -A non_snake_case -A unused_variables -A unreachable_code

build:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --bin ptp
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --bin mpcn
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --bin vrf_demo

runt:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --bin ptp -- $(ARGS)

runn:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --bin mpcn

runvrf:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --bin vrf_demo

# RPC Server related targets
test-rpc:
	cd clients/nodejs && npm install && node test_client.js

test-rpc-curl:
	@echo "Testing RPC server with curl..."
	@echo "1. Getting node status..."
	@curl -s http://localhost:8080/status | jq .
	@echo ""
	@echo "2. Submitting transaction..."
	@curl -s -X POST http://localhost:8080/submit_transaction \
		-H "Content-Type: application/json" \
		-d '{"from":"0x123","to":"0x456","amount":1000,"nonce":1,"data":"test"}' | jq .
	@echo ""
	@echo "3. Starting DKG..."
	@curl -s -X POST http://localhost:8080/start_dkg | jq .

install-deps:
	cd clients/nodejs && npm install

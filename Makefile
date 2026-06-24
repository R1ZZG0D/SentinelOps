# SentinelOps developer workflow. Run `make help` for the list.
.DEFAULT_GOAL := help
PY := python3

.PHONY: help test lint parse triage triage-online siem-up siem-down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

test: ## Run parser unit tests
	$(PY) -m pytest ingestion/tests -q

lint: ## Validate Sigma detections (same check CI runs)
	sigma check detections/sigma -i -x attacktag

parse: ## Demo: normalize the sample Linux auth log to NDJSON
	$(PY) -m ingestion.parsers.cli ingestion/sample_logs/linux_auth.log --source linux_auth --pretty

triage: ## Demo: triage the SSH brute-force alert (offline, no API key)
	cd triage-assistant && $(PY) triage.py sample_alerts/ssh_bruteforce.json --offline

triage-online: ## Triage with Claude (requires ANTHROPIC_API_KEY)
	cd triage-assistant && $(PY) triage.py sample_alerts/ssh_bruteforce.json

siem-up: ## Bring up the Wazuh stack (needs Docker + certs generated)
	cd docker && docker compose up -d

siem-down: ## Tear down the Wazuh stack
	cd docker && docker compose down

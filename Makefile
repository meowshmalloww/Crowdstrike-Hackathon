.PHONY: verify python-test gateway-test dashboard-check evaluation

verify: python-test gateway-test dashboard-check evaluation

python-test:
	python -m pytest -q

gateway-test:
	cd services/gateway && go test ./...

dashboard-check:
	cd apps/dashboard && npm run lint && npm run build

evaluation:
	python -m counterflow_eval --dataset data/evaluation/events.jsonl

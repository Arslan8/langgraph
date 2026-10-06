.PHONY: benchmark-census bolt-on-pocs camel-pocs census format lint model-probe pocs progent-pocs seed-transcripts test tables

benchmark-census:
	uv run --project . python -m slanggraph_eval.benchmark_census --config configs/benchmark_samples.json --root . --output reports/e1/benchmark-sample.json --audit-db audits/e1.db

census:
	uv run --project . python -m slanggraph_eval.census --manifest vulntools/manifest.json --source vulntools/tools.py --output-dir reports/e1 --audit-db audits/e1.db

pocs:
	uv run --project . python -m slanggraph_eval.pocs --condition none --transcript transcripts/e2/qwen3-8b.json --output reports/e2/no-defense.json --audit-db audits/e2.db

model-probe:
	uv run --project . python -m slanggraph_eval.model_probe --config configs/models.json --audit-db audits/setup.db

seed-transcripts:
	uv run --project . python -m slanggraph_eval.transcript_seed --config configs/models.json --role secondary --output transcripts/e2/qwen3-8b.json --audit-db audits/e2.db

progent-pocs:
	PYTHONPATH=.:adapters SECAGENT_GENERATE=false SECAGENT_POLICY_MODEL=qwen3:8b uv run --isolated --with ./vendor/progent --with-editable . --with-editable ../libs/langgraph --with-editable ../libs/prebuilt python adapters/progent_pocs.py --transcript transcripts/e2/qwen3-8b.json --output reports/e2/progent.json --audit-db audits/e2.db

bolt-on-pocs:
	PYTHONPATH=. uv run --isolated --with langchain-eydii==0.1.1 --with-editable . python adapters/bolt_on_pocs.py --defense eydii --transcript transcripts/e2/qwen3-8b.json --output reports/e2/bolt-on-eydii.json --audit-db audits/e2.db
	PYTHONPATH=. uv run --isolated --with langchain-forge==0.2.0 --with veritera==0.4.0 --with-editable . python adapters/bolt_on_pocs.py --defense forge --transcript transcripts/e2/qwen3-8b.json --output reports/e2/bolt-on-forge.json --audit-db audits/e2.db
	PYTHONPATH=. uv run --isolated --with langchain-nuggets==1.4.0 --with-editable . python adapters/bolt_on_pocs.py --defense nuggets --transcript transcripts/e2/qwen3-8b.json --output reports/e2/bolt-on-nuggets.json --audit-db audits/e2.db

camel-pocs:
	PYTHONPATH=. uv run --isolated --with ./vendor/camel --with-editable . python adapters/camel_pocs.py --transcript transcripts/e2/qwen3-8b.json --output reports/e2/camel-argument-hijack.json --audit-db audits/e2.db

format:
	uv run --project . ruff format .

lint:
	uv run --project . ruff check .

test:
	uv run --project . pytest

tables:
	uv run --project . python -m slanggraph_eval.tables --audit-dir audits --output-dir reports/generated

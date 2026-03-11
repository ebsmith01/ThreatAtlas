# ThreatAtlas

Skeleton monorepo for evaluating and red-teaming LLM systems. Contains API, runner utilities, core libraries, datasets, docs, and CI stubs.

## Layout
- `apps/api`: FastAPI service exposing health, evaluation, attacks, reports, and targets endpoints.
- `apps/runner`: CLI runners for executing suites, single cases, and batch jobs.
- `core`: Shared libraries for attacks, evaluation, targets, guardrails, reporting, and retrieval.
- `data`: Seed JSON/YAML for attacks, policies, and eval cases.
- `tests`: Unit/integration/redteam/regression harnesses.
- `docs`: Architecture, threat model, methodology, and taxonomy notes.
- `scripts`: Utility scripts for seeding, benchmarking, and reporting.
- `docker`: Container build context; compose file exposes the API on port 8000.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
uvicorn apps.api.main:app --reload
```

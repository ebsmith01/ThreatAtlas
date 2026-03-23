from fastapi import FastAPI

from src.api.models import EvalRequest, EvalResponse, HealthResponse
from src.evals.attack_eval import run_attack_eval
from src.evals.reporting import build_report
from src.targets.mock_target import MockTarget


app = FastAPI()


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok")


@app.post("/evaluate", response_model=EvalResponse)
def evaluate(request: EvalRequest):
    if request.target_name == "mock":
        target = MockTarget()
    else:
        target = MockTarget()

    results = run_attack_eval(target=target, sample_size=request.sample_size)
    report = build_report(results)

    return EvalResponse(
        summary=report["summary"],
        results=report["results"],
    )
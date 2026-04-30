from __future__ import annotations

import argparse, json, time
from collections import defaultdict, Counter
from pathlib import Path

from data.loaders import load_attack_corpus
from evals.rule_evaluator import evaluate_response
from evals.risk import score_report
from evals.severity import score_response
from guardrails.filters import run_guardrail_checks
from targets.llm_target import LLMTarget
from targets.mock_safe_target import MockSafeTarget
from targets.mock_target import MockSmokeTarget
from targets.mock_vulnerable_target import MockVulnerableTarget

# ------------------------------------------------------------
# QUICK GUIDE
# ------------------------------------------------------------
# pass_rate → how safe the system is
# authorization_failure_rate → IAM failure (critical)
# rag_data_leak_rate → RAG leaking sensitive data
# agent_tool_abuse_rate → agent misusing tools
# coverage → tells you if dataset is balanced
# ------------------------------------------------------------

ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")
REPORTS_DIR = Path("outputs")

# ------------------ TARGET ------------------
def get_target(name, model=None, provider=None, base_url=None, api_key_env=None):
    if name == "smoke": return MockSmokeTarget()
    if name == "safe": return MockSafeTarget()
    if name == "vulnerable": return MockVulnerableTarget()
    if name == "llm":
        return LLMTarget(provider=provider or "openai", model=model or "gpt-4.1", base_url=base_url, api_key_env=api_key_env)
    raise ValueError(f"Unknown target: {name}")

# ------------------ SUMMARY ------------------
def summarize(results):
    bucket = lambda: {"total":0,"pass":0,"fail":0,"unauth":0,"auth_fail":0}
    by_cat, by_role, by_sys, by_sens = map(lambda _: defaultdict(bucket), range(4))

    total=passed=failed=unauth=auth_fail=0
    rag_total=rag_leak=agent_total=agent_abuse=0
    llm_total=llm_failures=0

    for r in results:
        pf = r["pass_fail"]
        sens = r.get("sensitivity")
        sys = r.get("target_system")

        is_unauth = r.get("permission_context",{}).get("is_authorized") is False
        is_auth_fail = is_unauth and "authorization_policy_enforcement" in r.get("violated_rules",[])

        for b,k in [(by_cat,r.get("category")),(by_role,r.get("actor_role")),(by_sys,sys),(by_sens,sens)]:
            if k:
                b[k]["total"]+=1; b[k][pf]+=1
                if is_unauth: b[k]["unauth"]+=1
                if is_auth_fail: b[k]["auth_fail"]+=1

        if pf=="pass": passed+=1
        else: failed+=1

        if is_unauth: unauth+=1
        if is_auth_fail: auth_fail+=1

        # NEW METRICS
        if sys=="rag":
            rag_total+=1
            if pf=="fail" and sens in {"internal","confidential"}: rag_leak+=1
        if sys=="agent":
            agent_total+=1
            if pf=="fail": agent_abuse+=1
        if sys=="llm":
            llm_total += 1
            if pf == "fail": llm_failures += 1

    def fmt(b):
        return {k:{
            **v,
            "pass_rate": round(v["pass"]/v["total"]*100,2) if v["total"] else 0
        } for k,v in b.items()}

    # compute total once (avoid walrus operator for compatibility)
    total = len(results)

    return {
        "overall":{
            "total": total,
            "pass":passed,
            "fail":failed,
            "pass_rate":round(passed/total*100,2) if total else 0,
            "unauthorized_cases":unauth,
            "authorization_failures":auth_fail,
            "authorization_failure_rate":round(auth_fail/unauth*100,2) if unauth else 0,
            "rag_data_leak_rate":round(rag_leak/rag_total*100,2) if rag_total else 0,
            "agent_tool_abuse_rate":round(agent_abuse/agent_total*100,2) if agent_total else 0,
            "llm_failure_rate": round(llm_failures/llm_total*100,2) if llm_total else 0,
        },
        "system_risk": {
            "rag_data_leak_rate": round(rag_leak/rag_total*100,2) if rag_total else 0,
            "agent_tool_abuse_rate": round(agent_abuse/agent_total*100,2) if agent_total else 0,
            "llm_failure_rate": round(llm_failures/llm_total*100,2) if llm_total else 0
        },
        "by_category":fmt(by_cat),
        "by_actor_role":fmt(by_role),
        "by_target_system":fmt(by_sys),
        "by_sensitivity":fmt(by_sens)
    }

# ------------------ COVERAGE ------------------
def coverage(results):
    c = lambda k: Counter(r.get(k) for r in results)
    return {
        "category":dict(c("category")),
        "role":dict(c("actor_role")),
        "system":dict(c("target_system")),
        "sensitivity":dict(c("sensitivity")),
        "auth":{
            "authorized":sum(r.get("permission_context",{}).get("is_authorized") is True for r in results),
            "unauthorized":sum(r.get("permission_context",{}).get("is_authorized") is False for r in results)
        }
    }

# ------------------ EVAL ------------------
def run_eval(n, target_name, system=None, **kwargs):
    attacks = load_attack_corpus(ATTACK_CORPUS_PATH)

    # optional system filter (llm / rag / agent)
    if system:
        attacks = [a for a in attacks if a.get("target_system") == system]

    attacks = attacks[:n]
    target = get_target(target_name, **kwargs)

    results=[]

    for a in attacks:
        t0 = time.perf_counter()
        out = target.run(
            prompt=a.get("prompt"),
            category=a.get("category"),
            actor_role=a.get("actor_role"),
            target_system=a.get("target_system"),
            sensitivity=a.get("sensitivity"),
            required_permission=a.get("required_permission"),
            permission_context=a.get("permission_context"),
            metadata=a.get("metadata"),
        )
        latency = (time.perf_counter() - t0) * 1000

        guard = run_guardrail_checks(out.response_text, a["category"], a.get("permission_context"), a.get("sensitivity"), a.get("required_permission"))
        pf, rules = evaluate_response(out.response_text, a["category"], a.get("expected_behavior"), a.get("actor_role"), a.get("target_system"), a.get("sensitivity"), a.get("required_permission"), a.get("permission_context"))

        violations = sorted(set(rules) | {v.get("category",v.get("rule_id")) for v in guard.get("violations",[])})
        final = "fail" if violations else pf

        r = {**a,
            "response_text":out.response_text,
            "pass_fail":final,
            "violated_rules":violations,
            "latency_ms":round(latency,2)
        }
        r.update(score_response(r))
        results.append(r)

    return {
        "summary": summarize(results),
        "coverage": coverage(results),
        "risk": score_report(results),
        "results": results
    }

# ------------------ PRINT ------------------
def print_report(r, target_name):
    o=r["summary"]["overall"]
    print("\n=== SUMMARY ===")
    for k,v in o.items(): print(f"{k}: {v}")

    print("\n=== SYSTEM RISK ===")
    for k,v in r["summary"].get("system_risk", {}).items():
        print(f"{k}: {v}%")

    print("\n=== SYSTEM BREAKDOWN ===")
    by_sys = r["summary"].get("by_target_system", {})

    # only show system relevant to target
    target_map = {
        "llm": "llm",
        "safe": None,
        "vulnerable": None,
        "smoke": None
    }

    selected_system = target_map.get(target_name)

    for sys, m in by_sys.items():
        if selected_system and sys != selected_system:
            continue

        print(f"\n[{sys.upper()}]")
        print(f"  total: {m.get('total')}")
        print(f"  pass_rate: {m.get('pass_rate')}%")
        print(f"  fail: {m.get('fail')}")
        print(f"  unauthorized: {m.get('unauth')}")
        print(f"  auth_failures: {m.get('auth_fail')}")

    print("\n=== COVERAGE ===")
    for k,v in r["coverage"].items(): print(k, v)

    print("\n=== RISK ===", r["risk"]["risk_score"])

# ------------------ CLI ------------------
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--target", default="smoke")
    p.add_argument("--model", default="gpt-4.1")
    p.add_argument("--provider", default="openai")
    p.add_argument("--sample", type=int, default=25)
    p.add_argument("--system", choices=["llm","rag","agent"], default=None)
    args=p.parse_args()

    report = run_eval(args.sample, args.target, system=args.system, model=args.model, provider=args.provider)
    print_report(report, args.target)

    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"{args.target}_report.json"
    json.dump(report, open(path,"w"), indent=2)
    print("\nSaved:", path)

if __name__ == "__main__":
    main()
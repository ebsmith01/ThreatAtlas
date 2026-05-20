import {
  FormEvent,
  useMemo,
  useState,
} from "react";

import FindingsTable from "../components/FindingsTable";
import RiskGauge from "../components/RiskGauge";
import SummaryCards from "../components/SummaryCards";
import TelemetryPanel from "../components/TelemetryPanel";

import {
  EvaluationResult,
  normalizeEvaluation,
  runEvaluation,
} from "../services/api";


// ==================================================
// Demo Result
// ==================================================
// Fallback data shown if:
// - backend is offline
// - API request fails
// - frontend is running independently
// ==================================================

const demoResult: EvaluationResult = normalizeEvaluation({

  summary: {

    pass_rate: 82,

    fail_rate: 18,

    risk_score: 42,

    authorization_failures: 2,

    allowed: 8,

    blocked: 2,

    tool_usage: 14,

    retrieval_attempts: 9,

    actor_roles: 3,
  },

  findings: [],
});


// ==================================================
// Dashboard Page
// ==================================================
// Main ThreatAtlas frontend interface.
//
// Responsibilities:
// - configure evaluations
// - execute evaluations
// - display telemetry
// - display findings
// - visualize AI security risk
// ==================================================

export default function Dashboard() {

  // --------------------------------------------------
  // Evaluation configuration state.
  // --------------------------------------------------

  const [target, setTarget] = useState("rag_safe");

  const [system, setSystem] = useState("rag");

  const [sampleSize, setSampleSize] = useState(10);


  // --------------------------------------------------
  // Evaluation result state.
  // --------------------------------------------------

  const [result, setResult] = useState<EvaluationResult>(
    demoResult,
  );


  // --------------------------------------------------
  // UI state.
  // --------------------------------------------------

  const [status, setStatus] = useState("Ready");

  const [isRunning, setIsRunning] = useState(false);


  // --------------------------------------------------
  // Request payload.
  // --------------------------------------------------
  // Memoized to avoid unnecessary recalculation.
  // --------------------------------------------------

  const payload = useMemo(
    () => ({

      target,

      system,

      sample_size: sampleSize,
    }),
    [sampleSize, system, target],
  );


  // ==================================================
  // Run Evaluation
  // ==================================================
  // Executes ThreatAtlas evaluations through the API.
  // ==================================================

  const handleSubmit = async (

    event: FormEvent<HTMLFormElement>,
  ) => {

    event.preventDefault();

    setIsRunning(true);

    setStatus("Running evaluation...");

    try {

      const evaluation = await runEvaluation(payload);

      setResult(evaluation);

      setStatus("Evaluation complete");

    } catch (error) {

      console.error(error);

      setStatus(
        "API unavailable, showing demo telemetry",
      );

    } finally {

      setIsRunning(false);
    }
  };


  // ==================================================
  // Render Dashboard
  // ==================================================

  return (

    <main className="min-h-screen bg-slate-100 text-slate-950">

      <div className="flex min-h-screen flex-col lg:flex-row">


        {/* ========================================== */}
        {/* Sidebar */}
        {/* ========================================== */}

        <aside className="border-b border-slate-200 bg-slate-950 p-6 text-white lg:w-80 lg:border-b-0 lg:border-r">


          {/* ------------------------------------------ */}
          {/* Branding */}
          {/* ------------------------------------------ */}

          <div>

            <p className="text-sm font-semibold uppercase tracking-widest text-teal-300">
              ThreatAtlas
            </p>

            <h1 className="mt-3 text-2xl font-semibold">
              Evaluation Dashboard
            </h1>

            <p className="mt-2 text-sm text-slate-300">
              AI security platform visualization
            </p>

          </div>


          {/* ------------------------------------------ */}
          {/* Evaluation Controls */}
          {/* ------------------------------------------ */}

          <form
            className="mt-8 space-y-6"
            onSubmit={handleSubmit}
          >


            {/* Target Selector */}

            <label className="block">

              <span className="text-sm font-medium text-slate-200">
                Target
              </span>

              <select
                className="mt-2 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-white outline-none ring-teal-400 focus:ring-2"
                value={target}
                onChange={(event) =>
                  setTarget(event.target.value)
                }
              >
                <option value="rag_safe">
                  rag_safe
                </option>

                <option value="smoke">
                  smoke
                </option>

                <option value="agent_safe">
                  agent_safe
                </option>
              </select>
            </label>


            {/* System Selector */}

            <label className="block">

              <span className="text-sm font-medium text-slate-200">
                System
              </span>

              <select
                className="mt-2 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-white outline-none ring-teal-400 focus:ring-2"
                value={system}
                onChange={(event) =>
                  setSystem(event.target.value)
                }
              >
                <option value="rag">
                  rag
                </option>

                <option value="llm">
                  llm
                </option>

                <option value="agent">
                  agent
                </option>
              </select>
            </label>


            {/* Sample Size Slider */}

            <label className="block">

              <span className="flex items-center justify-between text-sm font-medium text-slate-200">
                Sample Size

                <span>
                  {sampleSize}
                </span>
              </span>

              <input
                className="mt-3 w-full accent-teal-400"
                min="1"
                max="100"
                type="range"
                value={sampleSize}
                onChange={(event) =>
                  setSampleSize(Number(event.target.value))
                }
              />
            </label>


            {/* Run Evaluation Button */}

            <button
              className="w-full rounded-md bg-teal-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-teal-300 disabled:cursor-not-allowed disabled:bg-slate-600 disabled:text-slate-300"
              disabled={isRunning}
              type="submit"
            >
              {isRunning
                ? "Running Evaluation"
                : "Run Evaluation"}
            </button>

          </form>


          {/* ------------------------------------------ */}
          {/* Status Indicator */}
          {/* ------------------------------------------ */}

          <p className="mt-6 rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-300">
            {status}
          </p>

        </aside>


        {/* ========================================== */}
        {/* Main Dashboard Content */}
        {/* ========================================== */}

        <section className="flex-1 p-6 lg:p-8">

          <div className="mx-auto max-w-7xl space-y-6">


            {/* Summary Metrics */}

            <SummaryCards
              summary={result.summary}
            />


            {/* Risk + Findings */}

            <div className="grid gap-6 xl:grid-cols-[360px_1fr]">

              <RiskGauge
                score={result.summary.risk_score}
              />

              <FindingsTable
                findings={result.findings}
              />

            </div>


            {/* Runtime Telemetry */}

            <TelemetryPanel
              summary={result.summary}
            />

          </div>

        </section>

      </div>

    </main>
  );
}

import {
  FormEvent,
  useEffect,
  useMemo,
  useState,
} from "react";

import ControlPlane from "../components/ControlPlane";
import CategoryBreakdown from "../components/CatagoryBreakdown";
import FindingsTable from "../components/FindingsTable";

import {
  EvaluationResult,
  normalizeEvaluation,
  runEvaluation,
} from "../services/api";


// ==================================================
// Demo Result
// ==================================================
// Fallback dashboard data shown when:
// - backend is offline
// - evaluation fails
// - frontend runs independently
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

  findings: [

    {
      id: "1",
      type: "Prompt Injection",
      severity: "Critical",
      detail: "System prompt override attempt detected.",
    },

    {
      id: "2",
      type: "Retrieval",
      severity: "High",
      detail: "Unauthorized retrieval exposure attempt.",
    },

    {
      id: "3",
      type: "Violation",
      severity: "Medium",
      detail: "Role escalation attempt blocked.",
    },
  ],
});


// ==================================================
// Dashboard Page
// ==================================================
// Main ThreatAtlas AI security interface.
//
// Responsibilities:
// - configure evaluations
// - execute evaluations
// - visualize attack performance
// - display security findings
// ==================================================

export default function Dashboard() {

  // --------------------------------------------------
  // Evaluation configuration.
  // --------------------------------------------------

  const [target, setTarget] = useState("rag_safe");

  const [system, setSystem] = useState("rag");

  const [sampleSize, setSampleSize] = useState(10);


  // --------------------------------------------------
  // Threat modeling configuration.
  // --------------------------------------------------

  const [attackCategory, setAttackCategory] = useState(
    "prompt_injection",
  );

  const [sensitivity, setSensitivity] = useState(
    "internal",
  );

  const [actorRole, setActorRole] = useState(
    "user",
  );


  // --------------------------------------------------
  // Keep target aligned with selected system.
  // --------------------------------------------------

  useEffect(() => {

    if (system === "rag") {
      setTarget("rag_safe");
    }

    if (system === "agent") {
      setTarget("agent_safe");
    }

    if (system === "llm") {
      setTarget("smoke");
    }

  }, [system]);


  // --------------------------------------------------
  // Evaluation result state.
  // --------------------------------------------------

  const [result, setResult] = useState<EvaluationResult>(
    demoResult,
  );


  // --------------------------------------------------
  // UI state.
  // --------------------------------------------------

  const [isRunning, setIsRunning] = useState(false);


  // --------------------------------------------------
  // Request payload.
  // --------------------------------------------------

  const payload = useMemo(
    () => ({

      // ----------------------------------------------
      // Core evaluation configuration.
      // ----------------------------------------------

      target,

      system,

      sample_size: sampleSize,


      // ----------------------------------------------
      // Threat modeling configuration.
      // ----------------------------------------------

      attack_category: attackCategory,

      sensitivity,

      actor_role: actorRole,

    }),
    [
      attackCategory,
      actorRole,
      sampleSize,
      sensitivity,
      system,
      target,
    ],
  );


  // ==================================================
  // Run Evaluation
  // ==================================================

  const handleSubmit = async (

    event: FormEvent<HTMLFormElement>,
  ) => {

    event.preventDefault();

    setIsRunning(true);

    console.log("ThreatAtlas Evaluation Payload:");

    console.log(payload);

    try {

      // ----------------------------------------------
      // Execute backend evaluation.
      // ----------------------------------------------
      // Sends:
      // - system type
      // - target
      // - attack category
      // - sensitivity level
      // - actor role
      // - sample size
      // ----------------------------------------------
      const evaluation = await runEvaluation(payload);

      setResult(evaluation);

      console.log("ThreatAtlas Evaluation Result:");
      console.log(evaluation);

    } catch (error) {

      console.error(error);

      setResult(demoResult);

    } finally {

      setIsRunning(false);
    }
  };


  // ==================================================
  // Render Dashboard
  // ==================================================

  return (

    <main className="min-h-screen bg-slate-100 text-slate-950 antialiased">

      <div className="flex min-h-screen flex-col lg:flex-row">


        {/* ========================================== */}
        {/* AI Security Control Plane */}
        {/* ========================================== */}

        <ControlPlane
          system={system}
          setSystem={setSystem}
          target={target}
          setTarget={setTarget}
          attackCategory={attackCategory}
          setAttackCategory={setAttackCategory}
          sampleSize={sampleSize}
          setSampleSize={setSampleSize}
          sensitivity={sensitivity}
          setSensitivity={setSensitivity}
          actorRole={actorRole}
          setActorRole={setActorRole}
          onRun={() => {
            const formEvent = {
              preventDefault: () => {},
            } as FormEvent<HTMLFormElement>;

            handleSubmit(formEvent);
          }}
          loading={isRunning}
        />


        {/* ========================================== */}
        {/* Main Dashboard Content */}
        {/* ========================================== */}

        <section className="flex-1 overflow-y-auto bg-slate-100 p-6 lg:p-8">

          <div className="mx-auto max-w-7xl space-y-8">


            {/* ====================================== */}
            {/* Attack Category Breakdown */}
            {/* ====================================== */}

            <CategoryBreakdown
              findings={result.findings}
            />


            {/* ====================================== */}
            {/* Findings Table */}
            {/* ====================================== */}

            <FindingsTable
              findings={result.findings}
            />

          </div>

        </section>

      </div>

    </main>
  );
}

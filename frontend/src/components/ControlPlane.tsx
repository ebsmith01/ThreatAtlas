import {
  Shield,
  Bot,
  Database,
  AlertTriangle,
  Play,
  Radar,
  User,
  Lock,
  Activity,
} from "lucide-react";

// ======================================================
// ThreatAtlas Control Plane
// ======================================================
// Primary evaluation control surface.
//
// Controls:
// - system type
// - target type
// - attack category
// - sample size
// - sensitivity
// - actor role
// - evaluation execution
// ======================================================

type ControlPlaneProps = {

  system: string;

  setSystem: (
    value: string,
  ) => void;

  target: string;

  setTarget: (
    value: string,
  ) => void;

  attackCategory: string;

  setAttackCategory: (
    value: string,
  ) => void;

  sampleSize: number;

  setSampleSize: (
    value: number,
  ) => void;

  sensitivity: string;

  setSensitivity: (
    value: string,
  ) => void;

  actorRole: string;

  setActorRole: (
    value: string,
  ) => void;

  onRun: () => void;

  loading?: boolean;
};


// ======================================================
// Section Label
// ======================================================
// Reusable section header for sidebar groups.
// ======================================================

function SectionLabel({
  title,
}: {
  title: string;
}) {

  return (
    <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">
      {title}
    </p>
  );
}


// ======================================================
// Sidebar Component
// ======================================================

export default function ControlPlane({

  system,
  setSystem,

  target,
  setTarget,

  attackCategory,
  setAttackCategory,

  sampleSize,
  setSampleSize,

  sensitivity,
  setSensitivity,

  actorRole,
  setActorRole,

  onRun,

  loading = false,

}: ControlPlaneProps) {

  return (

    <aside className="flex h-screen w-[340px] flex-col border-r border-slate-800 bg-gradient-to-b from-slate-950 to-slate-900 text-slate-100 shadow-2xl">


      {/* ================================================= */}
      {/* Header */}
      {/* ================================================= */}

      <div className="border-b border-slate-800 px-6 py-5">

        <div className="flex items-center gap-3">

          <div className="rounded-lg bg-indigo-500/20 p-2">

            <Shield className="h-5 w-5 text-indigo-400" />

          </div>

          <div>

            <h1 className="text-lg font-semibold">
              ThreatAtlas
            </h1>

            <p className="text-xs text-slate-400">
              AI Security Control Plane
            </p>

          </div>

        </div>

      </div>


      {/* ================================================= */}
      {/* Controls */}
      {/* ================================================= */}

      <div className="flex-1 space-y-8 overflow-y-auto px-6 py-6">


        {/* ----------------------------------------------- */}
        {/* System Overview */}
        {/* ----------------------------------------------- */}

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">

          <div className="flex items-center justify-between">

            <div>

              <p className="text-xs uppercase tracking-wide text-slate-500">
                Active Security Profile
              </p>

              <h2 className="mt-1 text-sm font-semibold text-slate-100">
                {system.toUpperCase()} Evaluation
              </h2>

            </div>

            <div className="rounded-lg bg-indigo-500/10 p-2">
              <Radar className="h-5 w-5 text-indigo-400" />
            </div>

          </div>

          <div className="mt-4 grid grid-cols-2 gap-3 text-xs">

            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">

              <p className="text-slate-500">
                Target
              </p>

              <p className="mt-1 font-medium text-slate-200">
                {target}
              </p>

            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">

              <p className="text-slate-500">
                Samples
              </p>

              <p className="mt-1 font-medium text-slate-200">
                {sampleSize}
              </p>

            </div>

          </div>

        </div>


        <SectionLabel title="System Configuration" />

        {/* ----------------------------------------------- */}
        {/* System Type */}
        {/* ----------------------------------------------- */}

        <div>

          <label className="mb-2 block text-sm font-medium text-slate-300">

            System Type

          </label>

          <div className="relative">

            <Bot className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <select
              value={system}
              onChange={(e) => setSystem(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-indigo-500"
            >

              <option value="llm">
                LLM
              </option>

              <option value="rag">
                RAG
              </option>

              <option value="agent">
                Agent
              </option>

            </select>

          </div>

        </div>


        {/* ----------------------------------------------- */}
        {/* Target Type */}
        {/* ----------------------------------------------- */}

        <div>

          <label className="mb-2 block text-sm font-medium text-slate-300">

            Target Type

          </label>

          <div className="relative">

            <Radar className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <select
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-indigo-500"
            >

              {system === "rag" && (
                <>
                  <option value="rag_safe">
                    rag_safe
                  </option>

                  <option value="rag_vulnerable">
                    rag_vulnerable
                  </option>
                </>
              )}

              {system === "agent" && (
                <>
                  <option value="agent_safe">
                    agent_safe
                  </option>

                  <option value="agent_vulnerable">
                    agent_vulnerable
                  </option>
                </>
              )}

              {system === "llm" && (
                <>
                  <option value="smoke">
                    smoke
                  </option>

                  <option value="vulnerable">
                    vulnerable
                  </option>
                </>
              )}

            </select>

          </div>

        </div>

        <SectionLabel title="Threat Modeling" />

        {/* ----------------------------------------------- */}
        {/* Attack Category */}
        {/* ----------------------------------------------- */}

        <div>
          <label className="mb-2 block text-sm font-medium text-slate-300">
            Attack Category
          </label>
          <div className="relative">

            <Activity className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <select
              value={attackCategory}
              onChange={(e) => setAttackCategory(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-indigo-500"
            >

              <option value="prompt_injection">
                Prompt Injection
              </option>

              <option value="tool_misuse">
                Tool Misuse
              </option>

              <option value="data_exfiltration">
                Data Exfiltration
              </option>

              <option value="jailbreak">
                Jailbreak
              </option>

            </select>

          </div>
        </div>

        <SectionLabel title="Access Context" />

        {/* ----------------------------------------------- */}
        {/* Sensitivity */}
        {/* ----------------------------------------------- */}

        <div>

          <label className="mb-2 block text-sm font-medium text-slate-300">

            Sensitivity Level

          </label>

          <div className="relative">

            <Lock className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <select
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-indigo-500"
            >

              <option value="low">
                Low
              </option>

              <option value="internal">
                Internal
              </option>

              <option value="confidential">
                Confidential
              </option>

            </select>

          </div>

        </div>


        {/* ----------------------------------------------- */}
        {/* Actor Role */}
        {/* ----------------------------------------------- */}

        <div>

          <label className="mb-2 block text-sm font-medium text-slate-300">

            Actor Role

          </label>

          <div className="relative">

            <User className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <select
              value={actorRole}
              onChange={(e) => setActorRole(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-indigo-500"
            >

              <option value="user">
                User
              </option>

              <option value="system">
                System
              </option>

              <option value="admin">
                Admin
              </option>

            </select>

          </div>

        </div>


        {/* ----------------------------------------------- */}
        {/* Sample Size */}
        {/* ----------------------------------------------- */}

        <div>

          <label className="mb-2 block text-sm font-medium text-slate-300">
            Sample Size
          </label>

          <div className="relative">

            <Database className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <select
              value={sampleSize}
              onChange={(e) => setSampleSize(Number(e.target.value))}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-3 text-sm text-slate-100 outline-none transition focus:border-indigo-500"
            >

              <option value={5}>5 Samples</option>
              <option value={10}>10 Samples</option>
              <option value={25}>25 Samples</option>
              <option value={50}>50 Samples</option>
              <option value={100}>100 Samples</option>

            </select>

          </div>

        </div>


      </div>


      {/* ================================================= */}
      {/* Run Evaluation */}
      {/* ================================================= */}

      <div className="border-t border-slate-800 p-6">

        <button
          onClick={onRun}
          disabled={loading}
          className="flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-3 text-sm font-medium text-white shadow-lg shadow-indigo-500/20 transition hover:scale-[1.01] hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >

          <Play className="h-4 w-4" />

          {loading
            ? "Running Evaluation..."
            : "Run Evaluation"}

        </button>


        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/80 p-4">

          <p className="text-xs uppercase tracking-wide text-slate-500">
            Evaluation Context
          </p>

          <div className="mt-3 space-y-2 text-xs">

            <div className="flex items-center justify-between">
              <span className="text-slate-500">System</span>
              <span className="font-medium text-slate-200">{system}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-500">Role</span>
              <span className="font-medium text-slate-200">{actorRole}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-500">Sensitivity</span>
              <span className="font-medium text-slate-200">{sensitivity}</span>
            </div>

          </div>

        </div>

        {/* ----------------------------------------------- */}
        {/* Footer Status */}
        {/* ----------------------------------------------- */}

        <div className="mt-4 flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900 p-3">

          <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-400" />

          <div className="text-xs text-slate-400">

            Live adversarial AI security testing against
            simulated LLM, RAG, and Agent systems.

          </div>

        </div>

      </div>

    </aside>
  );
}

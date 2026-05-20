import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type {
  EvaluationSummary,
} from "../services/api";


// ==================================================
// Component Props
// ==================================================
// High-level telemetry metrics generated during
// ThreatAtlas evaluations.
// ==================================================

type TelemetryPanelProps = {

  summary: EvaluationSummary;
};


// ==================================================
// Telemetry Panel
// ==================================================
// Displays:
// - allowed vs blocked actions
// - tool activity
// - retrieval activity
// - runtime telemetry metrics
// ==================================================

export default function TelemetryPanel({

  summary,
}: TelemetryPanelProps) {


  // --------------------------------------------------
  // Access Control Metrics
  // --------------------------------------------------
  // Tracks:
  // - allowed actions
  // - blocked actions
  // --------------------------------------------------

  const accessData = [

    {
      name: "Allowed",
      count: summary.allowed,
    },

    {
      name: "Blocked",
      count: summary.blocked,
    },
  ];


  // --------------------------------------------------
  // Runtime Activity Metrics
  // --------------------------------------------------
  // Tracks:
  // - tool usage
  // - retrieval attempts
  // - actor role coverage
  // --------------------------------------------------

  const activityData = [

    {
      name: "Tools",
      count: summary.tool_usage,
    },

    {
      name: "Retrieval",
      count: summary.retrieval_attempts,
    },

    {
      name: "Roles",
      count: summary.actor_roles,
    },
  ];


  return (

    <section className="grid gap-4 xl:grid-cols-2">


      {/* ========================================== */}
      {/* Allowed vs Blocked */}
      {/* ========================================== */}

      <article className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">


        {/* -------------------------------------- */}
        {/* Header */}
        {/* -------------------------------------- */}

        <div>

          <h2 className="text-lg font-semibold text-slate-950">
            Allowed vs Blocked
          </h2>

          <p className="mt-1 text-sm text-slate-500">
            Authorization and enforcement telemetry
          </p>

        </div>


        {/* -------------------------------------- */}
        {/* Chart */}
        {/* -------------------------------------- */}

        <div className="mt-4 h-72">

          <ResponsiveContainer
            width="100%"
            height="100%"
          >

            <BarChart data={accessData}>

              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#e2e8f0"
              />

              <XAxis
                dataKey="name"
                stroke="#64748b"
              />

              <YAxis stroke="#64748b" />

              <Tooltip />

              <Bar
                dataKey="count"
                fill="#0f766e"
                radius={[6, 6, 0, 0]}
              />

            </BarChart>

          </ResponsiveContainer>

        </div>

      </article>


      {/* ========================================== */}
      {/* Runtime Telemetry */}
      {/* ========================================== */}

      <article className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">


        {/* -------------------------------------- */}
        {/* Header */}
        {/* -------------------------------------- */}

        <div>

          <h2 className="text-lg font-semibold text-slate-950">
            Runtime Telemetry
          </h2>

          <p className="mt-1 text-sm text-slate-500">
            Tool, retrieval, and role activity
          </p>

        </div>


        {/* -------------------------------------- */}
        {/* Chart */}
        {/* -------------------------------------- */}

        <div className="mt-4 h-72">

          <ResponsiveContainer
            width="100%"
            height="100%"
          >

            <BarChart data={activityData}>

              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#e2e8f0"
              />

              <XAxis
                dataKey="name"
                stroke="#64748b"
              />

              <YAxis stroke="#64748b" />

              <Tooltip />

              <Legend />

              <Bar
                dataKey="count"
                fill="#2563eb"
                radius={[6, 6, 0, 0]}
              />

            </BarChart>

          </ResponsiveContainer>

        </div>

      </article>

    </section>
  );
}

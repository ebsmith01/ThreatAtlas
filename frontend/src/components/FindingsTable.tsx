import type { Finding } from "../services/api";


// ==================================================
// Component Props
// ==================================================
// Findings returned from ThreatAtlas evaluations.
// ==================================================

type FindingsTableProps = {

  findings: Finding[];
};


// ==================================================
// Demo Findings
// ==================================================
// Fallback findings shown when:
// - API is unavailable
// - no findings are returned
// - frontend is running independently
// ==================================================

const fallbackFindings: Finding[] = [

  {
    id: "demo-1",
    type: "Violation",
    severity: "High",
    detail:
      "Model response bypassed an authorization boundary.",
  },

  {
    id: "demo-2",
    type: "Retrieval",
    severity: "Medium",
    detail:
      "Retrieved document exceeded the requested security context.",
  },

  {
    id: "demo-3",
    type: "Prompt Injection",
    severity: "Critical",
    detail:
      "Prompt attempted to override system instructions.",
  },
];


// ==================================================
// Severity Badge Styles
// ==================================================
// Maps finding severity to UI styling.
// ==================================================

const severityStyles: Record<string, string> = {

  Low:
    "bg-slate-100 text-slate-700",

  Medium:
    "bg-amber-100 text-amber-800",

  High:
    "bg-orange-100 text-orange-800",

  Critical:
    "bg-red-100 text-red-800",
};


// ==================================================
// Findings Table
// ==================================================
// Displays:
// - policy violations
// - prompt injection findings
// - retrieval issues
// - AI security events
// ==================================================

export default function FindingsTable({

  findings,
}: FindingsTableProps) {


  // --------------------------------------------------
  // Use fallback demo data if findings are empty.
  // --------------------------------------------------

  const rows = findings.length
    ? findings
    : fallbackFindings;


  return (

    <section className="rounded-lg border border-slate-200 bg-white shadow-sm">


      {/* ========================================== */}
      {/* Header */}
      {/* ========================================== */}

      <div className="border-b border-slate-200 p-5">

        <h2 className="text-lg font-semibold text-slate-950">
          Findings
        </h2>

        <p className="mt-1 text-sm text-slate-500">
          Violations, retrieval findings, and prompt injection findings
        </p>

      </div>


      {/* ========================================== */}
      {/* Table */}
      {/* ========================================== */}

      <div className="overflow-x-auto">

        <table className="min-w-full divide-y divide-slate-200 text-left text-sm">


          {/* -------------------------------------- */}
          {/* Table Header */}
          {/* -------------------------------------- */}

          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">

            <tr>

              <th className="px-5 py-3 font-semibold">
                Type
              </th>

              <th className="px-5 py-3 font-semibold">
                Severity
              </th>

              <th className="px-5 py-3 font-semibold">
                Detail
              </th>

            </tr>

          </thead>


          {/* -------------------------------------- */}
          {/* Table Body */}
          {/* -------------------------------------- */}

          <tbody className="divide-y divide-slate-200">

            {rows.map((finding) => (

              <tr
                key={finding.id}
                className="transition hover:bg-slate-50"
              >


                {/* Finding Type */}

                <td className="px-5 py-4 font-medium text-slate-950">
                  {finding.type}
                </td>


                {/* Severity Badge */}

                <td className="px-5 py-4">

                  <span
                    className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${
                      severityStyles[finding.severity]
                      ?? "bg-slate-100 text-slate-700"
                    }`}
                  >
                    {finding.severity}
                  </span>

                </td>


                {/* Finding Details */}

                <td className="px-5 py-4 text-slate-600">
                  {finding.detail}
                </td>

              </tr>
            ))}

          </tbody>

        </table>

      </div>

    </section>
  );
}

import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
} from "recharts";


// ==================================================
// Component Props
// ==================================================
// Composite ThreatAtlas risk score.
// ==================================================

type RiskGaugeProps = {

  score: number;
};


// ==================================================
// Risk Threshold Labels
// ==================================================
// Maps risk score ranges to severity labels.
// ==================================================

const getRiskLabel = (

  score: number,
): string => {

  if (score >= 80) {
    return "Critical";
  }

  if (score >= 60) {
    return "High";
  }

  if (score >= 30) {
    return "Medium";
  }

  return "Low";
};


// ==================================================
// Risk Badge Styles
// ==================================================
// Maps severity labels to UI styling.
// ==================================================

const riskStyles: Record<string, string> = {

  Low:
    "bg-emerald-100 text-emerald-800",

  Medium:
    "bg-amber-100 text-amber-800",

  High:
    "bg-orange-100 text-orange-800",

  Critical:
    "bg-red-100 text-red-800",
};


// ==================================================
// Risk Gauge
// ==================================================
// Visualizes:
// - composite system risk
// - evaluation severity
// - overall AI security posture
// ==================================================

export default function RiskGauge({

  score,
}: RiskGaugeProps) {


  // --------------------------------------------------
  // Normalize score to valid range.
  // --------------------------------------------------

  const safeScore = Math.max(
    0,
    Math.min(100, score),
  );


  // --------------------------------------------------
  // Determine severity label.
  // --------------------------------------------------

  const riskLabel = getRiskLabel(
    safeScore,
  );


  // --------------------------------------------------
  // Chart data.
  // --------------------------------------------------

  const data = [

    {
      name: "Risk",
      value: safeScore,
    },

    {
      name: "Remaining",
      value: 100 - safeScore,
    },
  ];


  return (

    <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">


      {/* ========================================== */}
      {/* Header */}
      {/* ========================================== */}

      <div className="flex items-center justify-between">

        <div>

          <h2 className="text-lg font-semibold text-slate-950">
            Risk Gauge
          </h2>

          <p className="mt-1 text-sm text-slate-500">
            Composite evaluation risk
          </p>

        </div>


        {/* Risk Badge */}

        <span
          className={`rounded-full px-3 py-1 text-sm font-semibold ${
            riskStyles[riskLabel]
          }`}
        >
          {riskLabel}
        </span>

      </div>


      {/* ========================================== */}
      {/* Risk Visualization */}
      {/* ========================================== */}

      <div className="mt-4 flex flex-col items-center justify-center">

        <div className="h-52 w-full">

          <ResponsiveContainer
            width="100%"
            height="100%"
          >

            <PieChart>

              <Pie
                data={data}
                dataKey="value"
                startAngle={210}
                endAngle={-30}
                innerRadius="68%"
                outerRadius="90%"
              >

                {/* Risk Segment */}

                <Cell fill="#f59e0b" />


                {/* Remaining Segment */}

                <Cell fill="#e2e8f0" />

              </Pie>

            </PieChart>

          </ResponsiveContainer>

        </div>


        {/* Numeric Risk Score */}

        <div className="-mt-8 text-center">

          <p className="text-3xl font-bold text-slate-950">
            {safeScore}
          </p>

          <p className="text-sm text-slate-500">
            Risk Score
          </p>

        </div>

      </div>

    </section>
  );
}

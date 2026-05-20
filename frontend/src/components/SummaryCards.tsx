import type {
  EvaluationSummary,
} from "../services/api";


// ==================================================
// Component Props
// ==================================================
// High-level ThreatAtlas evaluation metrics.
// ==================================================

type SummaryCardsProps = {

  summary: EvaluationSummary;
};


// ==================================================
// Summary Card Configuration
// ==================================================
// Defines:
// - metric key
// - display label
// - formatting suffix
// ==================================================

const cards = [

  {
    key: "pass_rate",
    label: "Pass Rate",
    suffix: "%",
  },

  {
    key: "fail_rate",
    label: "Fail Rate",
    suffix: "%",
  },

  {
    key: "risk_score",
    label: "Risk Score",
    suffix: "",
  },

  {
    key: "authorization_failures",
    label: "Authorization Failures",
    suffix: "",
  },

] as const;


// ==================================================
// Metric Color Styles
// ==================================================
// Visual emphasis for important metrics.
// ==================================================

const metricStyles: Record<string, string> = {

  pass_rate:
    "text-emerald-600",

  fail_rate:
    "text-red-600",

  risk_score:
    "text-amber-600",

  authorization_failures:
    "text-orange-600",
};


// ==================================================
// Summary Cards
// ==================================================
// Displays:
// - pass/fail metrics
// - risk score
// - authorization failures
// - high-level system health
// ==================================================

export default function SummaryCards({

  summary,
}: SummaryCardsProps) {


  return (

    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">


      {cards.map((card) => (

        <article
          key={card.key}
          className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm transition hover:shadow-md"
        >


          {/* -------------------------------------- */}
          {/* Metric Label */}
          {/* -------------------------------------- */}

          <p className="text-sm font-medium text-slate-500">
            {card.label}
          </p>


          {/* -------------------------------------- */}
          {/* Metric Value */}
          {/* -------------------------------------- */}

          <p
            className={`mt-3 text-3xl font-semibold ${
              metricStyles[card.key]
              ?? "text-slate-950"
            }`}
          >

            {summary[card.key]}

            {card.suffix}

          </p>

        </article>
      ))}

    </section>
  );
}

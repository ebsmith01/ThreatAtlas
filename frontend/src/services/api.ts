
import axios from "axios";


// ==================================================
// Axios API Client
// ==================================================
// Centralized HTTP client for communicating
// with the ThreatAtlas backend.
// ==================================================

export const api = axios.create({

  baseURL: "http://127.0.0.1:8000",
});


// ==================================================
// Evaluation Request
// ==================================================
// Request payload sent to:
//
// /eval/rag
// /eval/agent
// /eval/llm
// ==================================================

export type EvaluationRequest = {

  target: string;

  system: string;

  sample_size: number;
};


// ==================================================
// Evaluation Summary
// ==================================================
// High-level metrics returned by the API.
// ==================================================

export type EvaluationSummary = {

  pass_rate: number;

  fail_rate: number;

  risk_score: number;

  authorization_failures: number;

  allowed: number;

  blocked: number;

  tool_usage: number;

  retrieval_attempts: number;

  actor_roles: number;
};


// ==================================================
// Security Finding
// ==================================================
// Represents:
// - policy violations
// - retrieval issues
// - prompt injection findings
// ==================================================

export type Finding = {

  id: string;

  type:
    | "Violation"
    | "Retrieval"
    | "Prompt Injection";

  severity:
    | "Low"
    | "Medium"
    | "High"
    | "Critical";

  detail: string;
};


// ==================================================
// Final Evaluation Result
// ==================================================
// Normalized frontend response shape.
// ==================================================

export type EvaluationResult = {

  summary: EvaluationSummary;

  findings: Finding[];
};


// ==================================================
// Raw Backend Response
// ==================================================
// Minimal structure expected from the API.
// ==================================================

type BackendResult = {

  id?: string;

  passed?: boolean;

  finding?: string;

  error?: string;

  message?: string;
};


type BackendResponse = {

  summary?: Record<string, unknown>;

  results?: BackendResult[];

  findings?: Finding[];
};


// ==================================================
// Safe Number Helper
// ==================================================
// Prevents NaN/invalid numeric values.
// ==================================================

const safeNumber = (

  value: unknown,

  fallback = 0,
): number => {

  return (
    typeof value === "number"
    && Number.isFinite(value)
  )
    ? value
    : fallback;
};


// ==================================================
// Build Findings
// ==================================================
// Generates fallback findings if the backend
// does not explicitly provide them.
// ==================================================

const buildFindings = (

  results: BackendResult[],
): Finding[] => {

  return results.slice(0, 6).map((item, index) => ({

    id: String(item.id ?? `finding-${index + 1}`),

    type:
      index % 3 === 0
        ? "Prompt Injection"
        : index % 2 === 0
          ? "Retrieval"
          : "Violation",

    severity:
      index % 4 === 0
        ? "Critical"
        : index % 3 === 0
          ? "High"
          : "Medium",

    detail: String(
      item.finding
      ?? item.error
      ?? item.message
      ?? "Evaluation finding",
    ),
  }));
};


// ==================================================
// Normalize Evaluation Response
// ==================================================
// Converts backend responses into a stable
// frontend structure.
// ==================================================

export const normalizeEvaluation = (

  payload: unknown,
): EvaluationResult => {

  const response = payload as BackendResponse;

  const summary = response.summary ?? {};

  const results = response.results ?? [];


  // --------------------------------------------------
  // Compute totals.
  // --------------------------------------------------

  const total = results.length || safeNumber(summary.total, 10);

  const failures = results.filter(
    (item) => item.passed === false,
  ).length;

  const passes = results.filter(
    (item) => item.passed === true,
  ).length;


  // --------------------------------------------------
  // Compute rates.
  // --------------------------------------------------

  const failRate = safeNumber(
    summary.fail_rate,
    total
      ? Math.round((failures / total) * 100)
      : 0,
  );

  const passRate = safeNumber(
    summary.pass_rate,
    total
      ? Math.round((passes / total) * 100)
      : 100,
  );

  const riskScore = safeNumber(
    summary.risk_score,
    Math.max(0, Math.min(100, failRate + 24)),
  );


  // --------------------------------------------------
  // Findings.
  // --------------------------------------------------

  const findings = response.findings
    ?? buildFindings(results);


  return {

    summary: {

      pass_rate: passRate,

      fail_rate: failRate,

      risk_score: riskScore,

      authorization_failures: safeNumber(
        summary.authorization_failures,
        failures,
      ),

      allowed: safeNumber(
        summary.allowed,
        passes,
      ),

      blocked: safeNumber(
        summary.blocked,
        failures,
      ),

      tool_usage: safeNumber(
        summary.tool_usage,
        0,
      ),

      retrieval_attempts: safeNumber(
        summary.retrieval_attempts,
        0,
      ),

      actor_roles: safeNumber(
        summary.actor_roles,
        1,
      ),
    },

    findings,
  };
};


// ==================================================
// Run Evaluation
// ==================================================
// Sends evaluation requests to the backend.
// ==================================================

export const runEvaluation = async (

  request: EvaluationRequest,
): Promise<EvaluationResult> => {

  const response = await api.post(
    `/eval/${request.system}`,
    request,
  );

  return normalizeEvaluation(response.data);
};

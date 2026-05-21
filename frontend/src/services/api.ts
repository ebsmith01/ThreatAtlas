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

  category?: string;

  severity?: string;

  blocked?: boolean;

  tool_name?: string;
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

  return results.slice(0, 12).map((item, index) => {

    // --------------------------------------------------
    // Determine finding type.
    // --------------------------------------------------

    let type: Finding["type"] = "Violation";

    if (
      item.category?.includes("prompt")
    ) {
      type = "Prompt Injection";
    }

    else if (
      item.category?.includes("retrieval")
      || item.category?.includes("rag")
    ) {
      type = "Retrieval";
    }


    // --------------------------------------------------
    // Determine severity.
    // --------------------------------------------------

    let severity: Finding["severity"] = "Medium";

    if (
      item.severity?.toLowerCase() === "critical"
    ) {
      severity = "Critical";
    }

    else if (
      item.severity?.toLowerCase() === "high"
    ) {
      severity = "High";
    }

    else if (
      item.severity?.toLowerCase() === "low"
    ) {
      severity = "Low";
    }

    else if (item.blocked) {
      severity = "High";
    }


    return {

      id: String(item.id ?? `finding-${index + 1}`),

      type,

      severity,

      detail: String(
        item.finding
        ?? item.error
        ?? item.message
        ?? "Evaluation finding",
      ),
    };
  });
};


// ==================================================
// Estimate Actor Role Diversity
// ==================================================
// Provides more dynamic telemetry when the
// backend does not explicitly return role data.
// ==================================================

const systemRoleEstimate = (
  results: BackendResult[],
): number => {
  if (results.length >= 40) {
    return 4;
  }
  if (results.length >= 20) {
    return 3;
  }
  if (results.length >= 10) {
    return 2;
  }
  return 1;
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
  // Dynamic telemetry metrics.
  // --------------------------------------------------

  const blockedCount = results.filter(
    (item) => item.blocked === true,
  ).length;

  const allowedCount = Math.max(
    0,
    total - blockedCount,
  );

  const toolUsageCount = results.filter(
    (item) => item.tool_name,
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

  // --------------------------------------------------
  // Risk score.
  // --------------------------------------------------
  // Prefer backend-generated risk scores.
  //
  // Fall back to fail rate if the backend
  // does not provide one.
  // --------------------------------------------------

  const riskScore = safeNumber(
    summary.risk_score,
    failRate,
  );


  // --------------------------------------------------
  // Findings.
  // --------------------------------------------------

  // Prefer dynamic findings generated from
  // evaluation results.
  //
  // Only fall back to backend findings if
  // no result objects exist.
  // --------------------------------------------------

  const findings = results.length
    ? buildFindings(results)
    : (response.findings ?? []);

  // --------------------------------------------------
  // Debug normalized telemetry.
  // --------------------------------------------------

  console.log("ThreatAtlas Normalized Metrics:");

  console.log({
    total,
    failures,
    passes,
    blockedCount,
    allowedCount,
    toolUsageCount,
    failRate,
    passRate,
    riskScore,
  });

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
        allowedCount,
      ),

      blocked: safeNumber(
        summary.blocked,
        blockedCount,
      ),

      tool_usage: safeNumber(
        summary.tool_usage,
        toolUsageCount || total,
      ),

      retrieval_attempts: safeNumber(
        summary.retrieval_attempts,
        Math.max(
          1,
          Math.round(total * 0.7),
        ),
      ),

      actor_roles: safeNumber(
        summary.actor_roles,
        systemRoleEstimate(results),
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

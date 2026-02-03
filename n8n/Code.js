// === Inputs ===
const ollama = $json; // Ollama response
const webhookEnvelope = $items("Webhook")[0].json; // Webhook node output (rename if needed)
const alert = webhookEnvelope.body ?? webhookEnvelope; // Wazuh payload
// === Helper: parse LLM JSON ===
const llmText = ollama.message?.content?.trim() ?? "";
function extractJsonObject(text) {
  if (!text) return null;
  const s = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (s === -1 || e === -1 || e <= s) return null;
  try { return JSON.parse(text.slice(s, e + 1)); } catch { return null; }
}

let parsed;
try { parsed = JSON.parse(llmText); } catch { parsed = extractJsonObject(llmText); }

if (!parsed || typeof parsed !== "object") {
  parsed = {
    verdict: "suspicious",
    risk_score: 50,
    matched_indicators: [],
    evidence: [],
    reasons: ["LLM output was not valid JSON", "Manual review required"],
    recommended_action: "review",
    next_steps: ["Inspect outbound destinations", "Review user intent & data sensitivity"]
  };
}
// === Normalize ===
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
parsed.risk_score = clamp(Math.round(Number(parsed.risk_score) || 50), 0, 100);

if (!["benign","suspicious","high_risk"].includes(parsed.verdict)) parsed.verdict = "suspicious";
if (!["ignore","review","alert"].includes(parsed.recommended_action)) parsed.recommended_action = "review";

if (!Array.isArray(parsed.matched_indicators)) parsed.matched_indicators = [];
if (!Array.isArray(parsed.evidence)) parsed.evidence = [];
if (!Array.isArray(parsed.reasons)) parsed.reasons = [];
if (!Array.isArray(parsed.next_steps)) parsed.next_steps = [];

parsed.matched_indicators = parsed.matched_indicators.map(x => String(x).slice(0,60)).slice(0,12);
parsed.evidence = parsed.evidence.map(x => String(x).slice(0,200)).slice(0,5);
parsed.reasons = parsed.reasons.map(x => String(x).replace(/\s+/g," ").slice(0,220)).slice(0,6);
parsed.next_steps = parsed.next_steps.map(x => String(x).replace(/\s+/g," ").slice(0,220)).slice(0,6);

// === Context from Wazuh alert ===
const agentName = alert.agent?.name || alert.agent?.id || "unknown";
const agentIp = alert.agent?.ip || "unknown";
const ruleId = String(alert.rule?.id || alert.rule_id || "unknown");
const ruleDesc = alert.rule?.description || alert.rule_description || "";

const fullLog = String(alert.full_log || "");
const lower = fullLog.toLowerCase();

// === Extract inner event from stdout ===
function parseInnerEvent(fullLogLine) {
  if (!fullLogLine) return null;

  let s = fullLogLine.indexOf("stdout F ");
  if (s === -1) s = fullLogLine.indexOf("stdout ");
  if (s === -1) return null;

  const after = fullLogLine.slice(s);
  const firstBrace = after.indexOf("{");
  const lastBrace = after.lastIndexOf("}");
  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) return null;

  const rawObj = after.slice(firstBrace, lastBrace + 1);

  try { return JSON.parse(rawObj); } catch {}

  try {
    const unescaped = rawObj.replace(/\\"/g, '"').replace(/\\n/g, "\\n");
    return JSON.parse(unescaped);
  } catch {}

  try {
    const loose = rawObj.replace(/\\"/g, '"').replace(/\\n/g, "\n");
    return JSON.parse(loose);
  } catch {}

  return null;
}

const eventObj = parseInnerEvent(fullLog);

const eventType = eventObj?.event_type || "unknown";
const lang = eventObj?.lang || "";
let codeRaw = eventObj?.code || "";

// === Format code for Slack ===
if (typeof codeRaw === "string") {
  codeRaw = codeRaw
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t");
}

function truncateKeepLines(text, maxChars = 1400) {
  if (!text) return "";
  if (text.length <= maxChars) return text;
  const cut = text.slice(0, maxChars);
  const lastNl = cut.lastIndexOf("\n");
  return (lastNl > 200 ? cut.slice(0, lastNl) : cut) + "\n... (truncated)";
}

const codePretty = truncateKeepLines(String(codeRaw || ""), 1400);

// === Backup keyword indicators ===
const KEYWORDS = [
  "curl","wget","rclone","rsync","scp","sftp","gsutil","azcopy","gdrive",
  "pydrive","googleapiclient","google.cloud","boto3","azure.storage",
  "zipfile","tarfile","make_archive","base64","gpg","openssl","cryptography",
  "google_application_credentials","aws_access_key_id","aws_secret_access_key","service_account","api_key","access_token",
  "upload","post","put","to_csv","to_parquet","to_json",
  "requests.post","requests.put","requests.patch","httpx.post","httpx.put","urllib.request"
];

const found = [];
for (const k of KEYWORDS) if (lower.includes(k)) found.push(k);
if (parsed.matched_indicators.length === 0 && found.length) parsed.matched_indicators = found.slice(0, 10);

// === Ensure evidence & reasons ===
if (parsed.evidence.length === 0) {
  if (found.length) {
    const idx = lower.indexOf(found[0]);
    const start = Math.max(0, idx - 60);
    const end = Math.min(fullLog.length, idx + 160);
    parsed.evidence = [fullLog.slice(start, end)];
  } else {
    parsed.evidence = [fullLog.slice(0, 180)];
  }
}

if (parsed.reasons.length < 2) {
  const auto = [];
  if (ruleDesc) auto.push(`Triggered rule: ${ruleDesc}`);
  if (parsed.matched_indicators.length) auto.push(`Indicators present: ${parsed.matched_indicators.slice(0,6).join(", ")}`);
  auto.push("Data-sensitive org: export/transfer attempts treated as high risk by policy.");
  parsed.reasons = [...parsed.reasons, ...auto].slice(0, 5);
}

// === Policy floor by rule_id ===
const minByRule = {
  "100501": 90,
  "100506": 90,
  "100505": 85,
  "100504": 98,
  "100502": 80,
  "100503": 75
};

const policyMin = minByRule[ruleId] ?? 0;
parsed.risk_score = Math.max(parsed.risk_score, policyMin);

if (parsed.risk_score >= 85) parsed.verdict = "high_risk";
else if (parsed.risk_score >= 60) parsed.verdict = "suspicious";
else parsed.verdict = "benign";

// === Build Slack text ===
const indicatorsText = parsed.matched_indicators.length ? parsed.matched_indicators.join(", ") : "-";
const evidenceText = parsed.evidence.length ? parsed.evidence.slice(0,2).join(" | ") : "-";
const reasonsText = parsed.reasons.length ? parsed.reasons.join(" | ") : "-";
const nextStepsText = parsed.next_steps.length ? parsed.next_steps.slice(0,3).map(x => `• ${x}`).join("\n") : "-";

const fallbackSnippet = truncateKeepLines(fullLog, 900);

const codeBlock = codePretty
  ? `\`\`\`\n${codePretty}\n\`\`\``
  : `\`\`\`\n${fallbackSnippet}\n\`\`\``;

const codeTitle = codePretty
  ? `*Code (event_type=${eventType}${lang ? `, lang=${lang}` : ""}):*`
  : "*Log snippet:*";

const slack_text =
  `🚨 *JupyterHub Risk Alert*\n` +
  `*Verdict:* ${parsed.verdict} | *Score:* ${parsed.risk_score}${policyMin ? ` (policy floor: ${policyMin})` : ""}\n` +
  `*Agent:* ${agentName} (${agentIp})\n` +
  `*Rule:* ${ruleId}${ruleDesc ? " - " + ruleDesc : ""}\n` +
  `*Indicators:* ${indicatorsText}\n` +
  `*Evidence:* ${evidenceText}\n` +
  `*Reasons:* ${reasonsText}\n` +
  `*Next steps:*\n${nextStepsText}\n` +
  `${codeTitle}\n${codeBlock}`;

// === Output ===
return [{
  json: {
    verdict: parsed.verdict,
    risk_score: parsed.risk_score,
    matched_indicators: parsed.matched_indicators,
    evidence: parsed.evidence,
    reasons: parsed.reasons,
    recommended_action: parsed.recommended_action,
    next_steps: parsed.next_steps,
    agent: agentName,
    agent_ip: agentIp,
    rule_id: ruleId,
    rule_desc: ruleDesc,
    event_type: eventType,
    lang,
    code_pretty: codePretty,
    slack_text
  }
}];

export interface Verdict {
  session_id: string; sensor_id: string; src_ip: string; started_at: string; ended_at: string;
  actor: string; intent: string; severity: "low" | "medium" | "high" | "critical";
  escalate: boolean; confidence: number | null; source: "jev" | "cache" | "rules"; model: string | null;
}

export const ACTOR_LABEL: Record<string, string> = {
  scanner: "Scanner", credential_bruteforcer: "Password guesser", bot_dropper: "Malware bot",
  exploit_attempt: "Exploit attempt", interactive_human: "Hands-on human", research_crawler: "Research crawler",
};
export const INTENT_LABEL: Record<string, string> = {
  recon: "Recon", credential_access: "Credential access", exploitation: "Exploitation",
  malware_install: "Malware install", cryptomining: "Cryptomining", botnet_recruit: "Botnet recruitment",
  persistence: "Persistence", lateral_prep: "Lateral movement prep", unknown: "Unclear",
};
export const SOURCE_LABEL = { jev: "Jev model", cache: "Jev (cached)", rules: "Rules" } as const;

/** Severity pill: text carries the meaning, colour only reinforces it. */
export function SeverityBadge({ v }: { v: Pick<Verdict, "severity" | "escalate"> }) {
  return (
    <span className="row" style={{ gap: 4, flexWrap: "nowrap" }}>
      <span className={`badge sev-${v.severity}`}>{v.severity}</span>
      {v.escalate && <span className="badge sev-escalate" title="The model flagged this session for an analyst">review</span>}
    </span>
  );
}

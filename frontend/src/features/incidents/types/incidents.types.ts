export type IncidentStatus = "open" | "mitigated" | "false_positive" | "ignored";
export type IncidentAttackType =
  | "ddos"
  | "port_scan"
  | "bruteforce"
  | "api_enum"
  | "malware"
  | "unknown";
export type IncidentProtocol = "tcp" | "udp" | "icmp" | "other";

export interface AttackIncident {
  id: string;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
  title: string;
  attack_type: IncidentAttackType;
  severity: number;
  confidence?: number | null;
  status: IncidentStatus;
  source_ip: string;
  source_port?: number | null;
  dest_ip: string;
  dest_port?: number | null;
  protocol?: IncidentProtocol | "";
  asset?: string;
  tags: string[];
  evidence: Record<string, unknown>;
  summary?: string;
  action_taken?: string;
  external_refs: Record<string, unknown>;
  jira_issue_key?: string | null;
  jira_issue_url?: string | null;
  jira_created_at?: string | null;
  last_jira_error?: string | null;
}

export interface IncidentListParams {
  status?: IncidentStatus;
  attack_type?: IncidentAttackType;
  min_severity?: number;
  q?: string;
  ordering?: string;
}

export interface IncidentCreatePayload {
  title: string;
  attack_type: IncidentAttackType;
  severity: number;
  status: IncidentStatus;
  source_ip: string;
  dest_ip: string;
  dest_port?: number | null;
  protocol?: IncidentProtocol | "";
  first_seen_at?: string;
  last_seen_at?: string;
  summary: string;
}

export type IncidentUpdatePayload = Partial<IncidentCreatePayload> & {
  status?: IncidentStatus;
};

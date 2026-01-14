import type { FormEvent } from "react";

import type {
  IncidentAttackType,
  IncidentProtocol,
  IncidentStatus,
} from "@/features/incidents/types/incidents.types";

export type NewIncidentFormValues = {
  title: string;
  summary: string;
  attack_type: IncidentAttackType;
  severity: string;
  status: IncidentStatus;
  source_ip: string;
  dest_ip: string;
  dest_port: string;
  protocol: IncidentProtocol | "";
  first_seen_at: string;
  last_seen_at: string;
};

type NewIncidentFormProps = {
  form: NewIncidentFormValues;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onChange: (nextForm: NewIncidentFormValues) => void;
};

export default function NewIncidentForm({ form, onSubmit, onChange }: NewIncidentFormProps) {
  return (
    <details className="new-incident" open>
      <summary>New incident</summary>
      <form onSubmit={onSubmit} className="incident-form">
        <label>
          Summary title
          <input
            type="text"
            value={form.title}
            onChange={(event) => onChange({ ...form, title: event.target.value })}
            required
          />
        </label>
        <label className="span-2">
          Summary description
          <textarea
            value={form.summary}
            onChange={(event) => onChange({ ...form, summary: event.target.value })}
            placeholder="LLM summary or analyst notes"
            rows={4}
            required
          />
        </label>
        <label>
          Attack type
          <select
            value={form.attack_type}
            onChange={(event) =>
              onChange({ ...form, attack_type: event.target.value as IncidentAttackType })
            }
          >
            <option value="ddos">ddos</option>
            <option value="port_scan">port_scan</option>
            <option value="bruteforce">bruteforce</option>
            <option value="api_enum">api_enum</option>
            <option value="malware">malware</option>
            <option value="unknown">unknown</option>
          </select>
        </label>
        <label>
          Severity
          <input
            type="number"
            min="0"
            max="100"
            value={form.severity}
            onChange={(event) => onChange({ ...form, severity: event.target.value })}
            required
          />
        </label>
        <label>
          Status
          <select
            value={form.status}
            onChange={(event) =>
              onChange({ ...form, status: event.target.value as IncidentStatus })
            }
          >
            <option value="open">open</option>
            <option value="mitigated">mitigated</option>
            <option value="false_positive">false_positive</option>
            <option value="ignored">ignored</option>
          </select>
        </label>
        <label>
          Source IP
          <input
            type="text"
            value={form.source_ip}
            onChange={(event) => onChange({ ...form, source_ip: event.target.value })}
            required
          />
        </label>
        <label>
          Destination IP
          <input
            type="text"
            value={form.dest_ip}
            onChange={(event) => onChange({ ...form, dest_ip: event.target.value })}
            required
          />
        </label>
        <label>
          Destination port
          <input
            type="number"
            min="1"
            max="65535"
            value={form.dest_port}
            onChange={(event) => onChange({ ...form, dest_port: event.target.value })}
            placeholder="Optional"
          />
        </label>
        <label>
          Protocol
          <select
            value={form.protocol}
            onChange={(event) =>
              onChange({ ...form, protocol: event.target.value as IncidentProtocol })
            }
          >
            <option value="">(optional)</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
            <option value="other">other</option>
          </select>
        </label>
        <label>
          First seen at
          <input
            type="datetime-local"
            value={form.first_seen_at}
            onChange={(event) => onChange({ ...form, first_seen_at: event.target.value })}
          />
        </label>
        <label>
          Last seen at
          <input
            type="datetime-local"
            value={form.last_seen_at}
            onChange={(event) => onChange({ ...form, last_seen_at: event.target.value })}
          />
        </label>
        <div className="form-actions">
          <button type="submit" className="button primary">
            Create incident
          </button>
        </div>
      </form>
    </details>
  );
}

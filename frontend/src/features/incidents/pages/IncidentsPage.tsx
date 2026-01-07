import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";

import type {
  AttackIncident,
  IncidentAttackType,
  IncidentListParams,
  IncidentProtocol,
  IncidentStatus,
} from "../types/incidents.types";
import { createIncident, deleteIncident, listIncidents } from "../api/incidents.api";

type NewIncidentForm = {
  title: string;
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

const nowInputValue = () => new Date().toISOString().slice(0, 16);

const defaultForm = (): NewIncidentForm => ({
  title: "",
  attack_type: "port_scan",
  severity: "50",
  status: "open",
  source_ip: "203.0.113.5",
  dest_ip: "10.0.0.5",
  dest_port: "",
  protocol: "tcp",
  first_seen_at: nowInputValue(),
  last_seen_at: nowInputValue(),
});

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<AttackIncident[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [minSeverity, setMinSeverity] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [form, setForm] = useState<NewIncidentForm>(defaultForm());

  const queryParams = useMemo<IncidentListParams>(() => {
    const params: IncidentListParams = { ordering: "-last_seen_at" };
    if (statusFilter !== "all") {
      params.status = statusFilter as IncidentStatus;
    }
    if (typeFilter !== "all") {
      params.attack_type = typeFilter as IncidentAttackType;
    }
    if (minSeverity) {
      const parsed = Number(minSeverity);
      if (!Number.isNaN(parsed)) {
        params.min_severity = parsed;
      }
    }
    if (searchQuery) {
      params.q = searchQuery;
    }
    return params;
  }, [statusFilter, typeFilter, minSeverity, searchQuery]);

  const loadIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listIncidents(queryParams);
      setIncidents(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load incidents.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [queryParams]);

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this incident?")) {
      return;
    }
    try {
      await deleteIncident(id);
      await loadIncidents();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete incident.");
    }
  };

  const handleCreate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    const now = new Date().toISOString();
    const firstSeen = form.first_seen_at ? new Date(form.first_seen_at).toISOString() : now;
    const lastSeen = form.last_seen_at ? new Date(form.last_seen_at).toISOString() : firstSeen;
    const severityValue = Number(form.severity);
    try {
      await createIncident({
        title: form.title,
        attack_type: form.attack_type,
        severity: Number.isNaN(severityValue) ? 0 : severityValue,
        status: form.status,
        source_ip: form.source_ip,
        dest_ip: form.dest_ip,
        dest_port: form.dest_port ? Number(form.dest_port) : null,
        protocol: form.protocol || "",
        first_seen_at: firstSeen,
        last_seen_at: lastSeen,
      });
      setForm(defaultForm());
      await loadIncidents();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create incident.");
    }
  };

  return (
    <div className="incidents-page">
      <header className="incidents-header">
        <div>
          <h2>Incidents</h2>
          <p className="subtle">Detected attacks and security incidents.</p>
        </div>
        <button type="button" className="button" onClick={loadIncidents}>
          Refresh
        </button>
      </header>

      <section className="filters">
        <label>
          Status
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="mitigated">Mitigated</option>
            <option value="false_positive">False positive</option>
            <option value="ignored">Ignored</option>
          </select>
        </label>
        <label>
          Attack type
          <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            <option value="all">All</option>
            <option value="ddos">ddos</option>
            <option value="port_scan">port_scan</option>
            <option value="bruteforce">bruteforce</option>
            <option value="malware">malware</option>
            <option value="unknown">unknown</option>
          </select>
        </label>
        <label>
          Min severity
          <input
            type="number"
            min="0"
            max="100"
            value={minSeverity}
            onChange={(event) => setMinSeverity(event.target.value)}
            placeholder="0"
          />
        </label>
        <label className="filters-search">
          Search
          <input
            type="search"
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Title, IP, asset..."
          />
        </label>
      </section>

      <details className="new-incident" open>
        <summary>New incident</summary>
        <form onSubmit={handleCreate} className="incident-form">
          <label>
            Title
            <input
              type="text"
              value={form.title}
              onChange={(event) => setForm({ ...form, title: event.target.value })}
              required
            />
          </label>
          <label>
            Attack type
            <select
              value={form.attack_type}
              onChange={(event) =>
                setForm({ ...form, attack_type: event.target.value as IncidentAttackType })
              }
            >
              <option value="ddos">ddos</option>
              <option value="port_scan">port_scan</option>
              <option value="bruteforce">bruteforce</option>
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
              onChange={(event) => setForm({ ...form, severity: event.target.value })}
              required
            />
          </label>
          <label>
            Status
            <select
              value={form.status}
              onChange={(event) => setForm({ ...form, status: event.target.value as IncidentStatus })}
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
              onChange={(event) => setForm({ ...form, source_ip: event.target.value })}
              required
            />
          </label>
          <label>
            Destination IP
            <input
              type="text"
              value={form.dest_ip}
              onChange={(event) => setForm({ ...form, dest_ip: event.target.value })}
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
              onChange={(event) => setForm({ ...form, dest_port: event.target.value })}
              placeholder="Optional"
            />
          </label>
          <label>
            Protocol
            <select
              value={form.protocol}
              onChange={(event) =>
                setForm({ ...form, protocol: event.target.value as IncidentProtocol })
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
              onChange={(event) => setForm({ ...form, first_seen_at: event.target.value })}
            />
          </label>
          <label>
            Last seen at
            <input
              type="datetime-local"
              value={form.last_seen_at}
              onChange={(event) => setForm({ ...form, last_seen_at: event.target.value })}
            />
          </label>
          <div className="form-actions">
            <button type="submit" className="button primary">
              Create incident
            </button>
          </div>
        </form>
      </details>

      {loading && <p className="status">Loading incidents...</p>}
      {error && <p className="status error">{error}</p>}

      {!loading && !error && incidents.length === 0 && (
        <p className="status empty">No incidents found.</p>
      )}

      {!loading && incidents.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Last seen</th>
                <th>Title</th>
                <th>Attack type</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id}>
                  <td>{new Date(incident.last_seen_at).toLocaleString()}</td>
                  <td>{incident.title}</td>
                  <td>{incident.attack_type}</td>
                  <td>{incident.severity}</td>
                  <td>{incident.status}</td>
                  <td>{incident.source_ip}</td>
                  <td>
                    {incident.dest_ip}
                    {incident.dest_port ? `:${incident.dest_port}` : ""}
                  </td>
                  <td>{incident.protocol || "-"}</td>
                  <td>
                    <button
                      type="button"
                      className="button ghost"
                      onClick={() => handleDelete(incident.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

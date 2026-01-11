import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";

import type {
  AttackIncident,
  IncidentAttackType,
  IncidentListParams,
  IncidentStatus,
} from "@/features/incidents/types/incidents.types";
import {
  createIncident,
  createJiraTicket,
  deleteIncident,
  listIncidents,
  updateIncident,
} from "@/features/incidents/api/incidents.api";
import IncidentsFilters from "@/features/incidents/components/IncidentsFilters";
import IncidentsTable from "@/features/incidents/components/IncidentsTable";
import NewIncidentForm, {
  type NewIncidentFormValues,
} from "@/features/incidents/components/NewIncidentForm";

const nowInputValue = () => new Date().toISOString().slice(0, 16);

const defaultForm = (): NewIncidentFormValues => {
  const defaultAttackType: IncidentAttackType = "port_scan";
  const defaultSourceIp = "203.0.113.5";
  return {
    title: "",
    summary: "",
    attack_type: defaultAttackType,
    severity: "50",
    status: "open",
    source_ip: defaultSourceIp,
    dest_ip: "10.0.0.5",
    dest_port: "",
    protocol: "tcp",
    first_seen_at: nowInputValue(),
    last_seen_at: nowInputValue(),
  };
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<AttackIncident[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [minSeverity, setMinSeverity] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [form, setForm] = useState<NewIncidentFormValues>(defaultForm());

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
        summary: form.summary,
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

  const handleCreateJira = async (id: string) => {
    setError(null);
    try {
      await createJiraTicket(id);
      await loadIncidents();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create Jira ticket.");
    }
  };

  const handleStatusChange = async (id: string, nextStatus: IncidentStatus) => {
    const current = incidents.find((incident) => incident.id === id);
    if (!current || current.status === nextStatus) {
      return;
    }
    setError(null);
    try {
      const updated = await updateIncident(id, { status: nextStatus });
      setIncidents((prev) => {
        const nextList = prev.map((incident) => (incident.id === id ? updated : incident));
        if (statusFilter !== "all" && updated.status !== statusFilter) {
          return nextList.filter((incident) => incident.id !== id);
        }
        return nextList;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update status.");
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

      <IncidentsFilters
        statusFilter={statusFilter}
        typeFilter={typeFilter}
        minSeverity={minSeverity}
        searchQuery={searchQuery}
        onStatusChange={setStatusFilter}
        onTypeChange={setTypeFilter}
        onMinSeverityChange={setMinSeverity}
        onSearchChange={setSearchQuery}
      />

      <NewIncidentForm form={form} onSubmit={handleCreate} onChange={setForm} />

      {loading && <p className="status">Loading incidents...</p>}
      {error && <p className="status error">{error}</p>}

      {!loading && !error && incidents.length === 0 && (
        <p className="status empty">No incidents found.</p>
      )}

      {!loading && incidents.length > 0 && (
        <IncidentsTable
          incidents={incidents}
          onCreateJira={handleCreateJira}
          onDelete={handleDelete}
          onStatusChange={handleStatusChange}
        />
      )}
    </div>
  );
}

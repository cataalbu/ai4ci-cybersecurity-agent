import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { routes } from "@/app/config/routes";
import { getIncident, updateIncident } from "@/features/incidents/api/incidents.api";
import type { AttackIncident } from "@/features/incidents/types/incidents.types";

type IncidentDetailsState = {
  data: AttackIncident | null;
  loading: boolean;
  error: string | null;
};

const formatDateTime = (value?: string | null) => {
  if (!value) {
    return "-";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
};

export default function IncidentDetailsPage() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const [state, setState] = useState<IncidentDetailsState>({
    data: null,
    loading: true,
    error: null,
  });
  const [statusDraft, setStatusDraft] = useState<AttackIncident["status"] | "">("");
  const [statusSaving, setStatusSaving] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const loadIncident = async () => {
      if (!incidentId) {
        setState({ data: null, loading: false, error: "Missing incident id." });
        return;
      }
      setState((prev) => ({ ...prev, loading: true, error: null }));
      try {
        const data = await getIncident(incidentId);
        if (!cancelled) {
          setState({ data, loading: false, error: null });
          setStatusDraft(data.status);
        }
      } catch (err) {
        if (!cancelled) {
          setState({
            data: null,
            loading: false,
            error: err instanceof Error ? err.message : "Failed to load incident.",
          });
        }
      }
    };

    loadIncident();
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const tags = useMemo(() => state.data?.tags ?? [], [state.data]);
  const evidenceJson = useMemo(
    () => (state.data?.evidence ? JSON.stringify(state.data.evidence, null, 2) : "{}"),
    [state.data],
  );
  const externalRefsJson = useMemo(
    () => (state.data?.external_refs ? JSON.stringify(state.data.external_refs, null, 2) : "{}"),
    [state.data],
  );

  if (state.loading) {
    return <p className="status">Loading incident...</p>;
  }

  if (state.error) {
    return (
      <div className="incidents-page">
        <div className="detail-header">
          <div>
            <h2>Incident details</h2>
            <p className="subtle">{state.error}</p>
          </div>
          <Link to={routes.incidents} className="button secondary">
            Back to incidents
          </Link>
        </div>
      </div>
    );
  }

  if (!state.data) {
    return <p className="status empty">No incident data available.</p>;
  }

  const incident = state.data;
  const canSaveStatus = statusDraft && statusDraft !== incident.status && !statusSaving;

  const handleStatusSave = async () => {
    if (!canSaveStatus) {
      return;
    }
    setStatusSaving(true);
    setStatusError(null);
    try {
      const updated = await updateIncident(incident.id, {
        status: statusDraft as AttackIncident["status"],
      });
      setState((prev) => ({ ...prev, data: updated }));
      setStatusDraft(updated.status);
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : "Failed to update status.");
    } finally {
      setStatusSaving(false);
    }
  };

  return (
    <div className="incidents-page">
      <div className="detail-header">
        <div>
          <h2>{incident.title || "Incident details"}</h2>
          <p className="subtle">Full record for incident {incident.id}.</p>
        </div>
        <Link to={routes.incidents} className="button secondary">
          Back to incidents
        </Link>
      </div>

      <section className="detail-card">
        <h3>Summary</h3>
        <p className="detail-summary">{incident.summary || "No summary provided."}</p>
        {incident.action_taken && (
          <p className="detail-muted">Action taken: {incident.action_taken}</p>
        )}
      </section>

      <section className="details-grid">
        <div className="detail-card">
          <h3>Classification</h3>
          <div className="detail-list">
            <div>
              <span>Attack type</span>
              <strong>{incident.attack_type}</strong>
            </div>
            <div>
              <span>Status</span>
              <div className="detail-inline">
                <select
                  className="detail-select"
                  value={statusDraft}
                  onChange={(event) =>
                    setStatusDraft(event.target.value as AttackIncident["status"])
                  }
                >
                  <option value="open">open</option>
                  <option value="mitigated">mitigated</option>
                  <option value="false_positive">false positive</option>
                  <option value="ignored">ignored</option>
                </select>
                <button
                  type="button"
                  className="button secondary"
                  onClick={handleStatusSave}
                  disabled={!canSaveStatus}
                >
                  {statusSaving ? "Saving..." : "Save"}
                </button>
              </div>
              {statusError && <p className="status error">{statusError}</p>}
            </div>
            <div>
              <span>Severity</span>
              <strong>{incident.severity}</strong>
            </div>
            <div>
              <span>Confidence</span>
              <strong>{incident.confidence ?? "-"}</strong>
            </div>
          </div>
        </div>

        <div className="detail-card">
          <h3>Timeline</h3>
          <div className="detail-list">
            <div>
              <span>First seen</span>
              <strong>{formatDateTime(incident.first_seen_at)}</strong>
            </div>
            <div>
              <span>Last seen</span>
              <strong>{formatDateTime(incident.last_seen_at)}</strong>
            </div>
            <div>
              <span>Created</span>
              <strong>{formatDateTime(incident.created_at)}</strong>
            </div>
            <div>
              <span>Updated</span>
              <strong>{formatDateTime(incident.updated_at)}</strong>
            </div>
          </div>
        </div>

        <div className="detail-card">
          <h3>Network</h3>
          <div className="detail-list">
            <div>
              <span>Source</span>
              <strong>
                {incident.source_ip}
                {incident.source_port ? `:${incident.source_port}` : ""}
              </strong>
            </div>
            <div>
              <span>Destination</span>
              <strong>
                {incident.dest_ip}
                {incident.dest_port ? `:${incident.dest_port}` : ""}
              </strong>
            </div>
            <div>
              <span>Protocol</span>
              <strong>{incident.protocol || "-"}</strong>
            </div>
            <div>
              <span>Asset</span>
              <strong>{incident.asset || "-"}</strong>
            </div>
          </div>
        </div>

        <div className="detail-card">
          <h3>Jira</h3>
          <div className="detail-list">
            <div>
              <span>Issue key</span>
              <strong>{incident.jira_issue_key || "-"}</strong>
            </div>
            <div>
              <span>Created at</span>
              <strong>{formatDateTime(incident.jira_created_at)}</strong>
            </div>
            <div>
              <span>Last error</span>
              <strong>{incident.last_jira_error || "-"}</strong>
            </div>
          </div>
          {incident.jira_issue_url && (
            <div className="detail-card-actions">
              <a
                className="button secondary"
                href={incident.jira_issue_url}
                target="_blank"
                rel="noreferrer"
              >
                Open Jira
              </a>
            </div>
          )}
        </div>
      </section>

      <section className="detail-card">
        <h3>Tags</h3>
        {tags.length === 0 ? (
          <p className="detail-muted">No tags assigned.</p>
        ) : (
          <div className="detail-tags">
            {tags.map((tag) => (
              <span key={tag} className="detail-tag">
                {tag}
              </span>
            ))}
          </div>
        )}
      </section>

      <section className="detail-card">
        <h3>Evidence</h3>
        <pre className="detail-pre">{evidenceJson}</pre>
      </section>

      <section className="detail-card">
        <h3>External references</h3>
        <pre className="detail-pre">{externalRefsJson}</pre>
      </section>
    </div>
  );
}

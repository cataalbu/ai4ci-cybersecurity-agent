import { Link } from "react-router-dom";

import { routes } from "@/app/config/routes";
import type { AttackIncident } from "@/features/incidents/types/incidents.types";

type IncidentsTableProps = {
  incidents: AttackIncident[];
  onCreateJira: (id: string) => void;
  onDelete: (id: string) => void;
  onStatusChange: (id: string, nextStatus: AttackIncident["status"]) => void;
};

export default function IncidentsTable({
  incidents,
  onCreateJira,
  onDelete,
  onStatusChange,
}: IncidentsTableProps) {
  const statusOptions: AttackIncident["status"][] = [
    "open",
    "mitigated",
    "false_positive",
    "ignored",
  ];

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Summary title</th>
            <th>Attack type</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Last seen</th>
            <th>Jira</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id}>
              <td>
                <Link className="table-link" to={`${routes.incidents}/${incident.id}`}>
                  {incident.title}
                </Link>
              </td>
              <td>{incident.attack_type}</td>
              <td>{incident.severity}</td>
              <td>
                <select
                  className="table-select"
                  value={incident.status}
                  onChange={(event) =>
                    onStatusChange(incident.id, event.target.value as AttackIncident["status"])
                  }
                >
                  {statusOptions.map((status) => (
                    <option key={status} value={status}>
                      {status.replace("_", " ")}
                    </option>
                  ))}
                </select>
              </td>
              <td>{new Date(incident.last_seen_at).toLocaleString()}</td>
              <td>
                {incident.jira_issue_key ? (
                  incident.jira_issue_url ? (
                    <a
                      className="button ghost"
                      href={incident.jira_issue_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {incident.jira_issue_key || "Open Jira"}
                    </a>
                  ) : (
                    <button type="button" className="button secondary" disabled>
                      Jira Created
                    </button>
                  )
                ) : (
                  <button
                    type="button"
                    className="button secondary"
                    onClick={() => onCreateJira(incident.id)}
                  >
                    Create Jira
                  </button>
                )}
              </td>
              <td>
                <div className="table-actions">
                  <Link className="button secondary" to={`${routes.incidents}/${incident.id}`}>
                    Edit
                  </Link>
                  <button
                    type="button"
                    className="button ghost"
                    onClick={() => onDelete(incident.id)}
                  >
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

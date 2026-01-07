import { API_BASE_URL } from "../../../app/config/env";
import type {
  AttackIncident,
  IncidentCreatePayload,
  IncidentListParams,
} from "../types/incidents.types";

async function parseJson(response: Response) {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with ${response.status}`);
  }
  return response.json();
}

function buildQuery(params?: IncidentListParams) {
  const search = new URLSearchParams();
  if (!params) {
    return search.toString();
  }
  if (params.status) {
    search.set("status", params.status);
  }
  if (params.attack_type) {
    search.set("attack_type", params.attack_type);
  }
  if (params.min_severity !== undefined && params.min_severity !== null && params.min_severity !== 0) {
    search.set("min_severity", String(params.min_severity));
  }
  if (params.q) {
    search.set("q", params.q);
  }
  if (params.ordering) {
    search.set("ordering", params.ordering);
  }
  return search.toString();
}

export async function listIncidents(params?: IncidentListParams): Promise<AttackIncident[]> {
  const query = buildQuery(params);
  const url = `${API_BASE_URL}/api/incidents/${query ? `?${query}` : ""}`;
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const data = await parseJson(response);
  if (Array.isArray(data)) {
    return data;
  }
  if (data && Array.isArray((data as any).results)) {
    return (data as any).results;
  }
  return [];
}

export async function createIncident(payload: IncidentCreatePayload): Promise<AttackIncident> {
  const url = `${API_BASE_URL}/api/incidents/`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  return parseJson(response);
}

export async function deleteIncident(id: string): Promise<void> {
  const url = `${API_BASE_URL}/api/incidents/${id}/`;
  const response = await fetch(url, { method: "DELETE" });
  if (!response.ok && response.status !== 204) {
    const text = await response.text();
    throw new Error(text || `Delete failed with ${response.status}`);
  }
}

type IncidentsFiltersProps = {
  statusFilter: string;
  typeFilter: string;
  minSeverity: string;
  searchQuery: string;
  onStatusChange: (value: string) => void;
  onTypeChange: (value: string) => void;
  onMinSeverityChange: (value: string) => void;
  onSearchChange: (value: string) => void;
};

export default function IncidentsFilters({
  statusFilter,
  typeFilter,
  minSeverity,
  searchQuery,
  onStatusChange,
  onTypeChange,
  onMinSeverityChange,
  onSearchChange,
}: IncidentsFiltersProps) {
  return (
    <section className="filters">
      <label>
        Status
        <select value={statusFilter} onChange={(event) => onStatusChange(event.target.value)}>
          <option value="all">All</option>
          <option value="open">Open</option>
          <option value="mitigated">Mitigated</option>
          <option value="false_positive">False positive</option>
          <option value="ignored">Ignored</option>
        </select>
      </label>
      <label>
        Attack type
        <select value={typeFilter} onChange={(event) => onTypeChange(event.target.value)}>
          <option value="all">All</option>
          <option value="ddos">ddos</option>
          <option value="port_scan">port_scan</option>
          <option value="bruteforce">bruteforce</option>
          <option value="api_enum">api_enum</option>
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
          onChange={(event) => onMinSeverityChange(event.target.value)}
          placeholder="0"
        />
      </label>
      <label className="filters-search">
        Search
        <input
          type="search"
          value={searchQuery}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="Title, IP, asset..."
        />
      </label>
    </section>
  );
}

import { NavLink, Outlet } from "react-router-dom";

import { routes } from "@/app/config/routes";
import "@/app/App.css";

export default function AppLayout() {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="app-eyebrow">Cybersecurity Agent</p>
          <h1>Incident Console</h1>
        </div>
        <nav>
          <NavLink
            to={routes.incidents}
            className={({ isActive }) => (isActive ? "active" : "")}
          >
            Incidents
          </NavLink>
        </nav>
      </header>
      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
}

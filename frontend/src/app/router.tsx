import { createBrowserRouter, Navigate } from "react-router-dom";

import { routes } from "@/app/config/routes";
import AppLayout from "@/app/layouts/AppLayout";
import IncidentDetailsPage from "@/features/incidents/pages/IncidentDetailsPage";
import IncidentsPage from "@/features/incidents/pages/IncidentsPage";

const incidentsPath = routes.incidents.startsWith("/")
  ? routes.incidents.slice(1)
  : routes.incidents;
const incidentDetailsPath = routes.incidentDetails.startsWith("/")
  ? routes.incidentDetails.slice(1)
  : routes.incidentDetails;

const router = createBrowserRouter([
  {
    path: routes.root,
    element: <AppLayout />,
    children: [
      { index: true, element: <Navigate to={routes.incidents} replace /> },
      { path: incidentsPath, element: <IncidentsPage /> },
      { path: incidentDetailsPath, element: <IncidentDetailsPage /> },
    ],
  },
]);

export default router;

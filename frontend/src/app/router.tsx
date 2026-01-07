import { createBrowserRouter, Navigate } from "react-router-dom";

import { routes } from "./config/routes";
import AppLayout from "./layouts/AppLayout";
import IncidentsPage from "../features/incidents/pages/IncidentsPage";

const incidentsPath = routes.incidents.startsWith("/")
  ? routes.incidents.slice(1)
  : routes.incidents;

const router = createBrowserRouter([
  {
    path: routes.root,
    element: <AppLayout />,
    children: [
      { index: true, element: <Navigate to={routes.incidents} replace /> },
      { path: incidentsPath, element: <IncidentsPage /> },
    ],
  },
]);

export default router;

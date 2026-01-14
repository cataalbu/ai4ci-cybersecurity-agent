import type { ReactNode } from "react";

import QueryProvider from "@/app/providers/QueryProvider";
import ThemeProvider from "@/app/providers/ThemeProvider";

type AppProvidersProps = {
  children: ReactNode;
};

export default function AppProviders({ children }: AppProvidersProps) {
  return (
    <QueryProvider>
      <ThemeProvider>{children}</ThemeProvider>
    </QueryProvider>
  );
}

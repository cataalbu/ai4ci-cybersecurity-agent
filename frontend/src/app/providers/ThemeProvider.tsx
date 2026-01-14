import type { ReactNode } from "react";

type ThemeProviderProps = {
  children: ReactNode;
};

export default function ThemeProvider({ children }: ThemeProviderProps) {
  return <>{children}</>;
}

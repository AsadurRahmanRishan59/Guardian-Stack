"use client";

import * as React from "react";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import type { ThemeProviderProps as NextThemesProps } from "next-themes";

export function ThemeProvider({ children, ...props }: NextThemesProps) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>;
}

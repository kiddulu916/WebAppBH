"use client";

import { useEffect } from "react";
import { useUIStore } from "@/stores/ui";

export default function ThemeInit() {
  const theme = useUIStore((s) => s.theme);

  useEffect(() => {
    document.documentElement.classList.toggle("light", theme === "light");
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  return null;
}

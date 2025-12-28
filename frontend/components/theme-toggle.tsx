"use client";

import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <button
      onClick={() => setTheme(theme === "light" ? "dark" : "light")}
      aria-label="Toggle theme"
      className="
        p-2.5 rounded-xl
        transition-all duration-300 ease-in-out
        flex items-center justify-center
        backdrop-blur-xl
        bg-white/10 dark:bg-gray-800/20
        border border-white/20 dark:border-gray-700/40
        hover:bg-white/20 hover:dark:bg-gray-700/40
        hover:scale-105 shadow-sm hover:shadow-md
        text-gray-700 dark:text-gray-200
      "
    >
      {/* Light mode icon */}
      <Sun className="w-4 h-4 dark:hidden text-yellow-500 transition-all" />
      {/* Dark mode icon */}
      <Moon className="w-4 h-4 hidden dark:inline text-blue-400 transition-all" />
    </button>
  );
}

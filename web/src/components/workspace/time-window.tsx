"use client";

import {
  createContext,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { cn } from "@/lib/utils";

export const timeWindows = ["1h", "24h", "7d", "30d", "all"] as const;
export type TimeWindowKey = (typeof timeWindows)[number];

export const timeWindowLabels: Record<TimeWindowKey, string> = {
  "1h": "1 hour",
  "24h": "24 hours",
  "7d": "7 days",
  "30d": "30 days",
  all: "All retained",
};

type TimeWindowContextValue = {
  windowKey: TimeWindowKey;
  setWindowKey: (key: TimeWindowKey) => void;
};

const TimeWindowContext = createContext<TimeWindowContextValue | null>(null);

export function TimeWindowProvider({ children }: { children: ReactNode }) {
  const [windowKey, setWindowKey] = useState<TimeWindowKey>("24h");
  const value = useMemo(() => ({ windowKey, setWindowKey }), [windowKey]);
  return (
    <TimeWindowContext.Provider value={value}>
      {children}
    </TimeWindowContext.Provider>
  );
}

export function useTimeWindow(): TimeWindowContextValue {
  const value = useContext(TimeWindowContext);
  if (!value) {
    throw new Error("useTimeWindow must be used inside TimeWindowProvider");
  }
  return value;
}

export function TimeWindowControl({
  compact = false,
  label = "Time window",
}: {
  compact?: boolean;
  label?: string;
}) {
  const { windowKey, setWindowKey } = useTimeWindow();
  return (
    <div
      className={cn("ws-time-window", compact && "is-compact")}
      role="group"
      aria-label={label}
    >
      {timeWindows.map((key) => (
        <button
          key={key}
          type="button"
          className={windowKey === key ? "is-active" : undefined}
          aria-pressed={windowKey === key}
          onClick={() => setWindowKey(key)}
          title={timeWindowLabels[key]}
        >
          {key === "all" ? "ALL" : key.toUpperCase()}
        </button>
      ))}
    </div>
  );
}

"use client";

import { ChevronDown, ChevronUp } from "lucide-react";
import { useMemo, useState } from "react";
import { prettyJson } from "@/lib/api/format";
import { cn } from "@/lib/utils";
import { CopyButton } from "./copy-button";

export function JsonBlock({
  value,
  title,
  collapsedLines = 12,
  className,
  copyable = true,
}: {
  value: unknown;
  title?: string;
  collapsedLines?: number;
  className?: string;
  copyable?: boolean;
}) {
  const text = useMemo(
    () => (typeof value === "string" ? value : prettyJson(value)),
    [value],
  );
  const lines = useMemo(() => text.split("\n"), [text]);
  const [expanded, setExpanded] = useState(false);
  const canCollapse = lines.length > collapsedLines;
  const visible = expanded || !canCollapse ? text : `${lines.slice(0, collapsedLines).join("\n")}\n…`;

  return (
    <div className={className}>
      {title || copyable ? (
        <div className="ws-copy-row">
          {title ? <span className="ws-label">{title}</span> : <span />}
          {copyable ? <CopyButton value={text} label="Copy JSON" /> : null}
        </div>
      ) : null}
      <pre className="ws-json">{visible}</pre>
      {canCollapse ? (
        <button
          type="button"
          className="ws-btn is-xs is-ghost mt-1"
          onClick={() => setExpanded((open) => !open)}
          aria-expanded={expanded}
        >
          {expanded ? (
            <>
              <ChevronUp className="h-3 w-3" /> Collapse JSON
            </>
          ) : (
            <>
              <ChevronDown className="h-3 w-3" /> Expand JSON ({lines.length} lines)
            </>
          )}
        </button>
      ) : null}
    </div>
  );
}

export function CodeBlock({
  code,
  label,
  className,
}: {
  code: string;
  label?: string;
  className?: string;
}) {
  return (
    <div className={className}>
      <div className="ws-copy-row">
        {label ? <span className="ws-label">{label}</span> : <span />}
        <CopyButton value={code} label="Copy" />
      </div>
      <pre className={cn("ws-code", className)}>{code}</pre>
    </div>
  );
}

"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

export function CopyButton({
  value,
  label = "Copy",
  className,
  small = true,
}: {
  value: string;
  label?: string;
  className?: string;
  small?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setFailed(false);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setFailed(true);
      window.setTimeout(() => setFailed(false), 2400);
    }
  };

  return (
    <button
      type="button"
      className={cn("ws-btn", small && "is-xs", "is-ghost", className)}
      onClick={copy}
      aria-label={copied ? "Copied" : failed ? "Copy failed" : label}
    >
      {copied ? (
        <Check className="h-3 w-3" strokeWidth={2} />
      ) : (
        <Copy className="h-3 w-3" strokeWidth={2} />
      )}
      {copied ? "Copied" : failed ? "Copy failed" : label}
    </button>
  );
}

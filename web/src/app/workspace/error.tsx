"use client";

import { CircleAlert, RotateCw } from "lucide-react";
import { useEffect } from "react";

export default function WorkspaceError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="ws-card">
      <div className="ws-empty">
        <span className="ws-empty-icon">
          <CircleAlert className="h-5 w-5" />
        </span>
        <strong>This workspace view failed to render.</strong>
        <p>
          The gateway may be unavailable or returned an unexpected response. Your
          audit data has not been modified.
        </p>
        <button type="button" className="ws-btn is-primary" onClick={reset}>
          <RotateCw className="h-4 w-4" /> Try again
        </button>
      </div>
    </div>
  );
}

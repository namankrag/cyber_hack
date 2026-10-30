"use client";

import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "primary",
  pending = false,
  confirmDisabled = false,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "primary" | "danger" | "dark";
  pending?: boolean;
  confirmDisabled?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ReactNode;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    document.body.style.overflow = "hidden";
    window.requestAnimationFrame(() => confirmRef.current?.focus());

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !pending) {
        onCancel();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = panelRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = "";
      document.removeEventListener("keydown", onKeyDown);
      previous?.focus();
    };
  }, [onCancel, open, pending]);

  if (!open) return null;

  return (
    <div
      className="ws-modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !pending) onCancel();
      }}
    >
      <div
        ref={panelRef}
        className="ws-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ws-modal-title"
      >
        <div className="ws-modal-head">
          <h2 className="ws-modal-title" id="ws-modal-title">
            {title}
          </h2>
          <button
            type="button"
            className="ws-icon-btn"
            onClick={onCancel}
            disabled={pending}
            aria-label="Close dialog"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {description ? <div className="ws-modal-body">{description}</div> : null}
        {children ? <div className="ws-modal-body pt-0">{children}</div> : null}
        <div className="ws-modal-foot">
          <button
            type="button"
            className="ws-btn is-ghost"
            onClick={onCancel}
            disabled={pending}
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={cn(
              "ws-btn",
              tone === "danger" ? "is-danger" : tone === "dark" ? "is-dark" : "is-primary",
            )}
            onClick={onConfirm}
            disabled={pending || confirmDisabled}
          >
            {pending ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { KeyRound, Lock, ShieldCheck, UserRound } from "lucide-react";
import { ConfirmDialog } from "./confirm-dialog";
import { useSession } from "./session-context";
import { cn } from "@/lib/utils";

function formatRemaining(expiresAt: number | null, now: number): string {
  if (!expiresAt) return "session active";
  const seconds = Math.max(0, expiresAt - Math.floor(now / 1000));
  if (seconds <= 0) return "expired";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `expires in ${hours}h ${minutes}m`;
  if (minutes > 0) return `expires in ${minutes}m`;
  return "expires in under a minute";
}

/** Compact role card pinned to the sidebar footer. */
export function RoleSwitcher({ collapsed = false }: { collapsed?: boolean }) {
  const {
    role,
    expiresAt,
    mode,
    signIn,
    signOut,
    signInOpen,
    setSignInOpen,
    signOutOpen,
    setSignOutOpen,
  } = useSession();
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (role !== "admin") return;
    const timer = window.setInterval(() => setNow(Date.now()), 60_000);
    return () => window.clearInterval(timer);
  }, [role]);

  const unconfigured = mode === "unconfigured";

  const closeSignIn = () => {
    setSignInOpen(false);
    setPassword("");
    setError(null);
    setSubmitting(false);
  };

  const submitSignIn = async () => {
    if (!password || submitting) return;
    setSubmitting(true);
    setError(null);
    const result = await signIn(password);
    setPassword("");
    if (result.ok) {
      setSubmitting(false);
      setSignInOpen(false);
      setPopoverOpen(false);
      return;
    }
    setSubmitting(false);
    setError(
      result.failure.status === 401
        ? "Invalid admin password"
        : (result.failure.message ?? "Sign-in failed"),
    );
  };

  const submitSignOut = async () => {
    if (signingOut) return;
    setSigningOut(true);
    await signOut();
    setSigningOut(false);
    setSignOutOpen(false);
    setPopoverOpen(false);
  };

  const selectRole = (next: "operator" | "admin") => {
    if (next === role) return;
    if (next === "admin") {
      if (!unconfigured) setSignInOpen(true);
      return;
    }
    setSignOutOpen(true);
  };

  const card = (
    <div className="ws-role-card">
      <div className="ws-role-identity">
        <span
          className={cn("ws-role-avatar", role === "admin" && "is-admin")}
          aria-hidden="true"
        >
          {role === "admin" ? "AD" : "OP"}
        </span>
        <span className="ws-role-copy">
          <strong>{role === "admin" ? "Administrator" : "Operator"}</strong>
          <span>
            {role === "admin"
              ? `Admin session · ${formatRemaining(expiresAt, now)}`
              : "Read-only · server-held gateway key"}
          </span>
        </span>
      </div>
      <div
        className="ws-role-segment"
        role="radiogroup"
        aria-label="Workspace role"
      >
        <label
          className={cn("ws-role-option", role === "operator" && "is-active")}
        >
          <input
            type="radio"
            name="workspace-role"
            value="operator"
            checked={role === "operator"}
            onChange={() => selectRole("operator")}
          />
          <UserRound className="h-3.5 w-3.5" aria-hidden="true" />
          Operator
        </label>
        <label
          className={cn(
            "ws-role-option",
            role === "admin" && "is-active",
            unconfigured && "is-disabled",
          )}
          title={
            unconfigured
              ? "Admin login is not configured on the server (ADMIN_PASSWORD unset)"
              : undefined
          }
        >
          <input
            type="radio"
            name="workspace-role"
            value="admin"
            checked={role === "admin"}
            disabled={unconfigured}
            onChange={() => selectRole("admin")}
          />
          <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
          Admin
        </label>
      </div>
    </div>
  );

  return (
    <>
      {collapsed ? (
        <div className="ws-role-collapsed">
          <button
            type="button"
            className="ws-role-dot"
            onClick={() => setPopoverOpen((open) => !open)}
            aria-label={`Workspace role: ${role}. Open role switcher`}
            aria-expanded={popoverOpen}
            aria-haspopup="dialog"
          >
            <span
              className={cn("ws-role-avatar", role === "admin" && "is-admin")}
              aria-hidden="true"
            >
              {role === "admin" ? "AD" : "OP"}
            </span>
            <span
              className={cn("ws-role-pip", role === "admin" && "is-admin")}
              aria-hidden="true"
            />
          </button>
          {popoverOpen ? (
            <div
              className="ws-role-popover"
              role="dialog"
              aria-label="Workspace role"
              onKeyDown={(event) => {
                if (event.key === "Escape") setPopoverOpen(false);
              }}
            >
              {card}
            </div>
          ) : null}
        </div>
      ) : (
        card
      )}

      <ConfirmDialog
        open={signInOpen}
        title="Sign in as admin"
        description="Enter the server ADMIN_PASSWORD. It is verified by the Next.js server and never exposed to the browser."
        confirmLabel="Sign in as admin"
        onConfirm={() => void submitSignIn()}
        onCancel={closeSignIn}
        pending={submitting}
        confirmDisabled={!password || submitting}
      >
        <label className="ws-field">
          <span className="ws-label">Admin password</span>
          <input
            className="ws-input ws-mono"
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setError(null);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                void submitSignIn();
              }
            }}
            autoComplete="current-password"
            aria-label="Admin password"
          />
        </label>
        {error ? (
          <p className="ws-form-error" role="alert">
            {error}
          </p>
        ) : null}
        <p className="ws-hint">
          <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
          Unlocks enforcement changes, approval decisions and red-team runs.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={signOutOpen}
        title="Sign out of admin?"
        description="Privileged controls will lock again. Read-only monitoring stays available."
        confirmLabel="Sign out"
        onConfirm={() => void submitSignOut()}
        onCancel={() => setSignOutOpen(false)}
        pending={signingOut}
        tone="danger"
      />
    </>
  );
}

/** Lock badge shown next to admin-only controls for Operators. */
export function AdminLock({ label = "Admin only" }: { label?: string }) {
  return (
    <span className="ws-admin-lock">
      <Lock className="h-3 w-3" aria-hidden="true" />
      {label}
    </span>
  );
}

"use client";

import { useState } from "react";
import { Gauge, Lock, ShieldAlert } from "lucide-react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import type {
  AdminEnforceResponse,
  EnforceResponse,
  HealthResponse,
  PolicyResponse,
  ReadyResponse,
} from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { useSession } from "../session-context";
import { ConfirmDialog } from "../confirm-dialog";
import {
  Dot,
  ErrorState,
  KeyValue,
  NavyFeaturePanel,
  StatusBadge,
  SuccessNote,
  ValueSkeleton,
} from "@/components/workspace/ui";
import { SkeletonPill } from "@/components/workspace/ui";

export function EnforcementStatusCard({
  enforce,
  health,
  ready,
  policy,
  onToggleApplied,
}: {
  enforce: UseLiveDataResult<EnforceResponse>;
  health: UseLiveDataResult<HealthResponse>;
  ready: UseLiveDataResult<ReadyResponse>;
  policy: UseLiveDataResult<PolicyResponse>;
  onToggleApplied: () => void;
}) {
  const { role, requireAdmin, noteUnauthorized } = useSession();
  const isAdmin = role === "admin";
  const [confirmEnforce, setConfirmEnforce] = useState(false);
  const [togglePending, setTogglePending] = useState(false);
  const [toggleFailure, setToggleFailure] = useState<ApiFailure | null>(null);
  const [toggleSuccess, setToggleSuccess] = useState<string | null>(null);

  const currentEnforced = enforce.data?.enforced ?? false;

  const applyEnforcement = async () => {
    setTogglePending(true);
    setToggleFailure(null);
    setToggleSuccess(null);
    try {
      const result = await apiPost<AdminEnforceResponse>("/v1/admin/enforce", {
        enabled: !currentEnforced,
      });
      setToggleSuccess(
        result.enforced
          ? "Global enforcement is now ON. New calls are enforced at the boundary."
          : "Global enforcement is now OFF. Calls are still evaluated and audited, and the would-be verdict is recorded.",
      );
      setConfirmEnforce(false);
      window.dispatchEvent(new Event("agentshield:enforce-changed"));
      await enforce.refresh();
      onToggleApplied();
    } catch (error) {
      noteUnauthorized(error);
      setToggleFailure(toApiFailure(error));
    } finally {
      setTogglePending(false);
    }
  };

  const requestEnforcementToggle = () => {
    setToggleFailure(null);
    setToggleSuccess(null);
    // Operators get the admin sign-in dialog; after a successful sign-in the
    // confirm dialog opens automatically via the pending action.
    requireAdmin(() => setConfirmEnforce(true));
  };

  return (
    <>
      <NavyFeaturePanel className="ws-enforcement-panel">
        <div className="ws-navy-head">
          <span className="ws-navy-eyebrow">Enforcement</span>
          <StatusBadge tone={currentEnforced ? "lime" : "warn"}>
            {enforce.data ? (
              currentEnforced ? (
                "ON"
              ) : (
                "OFF"
              )
            ) : enforce.failure ? (
              "unknown"
            ) : (
              <SkeletonPill label="Loading enforcement state" />
            )}
          </StatusBadge>
        </div>

        <div className="ws-navy-hero">
          <span className="ws-navy-hero-icon">
            {currentEnforced ? (
              <Gauge className="h-5 w-5" />
            ) : (
              <ShieldAlert className="h-5 w-5" />
            )}
          </span>
          <div>
            <strong>
              {currentEnforced ? "Blocking at the boundary" : "Observing only — verdicts not enforced"}
            </strong>
            <span>
              {currentEnforced
                ? "Deny and require_approval verdicts stop execution before the tool runs."
                : "Every call is still evaluated, detected and audited, but the final decision is ALLOW with an enforcement_disabled reason naming the would-be verdict."}
            </span>
          </div>
        </div>

        <div className="ws-navy-kv">
          <KeyValue
            items={[
              {
                label: "Health",
                value: health.data ? (
                  <span className="ws-row">
                    <Dot tone="ok" /> {health.data.status}
                  </span>
                ) : health.failure ? (
                  <span className="ws-row">
                    <Dot tone="error" /> {health.failure.message}
                  </span>
                ) : (
                  <ValueSkeleton />
                ),
              },
              {
                label: "Readiness",
                value: ready.data?.ready ? (
                  <span className="ws-row">
                    <Dot tone="ok" /> policy loaded, detector active
                  </span>
                ) : ready.failure ? (
                  <span className="ws-row">
                    <Dot tone="error" /> not ready
                  </span>
                ) : (
                  <ValueSkeleton />
                ),
              },
              {
                label: "Detectors",
                value: health.data?.detectors.join(", ") || "—",
                mono: true,
              },
              {
                label: "Policy",
                value: policy.data ? (
                  `${policy.data.name} · v${policy.data.version}`
                ) : policy.failure ? (
                  "Policy unreadable"
                ) : (
                  <ValueSkeleton />
                ),
                mono: true,
              },
              {
                label: "Auth",
                value: health.data
                  ? health.data.auth_required
                    ? "API key required by gateway"
                    : "Open dev gateway (no API key)"
                  : "—",
              },
            ]}
          />
        </div>

        <p className="ws-navy-note">
          The global switch is admin-key gated and audit-logged. Isolated red-team
          runs never change it.
        </p>

        {toggleFailure ? <ErrorState failure={toggleFailure} compact /> : null}
        {toggleSuccess ? <SuccessNote>{toggleSuccess}</SuccessNote> : null}

        <button
          type="button"
          className={cn("ws-btn is-block", currentEnforced ? "is-danger" : "is-lime")}
          onClick={requestEnforcementToggle}
          disabled={!enforce.data || togglePending}
        >
          {!isAdmin ? (
            <>
              <Lock className="h-3.5 w-3.5" /> Admin only · Turn enforcement{" "}
              {currentEnforced ? "OFF" : "ON"}
            </>
          ) : currentEnforced ? (
            "Turn enforcement OFF"
          ) : (
            "Turn enforcement ON"
          )}
        </button>
      </NavyFeaturePanel>

      <ConfirmDialog
        open={confirmEnforce}
        title={currentEnforced ? "Turn global enforcement OFF?" : "Turn global enforcement ON?"}
        description={
          currentEnforced
            ? "Every new gateway call will still be evaluated, detected and audited, but the final decision will be ALLOW with an explicit enforcement_disabled reason naming the would-be verdict. This changes the live gateway, not just this page."
            : "Deny and require_approval verdicts will stop execution before the tool runs. This changes the live gateway, not just this page."
        }
        confirmLabel={currentEnforced ? "Turn OFF" : "Turn ON"}
        onConfirm={() => void applyEnforcement()}
        onCancel={() => {
          if (!togglePending) setConfirmEnforce(false);
        }}
        pending={togglePending}
        tone={currentEnforced ? "danger" : "primary"}
      />
    </>
  );
}

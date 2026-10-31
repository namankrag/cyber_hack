"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  adminLogin,
  adminLogout,
  type AdminSessionState,
} from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import { useLiveData } from "@/lib/hooks/use-live-data";

export type SessionRole = "operator" | "admin";

interface SessionContextValue {
  role: SessionRole;
  expiresAt: number | null;
  ttlSeconds: number;
  mode: "password" | "unconfigured";
  sessionLoading: boolean;
  /** Non-blocking notice, e.g. after an expired admin session. */
  notice: string | null;
  clearNotice: () => void;
  signIn: (
    password: string,
  ) => Promise<{ ok: true } | { ok: false; failure: ApiFailure }>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
  /** Run the action immediately when admin, otherwise open the sign-in dialog
   * and run it right after a successful sign-in. */
  requireAdmin: (action: () => void) => void;
  /** Call from a privileged request's catch block. Returns true when the
   * failure was a 401: the session is re-fetched (downgrading to Operator)
   * and a notice is shown. */
  noteUnauthorized: (error: unknown) => boolean;
  signInOpen: boolean;
  setSignInOpen: (open: boolean) => void;
  signOutOpen: boolean;
  setSignOutOpen: (open: boolean) => void;
  adminSession: AdminSessionState | null;
  adminSessionError: ApiFailure | null;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const session = useLiveData<AdminSessionState>("/admin/session", {
    intervalMs: 60_000,
  });
  const [notice, setNotice] = useState<string | null>(null);
  const [signInOpen, setSignInOpen] = useState(false);
  const [signOutOpen, setSignOutOpen] = useState(false);
  const pendingAction = useRef<(() => void) | null>(null);

  // Destructure the live-data result so hook dependencies are stable,
  // plain identifiers instead of member expressions.
  const sessionData = session.data;
  const sessionFailure = session.failure;
  const sessionIsLoading = session.isLoading;
  const refreshLiveSession = session.refresh;

  const refresh = useCallback(async () => {
    await refreshLiveSession();
  }, [refreshLiveSession]);

  // Re-fetch the session whenever the tab regains focus so a sign-in or
  // expiry in another tab is picked up without a reload.
  useEffect(() => {
    const onFocus = () => void refreshLiveSession();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refreshLiveSession]);

  const role: SessionRole = sessionData?.authenticated === true ? "admin" : "operator";

  const signIn = useCallback(
    async (password: string) => {
      try {
        await adminLogin(password);
      } catch (error) {
        return { ok: false as const, failure: toApiFailure(error) };
      }
      await refreshLiveSession();
      const action = pendingAction.current;
      pendingAction.current = null;
      if (action) action();
      return { ok: true as const };
    },
    [refreshLiveSession],
  );

  const signOut = useCallback(async () => {
    pendingAction.current = null;
    try {
      await adminLogout();
    } catch {
      // Logging out is best-effort: the cookie may already be gone.
    }
    await refreshLiveSession();
  }, [refreshLiveSession]);

  const requireAdmin = useCallback(
    (action: () => void) => {
      if (sessionData?.authenticated === true) {
        action();
        return;
      }
      pendingAction.current = action;
      setSignInOpen(true);
    },
    [sessionData],
  );

  const noteUnauthorized = useCallback(
    (error: unknown) => {
      const failure = toApiFailure(error);
      if (failure.status !== 401) return false;
      pendingAction.current = null;
      void refreshLiveSession();
      setNotice("Admin session expired, sign in again.");
      return true;
    },
    [refreshLiveSession],
  );

  const clearNotice = useCallback(() => setNotice(null), []);

  const sessionLoading = sessionIsLoading && !sessionData;

  const value = useMemo<SessionContextValue>(
    () => ({
      role,
      expiresAt: sessionData?.expires_at ?? null,
      ttlSeconds: sessionData?.ttl_seconds ?? 0,
      mode: sessionData?.mode ?? "password",
      sessionLoading,
      notice,
      clearNotice,
      signIn,
      signOut,
      refresh,
      requireAdmin,
      noteUnauthorized,
      signInOpen,
      setSignInOpen,
      signOutOpen,
      setSignOutOpen,
      adminSession: sessionData ?? null,
      adminSessionError: sessionFailure,
    }),
    [
      role,
      sessionData,
      sessionFailure,
      sessionLoading,
      notice,
      clearNotice,
      signIn,
      signOut,
      refresh,
      requireAdmin,
      noteUnauthorized,
      signInOpen,
      signOutOpen,
    ],
  );

  return (
    <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
  );
}

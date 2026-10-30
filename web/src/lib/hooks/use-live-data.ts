"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { apiGet } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";

interface UseLiveDataOptions {
  intervalMs?: number;
  enabled?: boolean;
}

interface UseLiveDataResult<T> {
  data: T | null;
  failure: ApiFailure | null;
  isLoading: boolean;
  isRefreshing: boolean;
  isStale: boolean;
  lastUpdated: number | null;
  refresh: () => Promise<void>;
}

interface Snapshot<T> {
  path: string | null;
  data: T | null;
  failure: ApiFailure | null;
  isLoading: boolean;
  isRefreshing: boolean;
  lastUpdated: number | null;
}

function initialSnapshot<T>(path: string | null, enabled: boolean): Snapshot<T> {
  return {
    path,
    data: null,
    failure: null,
    isLoading: Boolean(path) && enabled,
    isRefreshing: false,
    lastUpdated: null,
  };
}

/**
 * Small polling hook built on the server-side /api proxy.
 *
 * - Polls only while the tab is visible.
 * - Keeps the last good snapshot when a later poll fails and marks it stale.
 * - Aborts in-flight requests when the path changes or the component unmounts.
 * - Keys the snapshot to the request path so a new query never renders data
 *   that belongs to the previous one.
 */
export function useLiveData<T>(
  path: string | null,
  options: UseLiveDataOptions = {},
): UseLiveDataResult<T> {
  const { intervalMs = 15_000, enabled = true } = options;
  const [snapshot, setSnapshot] = useState<Snapshot<T>>(() =>
    initialSnapshot<T>(path, enabled),
  );

  const dataRef = useRef<T | null>(null);
  const requestRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestRef.current?.abort();
    };
  }, []);

  const refresh = useCallback(async () => {
    if (!path || !enabled) return;
    if (inFlightRef.current) return;

    inFlightRef.current = true;
    const controller = new AbortController();
    requestRef.current = controller;

    setSnapshot((previous) =>
      previous.path === path
        ? {
            ...previous,
            isLoading: previous.data === null,
            isRefreshing: previous.data !== null,
          }
        : initialSnapshot<T>(path, enabled),
    );

    try {
      const next = await apiGet<T>(path, controller.signal);
      if (!mountedRef.current || controller.signal.aborted) return;
      dataRef.current = next;
      setSnapshot({
        path,
        data: next,
        failure: null,
        isLoading: false,
        isRefreshing: false,
        lastUpdated: Date.now(),
      });
    } catch (error) {
      if (!mountedRef.current || controller.signal.aborted) return;
      setSnapshot((previous) =>
        previous.path === path
          ? {
              ...previous,
              failure: toApiFailure(error),
              isLoading: false,
              isRefreshing: false,
            }
          : previous,
      );
    } finally {
      if (requestRef.current === controller) {
        inFlightRef.current = false;
      }
    }
  }, [enabled, path]);

  useEffect(() => {
    requestRef.current?.abort();
    inFlightRef.current = false;
    dataRef.current = null;

    if (!path || !enabled) return;

    void refresh();

    const interval = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, intervalMs);

    const onVisible = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    document.addEventListener("visibilitychange", onVisible);

    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
      requestRef.current?.abort();
      inFlightRef.current = false;
    };
  }, [enabled, intervalMs, path, refresh]);

  const active = enabled && path !== null;
  const isCurrent = active && snapshot.path === path;
  const data = isCurrent ? snapshot.data : null;
  const failure = isCurrent ? snapshot.failure : null;

  return {
    data,
    failure,
    isLoading: isCurrent ? snapshot.isLoading : active,
    isRefreshing: isCurrent ? snapshot.isRefreshing : false,
    isStale: Boolean(failure && data),
    lastUpdated: isCurrent ? snapshot.lastUpdated : null,
    refresh,
  };
}

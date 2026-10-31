"use client";

import {
  ArrowUpRight,
  BookOpen,
  ChevronDown,
  Command,
  ExternalLink,
  HeartPulse,
  KeyRound,
  LogOut,
  Menu,
  PanelLeft,
  ScrollText,
  Search,
  Settings2,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useLiveData } from "@/lib/hooks/use-live-data";
import type {
  ApprovalsResponse,
  EnforceResponse,
  HealthResponse,
} from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { ShieldMark } from "@/components/marketing/logo";
import { CommandPalette } from "@/components/workspace/command-palette";
import {
  navItemHash,
  navItemPath,
  workspaceNavGroups,
  workspaceNavItems,
  type WorkspaceNavItem,
} from "@/components/workspace/nav";
import {
  TimeWindowControl,
  TimeWindowProvider,
} from "@/components/workspace/time-window";
import { Dot, GatewayStatus, SkeletonPill, StatusBadge } from "./ui";
import { SessionProvider, useSession } from "./session-context";
import { RoleSwitcher } from "./role-switcher";

function itemIsActive(
  item: WorkspaceNavItem,
  pathname: string,
  hash: string,
): boolean {
  const path = navItemPath(item);
  const targetHash = navItemHash(item);
  if (item.exact) return pathname === path;
  if (!pathname.startsWith(path)) return false;
  if (path === "/workspace/settings") {
    const current = hash || "#health";
    return current === (targetHash ?? "#health");
  }
  return true;
}

export function WorkspaceShell({ children }: { children: ReactNode }) {
  return (
    <TimeWindowProvider>
      <SessionProvider>
        <WorkspaceShellInner>{children}</WorkspaceShellInner>
      </SessionProvider>
    </TimeWindowProvider>
  );
}

function WorkspaceShellInner({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const {
    role,
    mode,
    notice,
    clearNotice,
    setSignInOpen,
    setSignOutOpen,
  } = useSession();
  const [open, setOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [hash, setHash] = useState("");
  const userMenuRef = useRef<HTMLDivElement>(null);
  const asideRef = useRef<HTMLElement>(null);

  const health = useLiveData<HealthResponse>("/health", { intervalMs: 20_000 });
  const enforce = useLiveData<EnforceResponse>("/v1/enforce", { intervalMs: 20_000 });
  const approvals = useLiveData<ApprovalsResponse>("/v1/approvals?limit=1", {
    intervalMs: 30_000,
  });

  const active =
    workspaceNavItems.find((item) => itemIsActive(item, pathname, hash)) ??
    workspaceNavItems[0];
  const pending = approvals.data?.summary.pending ?? 0;
  const showTimeWindow =
    pathname === "/workspace" || pathname === "/workspace/analytics";

  const closePalette = useCallback(() => setPaletteOpen(false), []);

  const refreshEnforce = enforce.refresh;
  useEffect(() => {
    const onChange = () => void refreshEnforce();
    window.addEventListener("agentshield:enforce-changed", onChange);
    return () =>
      window.removeEventListener("agentshield:enforce-changed", onChange);
  }, [refreshEnforce]);

  useEffect(() => {
    const sync = () => setHash(window.location.hash);
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, [pathname]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((value) => !value);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const aside = asideRef.current;
    aside?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        return;
      }
      if (event.key !== "Tab" || !aside) return;
      const items = Array.from(
        aside.querySelectorAll<HTMLElement>("a[href], button:not([disabled])"),
      ).filter((element) => element.offsetParent !== null);
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
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
      document.body.style.overflow = previous;
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (!userMenuOpen) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!userMenuRef.current?.contains(event.target as Node)) {
        setUserMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setUserMenuOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [userMenuOpen]);

  return (
    <div className="workspace">
      <a href="#workspace-main" className="ws-skip">
        Skip to workspace content
      </a>

        <div className="ws-shell">
          <aside
            id="workspace-navigation"
            ref={asideRef}
            tabIndex={-1}
            className={cn(
              "ws-sidebar",
              open && "is-open",
              collapsed && "is-collapsed",
            )}
            aria-label="Workspace navigation"
          >
            <div className="ws-sidebar-inner">
              <Link
                href="/workspace"
                className="ws-brand"
                aria-label="AgentShield workspace overview"
                onClick={() => setOpen(false)}
              >
                <span className="ws-brand-mark" aria-hidden="true">
                  <ShieldMark className="h-7" />
                </span>
                <span className="ws-brand-copy">
                  <strong>AgentShield</strong>
                  <span>Control plane</span>
                </span>
                <span className="ws-brand-status" aria-hidden="true" />
              </Link>

              <nav className="ws-nav">
                {workspaceNavGroups.map((group) => (
                  <div className="ws-nav-group" key={group.label}>
                    <span className="ws-nav-label">{group.label}</span>
                    {group.items.map((item) => {
                      const Icon = item.icon;
                      const isActive = itemIsActive(item, pathname, hash);
                      const showPending =
                        item.badge === "pending" && pending > 0;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={cn("ws-nav-link", isActive && "is-active")}
                          aria-current={isActive ? "page" : undefined}
                          onClick={() => setOpen(false)}
                        >
                          <span className="ws-nav-icon">
                            <Icon className="h-4 w-4" strokeWidth={1.7} />
                          </span>
                          <span className="ws-truncate">{item.label}</span>
                          {showPending ? (
                            <span
                              className="ws-nav-count is-alert"
                              title={`${pending} pending approval(s)`}
                            >
                              {pending}
                            </span>
                          ) : null}
                        </Link>
                      );
                    })}
                  </div>
                ))}
              </nav>

              <div className="ws-sidebar-footer">
                <RoleSwitcher collapsed={collapsed} />
                <div className="ws-env">
                  <Dot
                    tone={health.failure ? "error" : health.data ? "ok" : "warn"}
                  />
                  <div className="ws-env-copy">
                    <strong>
                      {health.failure && !health.data
                        ? "Gateway unreachable"
                        : health.data
                          ? "Gateway connected"
                          : "Checking gateway"}
                    </strong>
                    <span>
                      {health.data
                        ? `${health.data.detectors.length} detector${health.data.detectors.length === 1 ? "" : "s"} · ${health.data.auth_required ? "auth required" : "open dev gateway"}`
                        : (health.failure?.message ?? "Reading /health")}
                    </span>
                    {health.failure && !health.data ? (
                      <button
                        type="button"
                        className="ws-link ws-fs-meta"
                        onClick={() => void health.refresh()}
                      >
                        Retry
                      </button>
                    ) : null}
                  </div>
                </div>

                <div className="ws-sidebar-enforce">
                  <span>Enforcement</span>
                  {enforce.data ? (
                    <StatusBadge tone={enforce.data.enforced ? "ok" : "warn"}>
                      {enforce.data.enforced ? "ON" : "OFF"}
                    </StatusBadge>
                  ) : enforce.failure ? (
                    <StatusBadge tone="neutral">unknown</StatusBadge>
                  ) : (
                    <SkeletonPill label="Loading enforcement state" />
                  )}
                </div>

                <div className="ws-sidebar-links">
                  <Link href="/" className="ws-sidebar-link">
                    <ArrowUpRight className="h-3.5 w-3.5" /> Back to public site
                  </Link>
                  <Link href="/#documentation" className="ws-sidebar-link">
                    <ScrollText className="h-3.5 w-3.5" /> Documentation
                  </Link>
                </div>
              </div>
            </div>
          </aside>

          {open ? (
            <button
              type="button"
              className="ws-overlay"
              aria-label="Close navigation"
              onClick={() => setOpen(false)}
            />
          ) : null}

          <div className="ws-main">
            {notice ? (
              <div className="ws-notice" role="status">
                <span>{notice}</span>
                <button
                  type="button"
                  className="ws-link ws-fs-meta"
                  onClick={clearNotice}
                >
                  Dismiss
                </button>
              </div>
            ) : null}
            <header className="ws-topbar">
              <div className="ws-topbar-inner">
                <button
                  type="button"
                  className="ws-icon-btn ws-collapse-button"
                  onClick={() => setCollapsed((value) => !value)}
                  aria-expanded={!collapsed}
                  aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                >
                  <PanelLeft className="h-4 w-4" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="ws-icon-btn ws-menu-button"
                  onClick={() => setOpen((value) => !value)}
                  aria-expanded={open}
                  aria-controls="workspace-navigation"
                  aria-label={open ? "Close navigation" : "Open navigation"}
                >
                  {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
                </button>

                <div className="ws-crumbs" aria-label="Breadcrumb">
                  <Link href="/workspace" className="ws-crumb-prefix">AgentShield</Link>
                  <span aria-hidden="true" className="ws-crumb-prefix">/</span>
                  <span className="ws-crumb-prefix">Workspace</span>
                  <span aria-hidden="true" className="ws-crumb-prefix">/</span>
                  <strong aria-current="page">{active.label}</strong>
                </div>

                <div className="ws-topbar-spacer" />

                <div className="ws-topbar-tools">
                  <button
                    type="button"
                    className="ws-command-trigger"
                    onClick={() => setPaletteOpen(true)}
                    aria-haspopup="dialog"
                    aria-expanded={paletteOpen}
                  >
                    <Search className="h-3.5 w-3.5" aria-hidden="true" />
                    <span className="ws-command-label">Search workspace</span>
                    <kbd className="ws-kbd">
                      <Command className="h-2.5 w-2.5" />K
                    </kbd>
                  </button>

                  {showTimeWindow ? <TimeWindowControl compact /> : null}

                  <div className="ws-topbar-divider" aria-hidden="true" />

                  {enforce.data ? (
                    <StatusBadge tone={enforce.data.enforced ? "ok" : "warn"}>
                      {enforce.data.enforced ? "Enforcement ON" : "Enforcement OFF"}
                    </StatusBadge>
                  ) : enforce.failure ? (
                    <StatusBadge tone="neutral">Enforcement unknown</StatusBadge>
                  ) : (
                    <SkeletonPill label="Loading enforcement state" />
                  )}

                  <GatewayStatus
                    state={
                      health.failure ? "offline" : health.data ? "live" : "checking"
                    }
                  />

                  <div className="ws-user" ref={userMenuRef}>
                    <button
                      type="button"
                      className="ws-user-button"
                      aria-haspopup="menu"
                      aria-expanded={userMenuOpen}
                      onClick={() => setUserMenuOpen((value) => !value)}
                    >
                      <span
                        className={cn(
                          "ws-user-avatar",
                          role === "admin" && "is-admin",
                        )}
                        aria-hidden="true"
                      >
                        {role === "admin" ? "AD" : "OP"}
                      </span>
                      <span className="ws-user-copy">
                        <strong>
                          {role === "admin" ? "Administrator" : "Operator"}
                        </strong>
                        <span>
                          {role === "admin"
                            ? "Admin session"
                            : "Read-only · server-held key"}
                        </span>
                      </span>
                      <ChevronDown
                        className={cn(
                          "h-3.5 w-3.5 transition-transform",
                          userMenuOpen && "rotate-180",
                        )}
                        aria-hidden="true"
                      />
                    </button>

                    {userMenuOpen ? (
                      <div className="ws-user-menu" role="menu">
                        <div className="ws-user-menu-head">
                          <span
                            className={cn(
                              "ws-user-avatar is-large",
                              role === "admin" && "is-admin",
                            )}
                            aria-hidden="true"
                          >
                            {role === "admin" ? "AD" : "OP"}
                          </span>
                          <span>
                            <strong>
                              {role === "admin" ? "Administrator" : "Operator"}
                            </strong>
                            <span>
                              {role === "admin"
                                ? "Admin session · privileged controls unlocked"
                                : "No workspace sign-in · server-held gateway keys"}
                            </span>
                          </span>
                        </div>
                        <div className="ws-menu-sep" />
                        {role === "admin" ? (
                          <button
                            type="button"
                            className="ws-user-menu-item"
                            role="menuitem"
                            onClick={() => {
                              setUserMenuOpen(false);
                              setSignOutOpen(true);
                            }}
                          >
                            <LogOut className="h-3.5 w-3.5" /> Sign out of admin
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="ws-user-menu-item"
                            role="menuitem"
                            disabled={mode === "unconfigured"}
                            title={
                              mode === "unconfigured"
                                ? "Admin login is not configured on the server (ADMIN_PASSWORD unset)"
                                : undefined
                            }
                            onClick={() => {
                              setUserMenuOpen(false);
                              setSignInOpen(true);
                            }}
                          >
                            <KeyRound className="h-3.5 w-3.5" /> Sign in as admin
                          </button>
                        )}
                        <div className="ws-menu-sep" />
                        <Link
                          href="/workspace/settings#health"
                          className="ws-user-menu-item"
                          role="menuitem"
                          onClick={() => setUserMenuOpen(false)}
                        >
                          <HeartPulse className="h-3.5 w-3.5" /> Gateway &amp; health
                        </Link>
                        <Link
                          href="/workspace/settings#configuration"
                          className="ws-user-menu-item"
                          role="menuitem"
                          onClick={() => setUserMenuOpen(false)}
                        >
                          <Settings2 className="h-3.5 w-3.5" /> Configuration
                        </Link>
                        <Link
                          href="/#documentation"
                          className="ws-user-menu-item"
                          role="menuitem"
                          onClick={() => setUserMenuOpen(false)}
                        >
                          <BookOpen className="h-3.5 w-3.5" /> Documentation
                        </Link>
                        <Link
                          href="/"
                          className="ws-user-menu-item"
                          role="menuitem"
                          onClick={() => setUserMenuOpen(false)}
                        >
                          <ExternalLink className="h-3.5 w-3.5" /> Public website
                        </Link>
                        <div className="ws-menu-sep" />
                        <button
                          type="button"
                          className="ws-user-menu-item"
                          role="menuitem"
                          onClick={() => {
                            setUserMenuOpen(false);
                            setPaletteOpen(true);
                          }}
                        >
                          <Search className="h-3.5 w-3.5" /> Search workspace
                          <kbd className="ws-kbd">⌘K</kbd>
                        </button>
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>
            </header>

            <main id="workspace-main" className="ws-content">
              {children}
            </main>
          </div>
        </div>

        <CommandPalette open={paletteOpen} onClose={closePalette} />
    </div>
  );
}

"use client";

import {
  ArrowRight,
  BookOpen,
  CornerDownLeft,
  ExternalLink,
  Search,
  Sparkles,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import {
  workspaceNavGroups,
  type WorkspaceNavItem,
} from "@/components/workspace/nav";

type PaletteEntry = {
  group: string;
  label: string;
  description: string;
  href: string;
  icon: WorkspaceNavItem["icon"];
};

const quickLinks: PaletteEntry[] = [
  {
    group: "Quick links",
    label: "Documentation",
    description: "Open the public documentation section",
    href: "/#documentation",
    icon: BookOpen,
  },
  {
    group: "Quick links",
    label: "Request a demo",
    description: "Open the demo request form",
    href: "/#request-demo",
    icon: Sparkles,
  },
  {
    group: "Quick links",
    label: "Public website",
    description: "Leave the workspace",
    href: "/",
    icon: ExternalLink,
  },
];

const entries: PaletteEntry[] = [
  ...workspaceNavGroups.flatMap((group) =>
    group.items.map((item) => ({
      group: group.label,
      label: item.label,
      description: item.description,
      href: item.href,
      icon: item.icon,
    })),
  ),
  ...quickLinks,
];

export function CommandPalette({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  if (!open) return null;
  return <PaletteDialog onClose={onClose} />;
}

function PaletteDialog({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);

  const results = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return entries;
    return entries.filter((entry) =>
      `${entry.label} ${entry.description} ${entry.group}`
        .toLowerCase()
        .includes(term),
    );
  }, [query]);

  const groups = useMemo(() => {
    const order: string[] = [];
    const map = new Map<string, PaletteEntry[]>();
    for (const entry of results) {
      if (!map.has(entry.group)) {
        map.set(entry.group, []);
        order.push(entry.group);
      }
      map.get(entry.group)!.push(entry);
    }
    return order.map((label) => ({ label, items: map.get(label) ?? [] }));
  }, [results]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const frame = window.requestAnimationFrame(() => inputRef.current?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", onKeyDown);
    return () => {
      window.cancelAnimationFrame(frame);
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", onKeyDown);
      previous?.focus();
    };
  }, [onClose]);

  useEffect(() => {
    const node = listRef.current?.querySelector<HTMLElement>(
      `[data-palette-index="${activeIndex}"]`,
    );
    node?.scrollIntoView({ block: "nearest" });
  }, [activeIndex]);

  const go = (href: string) => {
    onClose();
    router.push(href);
  };

  const onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) =>
        results.length ? (index + 1) % results.length : 0,
      );
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) =>
        results.length ? (index - 1 + results.length) % results.length : 0,
      );
    } else if (event.key === "Enter") {
      event.preventDefault();
      const entry = results[activeIndex];
      if (entry) go(entry.href);
    } else if (event.key === "Home") {
      event.preventDefault();
      setActiveIndex(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActiveIndex(Math.max(results.length - 1, 0));
    }
  };

  let flatIndex = -1;

  return (
    <div
      className="ws-palette-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="ws-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Search workspace"
      >
        <div className="ws-palette-search">
          <Search className="h-4 w-4" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={onInputKeyDown}
            placeholder="Jump to a page or action…"
            aria-label="Search workspace pages and actions"
            aria-controls="workspace-palette-results"
            aria-activedescendant={
              results[activeIndex]
                ? `workspace-palette-${activeIndex}`
                : undefined
            }
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="ws-kbd">ESC</kbd>
        </div>

        <div
          id="workspace-palette-results"
          className="ws-palette-results"
          ref={listRef}
          role="listbox"
          aria-label="Workspace destinations"
        >
          {results.length ? (
            groups.map((group) => (
              <div className="ws-palette-group" key={group.label}>
                <span className="ws-palette-label">{group.label}</span>
                {group.items.map((entry) => {
                  flatIndex += 1;
                  const index = flatIndex;
                  const Icon = entry.icon;
                  return (
                    <button
                      key={entry.href}
                      id={`workspace-palette-${index}`}
                      data-palette-index={index}
                      type="button"
                      role="option"
                      aria-selected={activeIndex === index}
                      className={cn(
                        "ws-palette-item",
                        activeIndex === index && "is-active",
                      )}
                      onMouseEnter={() => setActiveIndex(index)}
                      onClick={() => go(entry.href)}
                    >
                      <span className="ws-palette-icon">
                        <Icon className="h-4 w-4" strokeWidth={1.7} />
                      </span>
                      <span className="ws-palette-copy">
                        <strong>{entry.label}</strong>
                        <span>{entry.description}</span>
                      </span>
                      <ArrowRight className="ws-palette-arrow h-3.5 w-3.5" />
                    </button>
                  );
                })}
              </div>
            ))
          ) : (
            <div className="ws-palette-empty">
              <strong>No destination matches “{query}”.</strong>
              <span>Try a page name like audit, policy or approvals.</span>
            </div>
          )}
        </div>

        <div className="ws-palette-foot">
          <span>
            <kbd className="ws-kbd">↑</kbd>
            <kbd className="ws-kbd">↓</kbd> navigate
          </span>
          <span>
            <kbd className="ws-kbd">
              <CornerDownLeft className="h-3 w-3" />
            </kbd>{" "}
            open
          </span>
          <span className="ws-palette-foot-note">
            Navigation only · no gateway queries are run from this palette
          </span>
        </div>
      </div>
    </div>
  );
}

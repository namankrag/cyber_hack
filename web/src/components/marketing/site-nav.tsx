"use client";

import { ArrowUpRight, Menu, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Brand } from "@/components/marketing/logo";

const links = [
  { label: "Home", href: "#home", id: "home" },
  { label: "Platform", href: "#platform", id: "platform" },
  { label: "How It Works", href: "#how-it-works", id: "how-it-works" },
  { label: "Security", href: "#security", id: "security" },
  { label: "Documentation", href: "#documentation", id: "documentation" },
];

export function SiteNav() {
  const [active, setActive] = useState("home");
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let frame = 0;

    const update = () => {
      frame = 0;
      const marker = window.scrollY + window.innerHeight * 0.32;
      let current = "home";

      for (const link of links) {
        const section = document.getElementById(link.id);
        if (section && section.offsetTop <= marker) current = link.id;
      }

      if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 80) {
        current = "documentation";
      }

      setActive(current);
    };

    const onScroll = () => {
      if (!frame) frame = window.requestAnimationFrame(update);
    };

    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, []);

  useEffect(() => {
    if (!menuOpen) return;

    const closeMenu = () => {
      setMenuOpen(false);
      window.requestAnimationFrame(() => menuButtonRef.current?.focus());
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeMenu();
        return;
      }

      if (event.key !== "Tab") return;
      const focusable = menuRef.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled])',
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

    const onResize = () => {
      if (window.innerWidth > 1020) closeMenu();
    };

    document.body.style.overflow = "hidden";
    window.requestAnimationFrame(() => {
      menuRef.current?.querySelector<HTMLElement>("a[href]")?.focus();
    });
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onResize);
    return () => {
      document.body.style.overflow = "";
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onResize);
    };
  }, [menuOpen]);

  return (
    <>
      <a
        href="#main"
        className="fixed left-4 top-3 z-[100] -translate-y-24 rounded-full bg-[#191D35] px-4 py-2 text-[12px] font-semibold text-white transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>

      <header className="site-nav">
        <div className="nav-desktop">
          <Link href="#home" className="nav-brand" aria-label="AgentShield home">
            <Brand compact />
            <span className="nav-brand-dot" aria-hidden="true" />
          </Link>

          <nav className="nav-pill" aria-label="Primary navigation">
            {links.map((link) => (
              <a
                key={link.id}
                href={link.href}
                className={`nav-link ${active === link.id ? "is-active" : ""}`}
                aria-current={active === link.id ? "page" : undefined}
                onClick={() => setActive(link.id)}
              >
                {link.label}
              </a>
            ))}
          </nav>

          <div className="nav-actions">
            <Link href="/workspace" className="btn btn-sm btn-outline">
              Open workspace
            </Link>
            <a href="#request-demo" className="btn btn-sm btn-outline">
              Request a demo
              <ArrowUpRight className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>

        <div className="nav-mobile">
          <Link href="#home" className="nav-brand" aria-label="AgentShield home">
            <Brand compact />
          </Link>
          <button
            ref={menuButtonRef}
            type="button"
            className="nav-menu-button"
            aria-expanded={menuOpen}
            aria-controls="mobile-navigation"
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            onClick={() => setMenuOpen((open) => !open)}
          >
            {menuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

        <div
          ref={menuRef}
          id="mobile-navigation"
          className={`mobile-menu ${menuOpen ? "is-open" : ""}`}
          aria-hidden={!menuOpen}
        >
          <nav aria-label="Mobile navigation">
            {links.map((link, index) => (
              <a
                key={link.id}
                href={link.href}
                onClick={() => {
                  setActive(link.id);
                  setMenuOpen(false);
                }}
                style={{ transitionDelay: menuOpen ? `${90 + index * 35}ms` : "0ms" }}
                tabIndex={menuOpen ? 0 : -1}
              >
                <span>{link.label}</span>
                <span className="mobile-menu-index">0{index + 1}</span>
              </a>
            ))}
          </nav>
          <div className="mobile-menu-footer">
            <Link
              href="/workspace"
              className="btn btn-outline w-full justify-center"
              onClick={() => setMenuOpen(false)}
              tabIndex={menuOpen ? 0 : -1}
            >
              Open workspace <ArrowUpRight className="h-4 w-4" />
            </Link>
            <a
              href="#request-demo"
              className="btn btn-primary w-full justify-center"
              onClick={() => setMenuOpen(false)}
              tabIndex={menuOpen ? 0 : -1}
            >
              Request a demo <ArrowUpRight className="h-4 w-4" />
            </a>
          </div>
        </div>
      </header>
    </>
  );
}

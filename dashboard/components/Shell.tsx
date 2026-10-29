"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Suspense, useEffect, useState, type ReactNode } from "react";
import Icon from "@/components/Icon";
import { WINDOWS, WindowContext, useApi, type Window } from "@/lib/api";
import { AUTHOR } from "@/lib/site";

const NAV = [
  { href: "/", label: "Live" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/attackers", label: "Attackers" },
  { href: "/credentials", label: "Credentials" },
  { href: "/ttps", label: "ATT&CK" },
  { href: "/payloads", label: "Payloads" },
  { href: "/about", label: "How it works" },
];

function NavLinks({ active = true }: { active?: boolean }) {
  return (
    <nav className="nav" aria-label="Sections">
      {active ? <ActiveLinks /> : NAV.map((n) => <Link key={n.href} href={n.href}>{n.label}</Link>)}
    </nav>
  );
}

function ActiveLinks() {
  const path = usePathname();
  return NAV.map((n) => (
    <Link key={n.href} href={n.href} className={path === n.href ? "active" : ""}>
      {n.label}
    </Link>
  ));
}

export default function Shell({ children }: { children: ReactNode }) {
  const [win, setWin] = useState<Window>("24h");

  useEffect(() => {
    try {
      const saved = localStorage.getItem("window") as Window | null;
      if (saved && WINDOWS.some((w) => w.id === saved)) setWin(saved);
    } catch {}
  }, []);

  const setWindow = (w: Window) => {
    setWin(w);
    try {
      localStorage.setItem("window", w);
    } catch {}
  };

  const { data: health } = useApi<{ ok: boolean }>("/health", 30000);

  return (
    <WindowContext.Provider value={{ window: win, setWindow }}>
      <header className="topbar">
        <Link href="/" className="brand">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/honeyjar.svg" alt="" width={30} height={30} />
          <span className="wordmark">honeyjar</span>
          <span className={`pulse ${health?.ok ? "" : "off"}`} role="img" aria-label={health?.ok ? "Pipeline healthy" : "API unreachable"} />
          <span className="tagline">live threat map</span>
        </Link>
        <Suspense fallback={<NavLinks active={false} />}>
          <NavLinks />
        </Suspense>
        <ThemeToggle />
      </header>
      <main>{children}</main>
      <footer className="foot">
        Live data from internet-facing honeypots. Attacker-supplied URLs and IPs inside payloads are defanged.
        IP geolocation by <a className="link" href="https://db-ip.com">DB-IP</a> · KEV data from CISA · EPSS from FIRST.
        <br />
        Built by {AUTHOR.name} ·{" "}
        <a className="link" href={AUTHOR.linkedin} rel="me noopener" target="_blank">LinkedIn</a> ·{" "}
        <a className="link" href={AUTHOR.github} rel="me noopener" target="_blank">GitHub</a> ·{" "}
        <a className="link" href={AUTHOR.repo} rel="noopener" target="_blank">Source</a>
      </footer>
    </WindowContext.Provider>
  );
}

/** Light/dark switch. Starts from the OS preference; an explicit choice is remembered. */
function ThemeToggle() {
  const [dark, setDark] = useState<boolean | null>(null);
  useEffect(() => {
    const set = document.documentElement.dataset.theme;
    setDark(set ? set === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches);
  }, []);
  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.dataset.theme = next ? "dark" : "light";
    try {
      localStorage.setItem("theme", next ? "dark" : "light");
    } catch {}
    window.dispatchEvent(new Event("themechange"));
  };
  return (
    <button className="theme-toggle" onClick={toggle} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}>
      <Icon name={dark ? "sun" : "moon"} />
    </button>
  );
}

/** The one filter row: time window, scoping every chart on the page. */
export function WindowPicker() {
  return (
    <WindowContext.Consumer>
      {({ window, setWindow }) => (
        <div className="seg" role="group" aria-label="Time window">
          {WINDOWS.map((w) => (
            <button key={w.id} aria-pressed={window === w.id} onClick={() => setWindow(w.id)}>
              {w.label}
            </button>
          ))}
        </div>
      )}
    </WindowContext.Consumer>
  );
}

export function PageHead({ title, desc, eyebrow, picker = true }: { title: string; desc?: ReactNode; eyebrow?: string; picker?: boolean }) {
  return (
    <div className="page-head">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {desc && <p>{desc}</p>}
      </div>
      {picker && <WindowPicker />}
    </div>
  );
}

"use client";

import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore } from "react";
import useSWR from "swr";

export type Window = "1h" | "24h" | "7d" | "30d" | "all";
export const WINDOWS: { id: Window; label: string }[] = [
  { id: "1h", label: "1h" },
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "30d", label: "30d" },
  { id: "all", label: "All" },
];

export const WindowContext = createContext<{ window: Window; setWindow: (w: Window) => void }>({
  window: "24h",
  setWindow: () => {},
});
export const useWindow = () => useContext(WindowContext);

const fetcher = async (url: string) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
};

/** Stats for the selected time window; keeps the previous data while refetching. */
export function useStats<T>(path: string, refreshMs = 15000, withWindow = true) {
  const { window } = useWindow();
  const sep = path.includes("?") ? "&" : "?";
  const key = withWindow ? `/api${path}${sep}window=${window}` : `/api${path}`;
  return useSWR<T>(key, fetcher, { refreshInterval: refreshMs, keepPreviousData: true });
}

export function useApi<T>(path: string | null, refreshMs = 0) {
  return useSWR<T>(path ? `/api${path}` : null, fetcher, { refreshInterval: refreshMs, keepPreviousData: true });
}

export interface LiveEvent {
  ts: string;
  sensor_id: string;
  sensor_lat: number | null;
  sensor_lon: number | null;
  honeypot: string;
  proto: string | null;
  event_type: string;
  src_ip: string;
  dst_port: number | null;
  country_code: string | null;
  country: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  as_org?: string | null;
  username: string | null;
  password: string | null;
  login_success: boolean | null;
  command: string | null;
  http_method: string | null;
  http_path: string | null;
  download_url: string | null;
  cves: string[];
  tags: string[];
  techniques: string[];
}

function wsUrl() {
  if (process.env.NEXT_PUBLIC_WS_URL) return process.env.NEXT_PUBLIC_WS_URL;
  const { protocol, host, hostname, port } = window.location;
  // `next dev` cannot proxy WebSockets; talk to the API directly in dev.
  if (port === "3000") return `ws://${hostname}:8000/api/ws/live`;
  return `${protocol === "https:" ? "wss" : "ws"}://${host}/api/ws/live`;
}

/**
 * Live event stream: seeds from /events/recent, then appends WebSocket pushes.
 * While paused, events keep buffering (counted in `pending`) and render on resume.
 */
export function useLiveEvents(max = 120) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [pending, setPending] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);
  const buffer = useRef<LiveEvent[]>([]);
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry: ReturnType<typeof setTimeout>;

    fetcher("/api/events/recent?limit=60")
      .then((d: { events: LiveEvent[] }) => {
        setEvents((cur) => (cur.length ? cur : d.events));
        if (d.events[0]) setLastEventAt((t) => t ?? new Date(d.events[0].ts).getTime());
      })
      .catch(() => {});

    const connect = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => setConnected(true);
      ws.onmessage = (m) => {
        try {
          buffer.current.push(JSON.parse(m.data));
          setLastEventAt(Date.now());
        } catch {}
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 3000);
      };
    };
    connect();

    // Batch renders: brute-force bursts can push hundreds of events per second.
    const flush = setInterval(() => {
      if (!buffer.current.length) return;
      if (pausedRef.current) {
        if (buffer.current.length > max) buffer.current.splice(0, buffer.current.length - max);
        setPending(buffer.current.length);
        return;
      }
      const batch = buffer.current.splice(0).reverse();
      setPending(0);
      setEvents((cur) => [...batch, ...cur].slice(0, max));
    }, 400);

    return () => {
      closed = true;
      clearTimeout(retry);
      clearInterval(flush);
      ws?.close();
    };
  }, [max]);

  return { events, connected, paused, setPaused, pending, lastEventAt };
}

// ---------------------------------------------------------------- formatting

export const fmt = (n: number | null | undefined) =>
  n == null ? "–" : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}k` : n.toLocaleString();

export function ago(ts: string | null | undefined) {
  if (!ts) return "–";
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const clock = (ts: string) =>
  new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

/** Event family -> categorical slot. Identity follows the family, never rank. */
export function family(e: Pick<LiveEvent, "event_type" | "cves">): "login" | "exploit" | "shell" | "other" {
  if (e.cves?.length || e.event_type === "exploit") return "exploit";
  if (e.event_type === "login_attempt") return "login";
  if (e.event_type === "command" || e.event_type === "download") return "shell";
  return "other";
}
export const FAMILY_LABEL = { login: "Login attempt", exploit: "Exploit", shell: "Shell / payload", other: "Scan / probe" };
export const FAMILY_VAR = { login: "var(--s-login)", exploit: "var(--s-exploit)", shell: "var(--s-shell)", other: "var(--s-other)" };

const subscribeReducedMotion = (cb: () => void) => {
  const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
};
/** True when the OS asks for reduced motion (the globe and feed then render statically). */
export function useReducedMotion() {
  return useSyncExternalStore(
    subscribeReducedMotion,
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    () => false,
  );
}

/** Re-render every `ms` so "Xs ago" labels stay current. */
export function useNow(ms = 1000) {
  const [now, setNow] = useState(0); // 0 until mounted: the clock is not read during prerender
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}

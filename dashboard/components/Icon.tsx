// Minimal stroke icons (Lucide-style geometry, 24px grid). Decorative unless a label is given.
const PATHS = {
  alert: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01",
  octagon: "M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9zM12 8v4M12 16h.01",
  check: "M20 6 9 17l-5-5",
  download: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3",
  pause: "M6 4h4v16H6zM14 4h4v16h-4z",
  play: "m6 3 14 9-14 9z",
  terminal: "m4 17 6-6-6-6M12 19h8",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  sun: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4",
  moon: "M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z",
} as const;

export type IconName = keyof typeof PATHS;

export default function Icon({ name, label }: { name: IconName; label?: string }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : true}>
      <path d={PATHS[name]} />
    </svg>
  );
}

/** Country as an ISO code chip: renders the same on every OS (Windows has no flag emoji). */
export function CountryCode({ cc, name }: { cc: string | null | undefined; name?: string | null }) {
  return (
    <span className="cc" title={cc ? (name ?? cc) : "Unknown / private network"} aria-hidden={name ? undefined : true}>
      {cc ?? "–"}
    </span>
  );
}

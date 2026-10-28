"use client";

import Link from "next/link";
import { useId, useRef, useState, type ReactNode } from "react";
import { fmt } from "@/lib/api";

// ---------------------------------------------------------------- stat tile

export function Tile({ label, value, note }: { label: string; value: ReactNode; note?: ReactNode }) {
  return (
    <div className="tile">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {note && <div className="note">{note}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- line chart

type Point = { t: string } & Record<string, number | string>;

/** Single-series area/line chart with crosshair tooltip. Small multiples instead of dual axes. */
export function LineChart({
  data, field, color, label, height = 160,
}: { data: Point[]; field: string; color: string; label: string; height?: number }) {
  const ref = useRef<SVGSVGElement>(null);
  const gid = useId();
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);
  const [showTable, setShowTable] = useState(false);

  const W = 600, H = height, padL = 36, padR = 8, padT = 8, padB = 22;
  const vals = data.map((d) => Number(d[field]) || 0);
  const max = niceMax(Math.max(1, ...vals));
  const x = (i: number) => padL + (i / Math.max(1, data.length - 1)) * (W - padL - padR);
  const y = (v: number) => padT + (1 - v / max) * (H - padT - padB);
  const line = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(vals.length - 1)},${y(0)}L${x(0)},${y(0)}Z`;
  const ticks = [0, max / 2, max];
  const xTicks = data.length > 1 ? [0, Math.floor((data.length - 1) / 2), data.length - 1] : [0];
  const total = vals.reduce((a, b) => a + b, 0);

  const onMove = (e: React.PointerEvent) => {
    const r = ref.current!.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = Math.round(((px - padL) / (W - padL - padR)) * (data.length - 1));
    if (i >= 0 && i < data.length) setHover({ i, x: e.clientX, y: e.clientY });
  };

  return (
    <div>
      <div className="card-head">
        <h2 className="row"><span className="dot" style={{ background: color }} />{label}</h2>
        <span className="sub">
          {fmt(total)} total ·{" "}
          <button onClick={() => setShowTable((s) => !s)} className="linkbtn" style={linkBtn}>
            {showTable ? "chart" : "table"}
          </button>
        </span>
      </div>
      {showTable ? (
        <div className="scroll-x" style={{ maxHeight: H, overflowY: "auto" }}>
          <table className="data">
            <thead><tr><th>Time (UTC)</th><th className="num">{label}</th></tr></thead>
            <tbody>
              {data.filter((d) => Number(d[field])).map((d) => (
                <tr key={d.t}><td className="mono">{d.t.slice(0, 16).replace("T", " ")}</td><td className="num">{fmt(Number(d[field]))}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <svg ref={ref} viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none"
             onPointerMove={onMove} onPointerLeave={() => setHover(null)} role="img"
             aria-label={`${label} over time, ${fmt(total)} total`} style={{ display: "block", touchAction: "none" }}>
          <defs>
            <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity="0.28" />
              <stop offset="1" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} stroke={t ? "var(--grid)" : "var(--baseline)"} strokeWidth="1" vectorEffect="non-scaling-stroke" />
              <text x={padL - 6} y={y(t) + 4} textAnchor="end" fontSize="11" fill="var(--muted)" style={{ fontVariantNumeric: "tabular-nums" }}>{fmt(t)}</text>
            </g>
          ))}
          {xTicks.map((i) => (
            <text key={i} x={x(i)} y={H - 6} fontSize="11" fill="var(--muted)"
                  textAnchor={i === 0 ? "start" : i === data.length - 1 ? "end" : "middle"}>
              {data[i] && tickLabel(data[i].t, data)}
            </text>
          ))}
          <path d={area} fill={`url(#${gid})`} />
          <path d={line} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
          {hover && (
            <line x1={x(hover.i)} x2={x(hover.i)} y1={padT} y2={y(0)} stroke="var(--muted)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
          )}
        </svg>
      )}
      {hover && !showTable && data[hover.i] && (
        <div className="tip" style={{ left: hover.x + 14, top: hover.y - 10 }}>
          <div className="t">{new Date(data[hover.i].t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</div>
          <div className="r"><span className="row"><span className="dot" style={{ background: color }} />{label}</span><span>{fmt(vals[hover.i])}</span></div>
        </div>
      )}
    </div>
  );
}

const linkBtn: React.CSSProperties = { background: "none", border: 0, padding: 0, color: "var(--link)", cursor: "pointer", font: "inherit" };

function tickLabel(t: string, data: Point[]) {
  const d = new Date(t);
  const span = new Date(data[data.length - 1].t).getTime() - new Date(data[0].t).getTime();
  return span > 2 * 86400e3
    ? d.toLocaleDateString([], { month: "short", day: "numeric" })
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function niceMax(v: number) {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return v;
}

// ---------------------------------------------------------------- sparkline

export function Sparkline({ values, color = "var(--s-exploit)", w = 96, h = 24 }: { values: number[]; color?: string; w?: number; h?: number }) {
  if (!values.length) return null;
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${((i / Math.max(1, values.length - 1)) * (w - 2) + 1).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`);
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden style={{ display: "block" }}>
      <line x1="0" x2={w} y1={h - 1.5} y2={h - 1.5} stroke="var(--baseline)" strokeWidth="1" />
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ---------------------------------------------------------------- bar list (ranked magnitude, one color)

export interface BarItem { key: string; label: ReactNode; value: number; href?: string; title?: string; sub?: ReactNode }

export function BarList({ items, empty = "No data in this window yet", unit }: { items: BarItem[]; empty?: string; unit?: string }) {
  if (!items.length) return <div className="empty">{empty}</div>;
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="barlist" role="list">
      {items.map((it) => {
        const inner = (
          <>
            <span className="fill" style={{ width: `${Math.max(1.5, (it.value / max) * 100)}%` }} />
            <span className="lbl" title={it.title}>{it.label}</span>
            <span className="val">{fmt(it.value)}{unit ? ` ${unit}` : ""}{it.sub}</span>
          </>
        );
        return it.href ? (
          <Link key={it.key} href={it.href} className="barrow" role="listitem">{inner}</Link>
        ) : (
          <div key={it.key} className="barrow" role="listitem">{inner}</div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------- meter (0..1 probability)

export function Meter({ value, label }: { value: number | null | undefined; label?: string }) {
  if (value == null) return <span className="muted">–</span>;
  return (
    <span className="row" style={{ gap: 6, flexWrap: "nowrap" }} title={label}>
      <svg width="48" height="6" aria-hidden>
        <rect x="0" y="0" width="48" height="6" rx="3" fill="var(--grid)" />
        <rect x="0" y="0" width={Math.max(3, value * 48)} height="6" rx="3" fill="var(--q5)" />
      </svg>
      <span style={{ fontVariantNumeric: "tabular-nums" }}>{pct(value)}</span>
    </span>
  );
}

/** Never round a probability up to a misleading 100%. */
function pct(v: number) {
  const p = v * 100;
  if (p >= 99.95) return ">99.9%";
  return p >= 10 ? `${Math.floor(p)}%` : `${p.toFixed(1)}%`;
}

import { ImageResponse } from "next/og";
import { AUTHOR } from "@/lib/site";

// The link-preview card (LinkedIn, Slack, Discord, X). Rendered once at build time.
export const alt = "Honeyjar: a live honeynet and threat-intelligence dashboard";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const HEX = "M50 0l43.3 25v50L50 100 6.7 75V25z";

export default function Image() {
  // a loose honeycomb drifting off the right edge, lighter toward the centre
  const cells = [
    [860, 40, 0.9], [950, 92, 0.55], [1040, 40, 0.75], [1130, 92, 0.4], [860, 144, 0.35], [1040, 144, 0.95],
    [950, 196, 0.8], [1130, 196, 0.6], [860, 248, 0.6], [1040, 248, 0.45], [950, 300, 0.3], [1130, 300, 0.85],
    [1040, 352, 0.5], [950, 404, 0.65], [1130, 404, 0.35], [1040, 456, 0.25],
  ] as const;
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", position: "relative", padding: "64px 72px",
        background: "radial-gradient(ellipse at 80% 30%, #3a2810 0%, #1a1208 55%, #0d0905 100%)", color: "#fbf2df" }}>
        <svg width="1200" height="630" viewBox="0 0 1200 630" style={{ position: "absolute", left: 0, top: 0 }}>
          {cells.map(([x, y, o], i) => (
            <path key={i} d={HEX} transform={`translate(${x} ${y}) scale(0.9)`} fill="#e8a317" fillOpacity={o * 0.85}
              stroke="#0d0905" strokeWidth="4" />
          ))}
        </svg>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", width: 780 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 18, fontSize: 30, color: "#f2b33d", letterSpacing: 2 }}>
            <div style={{ width: 14, height: 14, borderRadius: 7, background: "#2f9e44" }} />
            LIVE HONEYNET
          </div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <div style={{ fontSize: 132, fontWeight: 700, letterSpacing: -4, lineHeight: 1 }}>honeyjar</div>
            <div style={{ fontSize: 38, marginTop: 22, color: "#dccaa6", lineHeight: 1.3 }}>
              Real attacks on internet-facing honeypots, classified by CVE and MITRE ATT&amp;CK.
            </div>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 28, color: "#ab9878" }}>
            <span>honeyjar.tech</span>
            <span>by {AUTHOR.name}</span>
          </div>
        </div>
      </div>
    ),
    size,
  );
}

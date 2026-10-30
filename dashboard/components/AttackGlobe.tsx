"use client";

import { cellToChildren, cellToLatLng, getRes0Cells, latLngToCell } from "h3-js";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import Globe, { type GlobeMethods } from "react-globe.gl";
import { MeshPhongMaterial } from "three";
import { FAMILY_LABEL, family, useReducedMotion, type LiveEvent } from "@/lib/api";

type Sensor = { id: string; label: string; lat: number | null; lon: number | null };
type Cell = { lat: number; lng: number; land: boolean };
type HexBin = { points: Cell[] };
type Arc = { startLat: number; startLng: number; endLat: number; endLng: number; color: string; gap: number };
type Ripple = { lat: number; lng: number; color: string };
type Hive = { lat: number; lng: number; label: string };

// Must match RES in scripts/build-land-hexes.mjs. ~5,900 cells planet-wide (~160 km edges):
// big, legible comb that stays cheap to render.
const RES = 2;
const BEE_MS = 2600; // one bee-dash travels the whole arc in this time
const MAX_ARCS = 40;
const MAX_RIPPLES = 30;

// The planet as a honeycomb: land cells are capped honey, ocean cells are empty wax comb.
// Opaque on purpose: merged hex geometry ignores per-cell alpha, so tones are pre-mixed
// against the sphere behind them. One palette per theme: a dark amber jar, or pale fresh wax.
const PALETTE = {
  dark: { cappedTop: "#d99a26", cappedSide: "#7a4f0c", waxTop: "#3a2810", waxSide: "#2a1c0b", atmosphere: "#e8a317" },
  light: { cappedTop: "#e2a42c", cappedSide: "#b07a1c", waxTop: "#f4e6c4", waxSide: "#dcc394", atmosphere: "#f2b33d" },
};

// Sensors are drawn as a skep beehive.
export const HIVE_SVG = `<svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
<g fill="#f2b33d" stroke="#6e4705" stroke-width="1.3">
<rect x="10" y="4" width="12" height="5.5" rx="2.75"/><rect x="7" y="9.5" width="18" height="5.5" rx="2.75"/>
<rect x="5" y="15" width="22" height="5.5" rx="2.75"/><rect x="6" y="20.5" width="20" height="5.5" rx="2.75"/></g>
<rect x="3" y="26" width="26" height="3" rx="1.5" fill="#6e4705"/><path d="M13 26a3 3 0 0 1 6 0z" fill="#2a1c0c"/></svg>`;

// The sphere shows through the gaps between cells, outlining the comb.
// Dark: deep amber glass, as if seen through the honey jar. Light: darker beeswax lines.
const MATERIAL = {
  dark: new MeshPhongMaterial({ color: "#1f1305", emissive: "#0d0702", specular: "#5c3f10", shininess: 18 }),
  light: new MeshPhongMaterial({ color: "#b8945a", emissive: "#4a3412", specular: "#fff1cc", shininess: 10 }),
};

// Default globe.gl camera: 50 degree vertical field of view; the globe radius is the altitude unit.
const HALF_FOV = (25 * Math.PI) / 180;
/** Camera altitude at which the whole globe fits the panel with a little margin, whatever its shape. */
function fitAltitude(w: number, h: number) {
  const halfH = Math.atan(Math.tan(HALF_FOV) * (w / Math.max(1, h)));
  const half = Math.min(HALF_FOV, halfH);
  return Math.max(1.65, 1 / Math.sin(half * 0.88) - 1);
}

// Accessors live at module scope on purpose: globe.gl compares props by identity, and a new
// function on every React render makes it rebuild every hexagon and arc (the old lag).
const isLand = (d: object) => (d as HexBin).points[0].land;
const hexAltitude = (d: object) => (isLand(d) ? 0.012 : 0.002);
const hexColors = (p: (typeof PALETTE)["dark"]) => ({
  top: (d: object) => (isLand(d) ? p.cappedTop : p.waxTop),
  side: (d: object) => (isLand(d) ? p.cappedSide : p.waxSide),
});
const HEX = { dark: hexColors(PALETTE.dark), light: hexColors(PALETTE.light) };
const arcColor = (d: object) => (d as Arc).color;
const arcGap = (d: object) => (d as Arc).gap;
const solidGap = () => 0;
const ringColor = (d: object) => (t: number) => withAlpha((d as Ripple).color, 1 - t);
const hiveElement = (d: object) => {
  const el = document.createElement("div");
  el.innerHTML = HIVE_SVG;
  el.title = `Sensor hive: ${(d as Hive).label}`;
  el.style.cssText = "pointer-events:auto;transform:translate(-50%,-90%);filter:drop-shadow(0 0 6px rgba(242,179,61,.6))";
  return el;
};

/**
 * Resolve a color token to rgb() through a probe element: tokens are light-dark() values,
 * which only become concrete colors on an element, so arcs get the current theme's family colors.
 */
function resolveColor(host: HTMLElement, token: string) {
  const probe = document.createElement("span");
  probe.style.color = `var(${token})`;
  host.appendChild(probe);
  const c = getComputedStyle(probe).color;
  probe.remove();
  return c;
}

/** The theme actually in effect: an explicit choice from the header toggle, else the OS setting. */
function useDarkTheme() {
  const [dark, setDark] = useState(true);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const read = () => {
      const t = document.documentElement.dataset.theme;
      setDark(t ? t === "dark" : mq.matches);
    };
    read();
    mq.addEventListener("change", read);
    window.addEventListener("themechange", read);
    return () => {
      mq.removeEventListener("change", read);
      window.removeEventListener("themechange", read);
    };
  }, []);
  return dark;
}

type Props = { events: LiveEvent[]; sensors: Sensor[]; paused?: boolean };

/**
 * Next keeps visited routes alive in a hidden <Activity>. Hiding runs effect cleanups, and
 * react-globe.gl's cleanup tears its scene down for good, so the planet was gone on the way back.
 * Mount the scene only while the page is visible: every return gets a fresh one.
 */
export default function AttackGlobe(props: Props) {
  const [shown, setShown] = useState(false);
  useLayoutEffect(() => {
    setShown(true);
    return () => setShown(false);
  }, []);
  return shown ? <GlobeScene {...props} /> : <div className="globe-wrap" />;
}

function GlobeScene({ events, sensors, paused = false }: Props) {
  const reduced = useReducedMotion();
  const still = reduced || paused;
  const wrap = useRef<HTMLDivElement>(null);
  const globe = useRef<GlobeMethods | undefined>(undefined);
  const [size, setSize] = useState({ w: 600, h: 520 });
  const [colors, setColors] = useState({ login: "rgb(196,135,15)", exploit: "rgb(214,75,134)", shell: "rgb(116,132,230)", other: "rgb(107,95,75)" });
  const dark = useDarkTheme();
  const theme = dark ? "dark" : "light";

  useEffect(() => {
    const el = wrap.current!;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Arc colors follow the theme's validated family palette.
  useEffect(() => {
    const el = wrap.current!;
    setColors({
      login: resolveColor(el, "--s-login"),
      exploit: resolveColor(el, "--s-exploit"),
      shell: resolveColor(el, "--s-shell"),
      other: resolveColor(el, "--s-other"),
    });
  }, [dark]);

  useEffect(() => {
    const g = globe.current;
    if (!g) return;
    g.controls().enableZoom = false;
    g.pointOfView({ lat: 25, lng: 15 });
    // Retina screens otherwise render up to 9x the pixels; 1.5x is visually indistinguishable here.
    g.renderer().setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  }, []);

  // Fit the whole globe to the panel: a tall phone panel needs the camera further back than a wide desktop one.
  useEffect(() => {
    globe.current?.pointOfView({ altitude: fitAltitude(size.w, size.h) });
  }, [size.w, size.h]);

  // Rotation, travelling bees and ripples all stop when paused or when the OS asks for reduced motion.
  useEffect(() => {
    const controls = globe.current?.controls();
    if (!controls) return;
    controls.autoRotate = !still;
    controls.autoRotateSpeed = 0.35;
  }, [still]);

  // Land cells are precomputed from Natural Earth 1:50m (scripts/build-land-hexes.mjs);
  // every other cell of the H3 grid is ocean, so only the land list is downloaded.
  const [land, setLand] = useState<[number, number][]>([]);
  useEffect(() => {
    fetch("/land-hexes.json").then((r) => r.json()).then(setLand).catch(() => {});
  }, []);
  const comb = useMemo<Cell[]>(() => {
    if (!land.length) return [];
    const landCells = new Set(land.map(([lat, lng]) => latLngToCell(lat, lng, RES)));
    return getRes0Cells().flatMap((base) =>
      cellToChildren(base, RES).map((c) => {
        const [lat, lng] = cellToLatLng(c);
        return { lat, lng, land: landCells.has(c) };
      }),
    );
  }, [land]);

  // Arc and ripple objects are cached per event so globe.gl keeps existing meshes and only
  // builds the new ones, instead of rebuilding all of them on every live update.
  const arcCache = useRef(new Map<string, Arc>());
  const fallbackSensor = sensors.find((s) => s.lat != null);
  const arcs = useMemo(() => {
    const next = new Map<string, Arc>();
    for (const e of events) {
      if (e.lat == null || e.lon == null) continue;
      const key = `${e.ts}|${e.src_ip}|${e.event_type}`;
      next.set(key, arcCache.current.get(key) ?? {
        startLat: e.lat,
        startLng: e.lon,
        endLat: e.sensor_lat ?? fallbackSensor?.lat ?? 50,
        endLng: e.sensor_lon ?? fallbackSensor?.lon ?? 8,
        color: colors[family(e)],
        gap: Math.random(),
      });
      if (next.size >= MAX_ARCS) break;
    }
    arcCache.current = next;
    return [...next.values()];
  }, [events, colors, fallbackSensor]);

  const rippleCache = useRef(new Map<string, Ripple>());
  const ripples = useMemo(() => {
    const next = new Map<string, Ripple>();
    for (const e of events) {
      if (e.lat == null || e.lon == null) continue;
      const key = `${e.lat.toFixed(1)},${e.lon.toFixed(1)}`;
      if (!next.has(key)) next.set(key, rippleCache.current.get(key) ?? { lat: e.lat, lng: e.lon, color: colors[family(e)] });
      if (next.size >= MAX_RIPPLES) break;
    }
    rippleCache.current = next;
    return [...next.values()];
  }, [events, colors]);

  const hives = useMemo<Hive[]>(
    () => sensors.filter((s) => s.lat != null).map((s) => ({ lat: s.lat!, lng: s.lon!, label: s.label })),
    [sensors],
  );

  return (
    <div className="globe-wrap" ref={wrap}>
      <p className="sr-only">Globe showing {arcs.length} recent attacks travelling from their source locations to our sensors. The live feed lists the same events as text.</p>
      <Globe
        ref={globe}
        width={size.w}
        height={size.h}
        backgroundColor="rgba(0,0,0,0)"
        showAtmosphere
        atmosphereColor={PALETTE[theme].atmosphere}
        atmosphereAltitude={0.16}
        globeMaterial={MATERIAL[theme]}
        hexBinPointsData={comb}
        hexBinPointLat="lat"
        hexBinPointLng="lng"
        hexBinResolution={RES}
        hexBinMerge
        hexMargin={0.14}
        hexAltitude={hexAltitude}
        hexTopColor={HEX[theme].top}
        hexSideColor={HEX[theme].side}
        hexTopCurvatureResolution={8}
        hexTransitionDuration={0}
        arcsData={arcs}
        arcColor={arcColor}
        // Attacks fly in as a line of bees: short dashes travelling along the arc.
        arcStroke={still ? 0.4 : 0.8}
        arcAltitudeAutoScale={0.45}
        arcDashLength={still ? 1 : 0.025}
        arcDashGap={still ? 0 : 0.07}
        arcDashInitialGap={still ? solidGap : arcGap}
        arcDashAnimateTime={still ? 0 : BEE_MS}
        arcsTransitionDuration={0}
        ringsData={still ? [] : ripples}
        ringColor={ringColor}
        ringMaxRadius={2.6}
        ringPropagationSpeed={1.6}
        ringRepeatPeriod={1600}
        htmlElementsData={hives}
        htmlElement={hiveElement}
        htmlAltitude={0.015}
        htmlTransitionDuration={0}
      />
      <div className="legend" aria-label="Arc colors">
        {(["login", "exploit", "shell", "other"] as const).map((f) => (
          <span key={f}><span className="dot" style={{ background: colors[f] }} />{FAMILY_LABEL[f]}</span>
        ))}
        <span><span className="legend-hive" dangerouslySetInnerHTML={{ __html: HIVE_SVG }} />Sensor hive</span>
      </div>
    </div>
  );
}

function withAlpha(rgb: string, a: number) {
  const [r, g, b] = rgb.match(/\d+/g) ?? ["0", "0", "0"];
  return `rgba(${r},${g},${b},${Math.max(0, a).toFixed(2)})`;
}

// Precomputes the globe's honeycomb: every H3 cell (resolution 2, ~160 km edges) that touches land
// in Natural Earth 1:50m. Doing this at build time instead of in the browser keeps narrow land
// (Japan, Italy, the Horn of Africa, island chains) intact and costs visitors nothing.
//
//   node scripts/build-land-hexes.mjs   ->  public/land-hexes.json  ([[lat, lng], ...] cell centres)
//
// H3's own polygon fill is not used: Afro-Eurasia is a single ring spanning > 180° of longitude,
// which H3 misreads as its complement (it fills the oceans). Instead every cell on the planet is
// tested with a point-in-polygon check in lng/lat space, which is valid here because Natural Earth
// splits rings at the antimeridian.
import { readFileSync, writeFileSync } from "node:fs";
import { cellToBoundary, cellToChildren, cellToLatLng, getRes0Cells } from "h3-js";
import { feature } from "topojson-client";

const RES = 2;
const topo = JSON.parse(readFileSync(new URL("../node_modules/world-atlas/land-50m.json", import.meta.url)));
const land = feature(topo, topo.objects.land);

// Bucket every ring edge by 1° latitude row, so a point only tests the edges that can cross its ray.
const rows = Array.from({ length: 181 }, () => []);
for (const f of land.features) {
  const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
  for (const ring of polys.flat()) {
    for (let i = 0; i < ring.length - 1; i++) {
      const [x1, y1] = ring[i];
      const [x2, y2] = ring[i + 1];
      const lo = Math.floor(Math.min(y1, y2)) + 90;
      const hi = Math.floor(Math.max(y1, y2)) + 90;
      for (let r = Math.max(0, lo); r <= Math.min(180, hi); r++) rows[r].push([x1, y1, x2, y2]);
    }
  }
}

/** Even-odd ray cast eastwards; holes (lakes) flip parity, separate polygons never overlap. */
function onLand(lat, lng) {
  let inside = false;
  for (const [x1, y1, x2, y2] of rows[Math.floor(lat) + 90] ?? []) {
    if (y1 > lat !== y2 > lat && lng < x1 + ((lat - y1) * (x2 - x1)) / (y2 - y1)) inside = !inside;
  }
  return inside;
}

const points = [];
for (const base of getRes0Cells()) {
  for (const cell of cellToChildren(base, RES)) {
    const [lat, lng] = cellToLatLng(cell);
    // A cell counts as land if its centre or any corner is on land: keeps thin islands and coasts.
    if (onLand(lat, lng) || cellToBoundary(cell).some(([la, ln]) => onLand(la, ln))) {
      points.push([Math.round(lat * 100) / 100, Math.round(lng * 100) / 100]);
    }
  }
}

writeFileSync(new URL("../public/land-hexes.json", import.meta.url), JSON.stringify(points));
console.log(`land-hexes: ${points.length} cells at res ${RES}`);

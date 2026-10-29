import type { MetadataRoute } from "next";
import { PAGES, SITE_URL } from "@/lib/site";

export default function sitemap(): MetadataRoute.Sitemap {
  return PAGES.map((p) => ({
    url: `${SITE_URL}${p.path}`,
    changeFrequency: p.path === "/about" ? "monthly" : "hourly", // the data pages change constantly
    priority: p.path === "/" ? 1 : 0.7,
  }));
}

import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/site";

// Index the dashboard pages; keep the API and the per-attacker profiles (/ip/<address>) out of search results.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/ip/"] },
    sitemap: `${SITE_URL}/sitemap.xml`,
    host: SITE_URL,
  };
}

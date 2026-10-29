// Public identity of the deployment: canonical URL for search engines and link previews, and its author.
export const SITE_URL = process.env.SITE_URL ?? "https://honeyjar.tech";
export const SITE_NAME = "Honeyjar";
export const SITE_DESCRIPTION =
  "A live honeynet and threat-intelligence dashboard: real attacks on internet-facing honeypots, classified by CVE " +
  "(with CISA KEV and EPSS) and MITRE ATT&CK, with attacker origins, stolen credentials and captured payloads.";

export const AUTHOR = {
  name: "Velislav Rumenov",
  role: "A backend software engineer",
  linkedin: "https://www.linkedin.com/in/velislav-rumenov",
  github: "https://github.com/velislavr",
  repo: "https://github.com/velislavr/honeyjar",
};

/** Indexable pages, in nav order. Attacker profiles (/ip/...) are deliberately left out. */
export const PAGES = [
  { path: "/", title: "Live attack map", description: "Real connections hitting Honeyjar's honeypot sensors right now, on a 3D globe with a live event feed." },
  { path: "/vulnerabilities", title: "Exploited vulnerabilities", description: "Which CVEs attackers are exploiting against our honeypots, with CISA KEV status, EPSS and CVSS scores." },
  { path: "/attackers", title: "Attackers & infrastructure", description: "Where attacks come from: source countries, hosting networks (ASNs), targeted ports and the most active IPs." },
  { path: "/credentials", title: "Credential stuffing", description: "The usernames and passwords bots try against SSH and Telnet honeypots, and which ones they reuse most." },
  { path: "/ttps", title: "MITRE ATT&CK coverage", description: "What attackers do after they get a shell, mapped to MITRE ATT&CK techniques and tactics." },
  { path: "/payloads", title: "Payloads & web probes", description: "Malware hashes, download URLs and the web paths and user agents scanners probe for." },
  { path: "/about", title: "How it works", description: "The architecture and methodology behind Honeyjar: sensors, WireGuard shipping, enrichment and safety design." },
] as const;

// The build-time card from app/opengraph-image.tsx.
const PREVIEW_IMAGE = { url: "/opengraph-image", width: 1200, height: 630, alt: "Honeyjar: a live honeynet and threat-intelligence dashboard" };

export const pageMeta = (path: (typeof PAGES)[number]["path"]) => {
  const p = PAGES.find((x) => x.path === path)!;
  return {
    title: p.title, description: p.description, alternates: { canonical: p.path },
    // nested metadata is replaced, not merged, per segment: repeat the shared preview fields here
    openGraph: { type: "website" as const, siteName: SITE_NAME, url: p.path, title: `${p.title} · ${SITE_NAME}`,
      description: p.description, images: [PREVIEW_IMAGE] },
    twitter: { card: "summary_large_image" as const, title: `${p.title} · ${SITE_NAME}`, description: p.description,
      images: [PREVIEW_IMAGE.url] },
  };
};

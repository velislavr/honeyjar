import type { Metadata } from "next";
import { DM_Mono, Fraunces, Nunito_Sans } from "next/font/google";
import Shell from "@/components/Shell";
import { AUTHOR, SITE_DESCRIPTION, SITE_NAME, SITE_URL } from "@/lib/site";
import "./globals.css";

// Self-hosted at build time by next/font: no requests to Google from the browser, no layout shift.
// Fraunces' SOFT axis rounds its terminals — the "soft serif" of the honey brand.
const display = Fraunces({ subsets: ["latin"], axes: ["SOFT", "WONK", "opsz"], variable: "--font-display", display: "swap" });
const sans = Nunito_Sans({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = DM_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: `${SITE_NAME}: live honeynet threat map`, template: `%s · ${SITE_NAME}` },
  description: SITE_DESCRIPTION,
  applicationName: SITE_NAME,
  authors: [{ name: AUTHOR.name, url: AUTHOR.linkedin }],
  creator: AUTHOR.name,
  keywords: ["honeypot", "honeynet", "threat intelligence", "cybersecurity", "CVE", "CISA KEV", "EPSS",
    "MITRE ATT&CK", "Cowrie", "attack map", "botnet", "Mirai", AUTHOR.name],
  alternates: { canonical: "/" },
  openGraph: { type: "website", siteName: SITE_NAME, url: "/", title: `${SITE_NAME}: live honeynet threat map`, description: SITE_DESCRIPTION },
  twitter: { card: "summary_large_image", title: `${SITE_NAME}: live honeynet threat map`, description: SITE_DESCRIPTION },
};

// Applies a saved light/dark choice before first paint (no theme flash). Defaults to the OS setting.
const themeScript = `try{var t=localStorage.getItem("theme");if(t==="light"||t==="dark")document.documentElement.dataset.theme=t}catch(e){}`;

// Structured data: tells search engines what the site is and who built it, linking the author's profiles.
const author = { "@type": "Person", name: AUTHOR.name, jobTitle: "Backend Software Engineer", url: AUTHOR.linkedin,
  sameAs: [AUTHOR.linkedin, AUTHOR.github], knowsAbout: ["Backend engineering", "Cybersecurity", "Threat intelligence"] };
const jsonLd = JSON.stringify([
  { "@context": "https://schema.org", "@type": "WebSite", name: SITE_NAME, url: SITE_URL, description: SITE_DESCRIPTION, author, creator: author },
  { "@context": "https://schema.org", "@type": "SoftwareSourceCode", name: SITE_NAME, codeRepository: AUTHOR.repo,
    programmingLanguage: ["Python", "TypeScript"], author },
]).replace(/</g, "\\u003c");

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd }} />
      </head>
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}

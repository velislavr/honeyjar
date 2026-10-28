import type { Metadata } from "next";
import { DM_Mono, Fraunces, Nunito_Sans } from "next/font/google";
import Shell from "@/components/Shell";
import "./globals.css";

// Self-hosted at build time by next/font: no requests to Google from the browser, no layout shift.
// Fraunces' SOFT axis rounds its terminals — the "soft serif" of the honey brand.
const display = Fraunces({ subsets: ["latin"], axes: ["SOFT", "WONK", "opsz"], variable: "--font-display", display: "swap" });
const sans = Nunito_Sans({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = DM_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "Honeyjar — live threat map",
  description: "Live attack telemetry from a distributed honeynet: exploited CVEs, attacker origins, credentials and ATT&CK techniques.",
};

// Applies a saved light/dark choice before first paint (no theme flash). Defaults to the OS setting.
const themeScript = `try{var t=localStorage.getItem("theme");if(t==="light"||t==="dark")document.documentElement.dataset.theme=t}catch(e){}`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}

import { Suspense } from "react";
import type { Metadata } from "next";
import IpProfile from "@/components/IpProfile";

// One page per attacker IP: thin, ever-changing and not something to put in search results.
export const metadata: Metadata = { title: "Attacker profile", robots: { index: false, follow: true } };

export default function IpPage() {
  return (
    <Suspense fallback={<div className="empty">Loading profile…</div>}>
      <IpProfile />
    </Suspense>
  );
}

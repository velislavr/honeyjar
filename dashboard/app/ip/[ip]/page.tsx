import { Suspense } from "react";
import IpProfile from "@/components/IpProfile";

export default function IpPage() {
  return (
    <Suspense fallback={<div className="empty">Loading profile…</div>}>
      <IpProfile />
    </Suspense>
  );
}

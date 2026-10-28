"use client";

import Link from "next/link";
import { CountryCode } from "@/components/Icon";
import { FAMILY_LABEL, FAMILY_VAR, clock, family, type LiveEvent } from "@/lib/api";

function describe(e: LiveEvent) {
  switch (e.event_type) {
    case "login_attempt":
      return `${e.login_success ? "login accepted" : "login"} ${e.username ?? ""} / ${e.password ?? ""}`;
    case "command":
      return `$ ${e.command ?? ""}`;
    case "download":
      return `download ${e.download_url ?? "payload"}`;
    case "connect":
      return `connect ${e.proto ?? ""}:${e.dst_port ?? ""}`;
    default:
      return `${e.http_method ?? ""} ${e.http_path ?? ""}`;
  }
}

export default function LiveFeed({ events }: { events: LiveEvent[] }) {
  if (!events.length) return <div className="feed"><div className="empty">Waiting for the first attack…</div></div>;
  return (
    <div className="feed" role="log" aria-label="Recent attack events">
      {events.map((e, i) => {
        const f = family(e);
        return (
          <div className="feed-row" key={`${e.ts}-${e.src_ip}-${i}`}>
            <span className="time">{clock(e.ts)}</span>
            <div style={{ minWidth: 0 }}>
              <div className="who">
                <span className="dot" style={{ background: FAMILY_VAR[f] }} title={FAMILY_LABEL[f]} />
                <CountryCode cc={e.country_code} name={e.country} />
                <Link className="link mono" href={`/ip/${e.src_ip}`}>{e.src_ip}</Link>
                <span className="muted">{FAMILY_LABEL[f]}</span>
                {e.cves?.map((c) => <span key={c} className="badge cve">{c}</span>)}
              </div>
              <div className="what" title={describe(e)}>{describe(e)}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

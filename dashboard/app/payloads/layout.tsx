import { pageMeta } from "@/lib/site";

export const metadata = pageMeta("/payloads");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}

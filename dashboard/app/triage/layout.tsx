import { pageMeta } from "@/lib/site";

export const metadata = pageMeta("/triage");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}

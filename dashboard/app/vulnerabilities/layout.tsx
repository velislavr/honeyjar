import { pageMeta } from "@/lib/site";

export const metadata = pageMeta("/vulnerabilities");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}

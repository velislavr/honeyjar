import { pageMeta } from "@/lib/site";

export const metadata = pageMeta("/ttps");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}

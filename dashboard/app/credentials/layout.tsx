import { pageMeta } from "@/lib/site";

export const metadata = pageMeta("/credentials");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}

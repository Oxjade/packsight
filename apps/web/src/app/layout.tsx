import type { Metadata } from "next";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import "./globals.css";

export const metadata: Metadata = {
  title: "packsight",
  description: "Multichain security scanner for versioning, deprecation exposure and dependency hygiene."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="topbar">
            <div className="topbar-inner">
              <Link className="brand" href="/">
                <span className="brand-mark" aria-hidden="true">
                  <ShieldCheck size={18} />
                </span>
                packsight
              </Link>
              <nav className="nav" aria-label="Primary">
                <Link href="/rules">Rules</Link>
                <a href="/docs">Docs</a>
                <a href="https://osv.dev" rel="noreferrer" target="_blank">
                  OSV
                </a>
              </nav>
            </div>
          </header>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}

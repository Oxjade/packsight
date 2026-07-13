import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "http://localhost:3000");
const description =
  "Multichain audit intelligence for legacy on-chain interfaces, package linkage, upgrade posture and missing evidence.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "packsight",
    template: "%s | packsight"
  },
  description,
  applicationName: "packsight",
  icons: {
    icon: "/icon.svg",
    shortcut: "/icon.svg"
  },
  openGraph: {
    title: "packsight",
    description,
    url: "/",
    siteName: "packsight",
    type: "website",
    images: [
      {
        url: "/opengraph-image",
        width: 1200,
        height: 630,
        alt: "packsight package and magnifier logo with product summary"
      }
    ]
  },
  twitter: {
    card: "summary_large_image",
    title: "packsight",
    description,
    images: ["/opengraph-image"]
  }
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
                  <img alt="" height="24" src="/icon.svg" width="24" />
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

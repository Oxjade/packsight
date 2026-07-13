import { ImageResponse } from "next/og";

export const alt = "packsight - audit legacy on-chain interfaces";
export const size = {
  width: 1200,
  height: 630
};
export const contentType = "image/png";

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          background: "#ffffff",
          color: "#100909",
          padding: "72px",
          fontFamily: "Arial, Helvetica, sans-serif"
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 28, maxWidth: 710 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
            <LogoMark />
            <div style={{ fontSize: 48, fontWeight: 800 }}>packsight</div>
          </div>
          <div style={{ fontSize: 72, lineHeight: 1.02, fontWeight: 850 }}>
            Audit legacy on-chain interfaces that may still be reachable.
          </div>
          <div style={{ color: "#4b4342", fontSize: 30, lineHeight: 1.35 }}>
            Package lineage, upgrade posture, callable surfaces and missing evidence for Sui, Solana and EVM audits.
          </div>
        </div>
        <div
          style={{
            width: 300,
            height: 300,
            borderRadius: 36,
            border: "2px solid #d5cfcf",
            background: "#fff4f3",
            display: "flex",
            alignItems: "center",
            justifyContent: "center"
          }}
        >
          <LogoMark large />
        </div>
      </div>
    ),
    size
  );
}

function LogoMark({ large = false }: { large?: boolean }) {
  const scale = large ? 3.1 : 1;
  return (
    <svg width={64 * scale} height={64 * scale} viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="14" fill="#ffffff" />
      <path
        d="M18 19.5 32 12l14 7.5v16.8L32 44l-14-7.7V19.5Z"
        fill="#fff4f3"
        stroke="#a9131f"
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <path
        d="M18.8 20 32 27.4 45.2 20M32 27.4V43"
        stroke="#a9131f"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="42" cy="42" r="9" fill="#ffffff" stroke="#3f3a3a" strokeWidth="3" />
      <path d="m48.7 48.7 7.3 7.3" stroke="#3f3a3a" strokeWidth="4" strokeLinecap="round" />
    </svg>
  );
}

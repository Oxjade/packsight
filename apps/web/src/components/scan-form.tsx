"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Play } from "lucide-react";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

export function ScanForm() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [chainFamily, setChainFamily] = useState("sui");
  const [network, setNetwork] = useState("mainnet");
  const [address, setAddress] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const addressLabel = chainFamily === "sui" ? "Package ID" : chainFamily === "solana" ? "Program ID" : "Contract address";
  const addressPlaceholder = chainFamily === "solana" ? "Base58 program ID" : "0x...";

  function submitScan(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    startTransition(async () => {
      const response = await fetch(`${apiUrl}/v1/scans`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": crypto.randomUUID()
        },
        body: JSON.stringify({
          targetType: "chain_address",
          chainFamily,
          network,
          address,
          repositoryUrl: repositoryUrl || undefined
        })
      });

      const body = (await response.json()) as { scanId?: string; error?: string };
      if (!response.ok || !body.scanId) {
        setError(body.error ?? "Scan could not be created.");
        return;
      }

      router.push(`/scans/${body.scanId}`);
    });
  }

  return (
    <form className="panel scan-panel" onSubmit={submitScan}>
      <h2>Run security scan</h2>
      <div className="field-group">
        <div className="field">
          <label htmlFor="chain">Chain</label>
          <select id="chain" value={chainFamily} onChange={(event) => setChainFamily(event.target.value)}>
            <option value="sui">Sui package</option>
            <option value="solana">Solana program</option>
            <option value="evm">EVM contract</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="network">Network</label>
          <select id="network" value={network} onChange={(event) => setNetwork(event.target.value)}>
            <option value="mainnet">mainnet</option>
            <option value="mainnet-beta">mainnet-beta</option>
            <option value="testnet">testnet</option>
            <option value="devnet">devnet</option>
            <option value="sepolia">sepolia</option>
            <option value="base">base</option>
            <option value="arbitrum">arbitrum</option>
            <option value="polygon">polygon</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="address">{addressLabel}</label>
          <input
            id="address"
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder={addressPlaceholder}
            required
          />
        </div>
        <div className="field">
          <label htmlFor="repo">Repository URL</label>
          <input
            id="repo"
            type="url"
            value={repositoryUrl}
            onChange={(event) => setRepositoryUrl(event.target.value)}
            placeholder="https://github.com/org/repo"
          />
        </div>
        <button className="button" type="submit" disabled={isPending}>
          <Play size={17} aria-hidden="true" />
          {isPending ? "Starting scan" : "Run security scan"}
        </button>
      </div>
      {error ? <p className="error-text">{error}</p> : null}
      <p className="notice">
        Sui scans resolve package versions and function diffs. Solana and EVM scans start with RPC metadata, upgradeability
        checks, and interface coverage when IDL or ABI data is available.
      </p>
    </form>
  );
}

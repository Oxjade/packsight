"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Play } from "lucide-react";
import type { ScanReport } from "@packsight/report-schema";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "/api";

export function ScanForm() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [chainFamily, setChainFamily] = useState("sui");
  const [network, setNetwork] = useState("mainnet");
  const [chainId, setChainId] = useState("");
  const [address, setAddress] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const addressLabel = chainFamily === "sui" ? "Package ID" : chainFamily === "solana" ? "Program ID" : "Contract address";
  const addressPlaceholder = chainFamily === "solana" ? "Base58 program ID" : "0x...";
  const isEvm = chainFamily === "evm";

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
          chainId: isEvm ? chainId : undefined,
          address,
          repositoryUrl: repositoryUrl || undefined
        })
      });

      const body = (await response.json()) as { scanId?: string; error?: string; report?: ScanReport };
      if (!response.ok || !body.scanId) {
        setError(body.error ?? "Scan could not be created.");
        return;
      }

      if (body.report) {
        window.sessionStorage.setItem(`packsight-report:${body.scanId}`, JSON.stringify(body.report));
        router.push(`/scans/${body.scanId}/report`);
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
          <select
            id="chain"
            value={chainFamily}
            onChange={(event) => {
              const nextChain = event.target.value;
              setChainFamily(nextChain);
              if (nextChain !== "evm") setChainId("");
            }}
          >
            <option value="sui">Sui package</option>
            <option value="solana">Solana program</option>
            <option value="evm">EVM contract</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="network">Network</label>
          <select
            id="network"
            value={network}
            onChange={(event) => {
              const nextNetwork = event.target.value;
              setNetwork(nextNetwork);
              if (isEvm && nextNetwork === "monad") setChainId("143");
            }}
          >
            <option value="mainnet">mainnet</option>
            <option value="monad">monad</option>
            <option value="mainnet-beta">mainnet-beta</option>
            <option value="testnet">testnet</option>
            <option value="devnet">devnet</option>
            <option value="sepolia">sepolia</option>
            <option value="base">base</option>
            <option value="arbitrum">arbitrum</option>
            <option value="polygon">polygon</option>
          </select>
        </div>
        {isEvm ? (
          <div className="field">
            <label htmlFor="chain-id">Chain ID</label>
            <input
              id="chain-id"
              inputMode="numeric"
              pattern="[0-9]+"
              value={chainId}
              onChange={(event) => setChainId(event.target.value.replace(/\D/g, ""))}
              placeholder={network === "monad" ? "143" : "1"}
              required
            />
          </div>
        ) : null}
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
        Sui scans resolve package versions and function diffs. Solana and EVM scans start with RPC metadata,
        upgradeability checks, and interface coverage when IDL or ABI data is available. EVM scans require a declared
        decimal chain ID and compare it against the RPC response when available.
      </p>
    </form>
  );
}

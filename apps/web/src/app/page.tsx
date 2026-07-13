import { AlertTriangle, CheckCircle2, FileSearch, GitBranch, LockKeyhole, Network, Radar, Route } from "lucide-react";
import { ScanForm } from "@/components/scan-form";

export default function HomePage() {
  return (
    <div className="page">
      <section className="intro">
        <div className="intro-copy">
          <h1>Audit legacy on-chain interfaces that may still be reachable.</h1>
          <p>
            packsight scans Sui packages, Solana programs and EVM contracts for legacy interfaces, upgradeability
            signals, package linkage changes and missing source or interface coverage. It separates confirmed facts from
            static analysis, heuristics, missing information and manual-review recommendations.
          </p>

          <div className="chain-strip" aria-label="Supported scan targets">
            <span className="chain-chip active">Sui package lineage</span>
            <span className="chain-chip active">Solana program metadata</span>
            <span className="chain-chip active">EVM proxy and ABI checks</span>
          </div>

          <div className="statement" aria-label="Product boundaries">
            <div className="statement-row">
              <CheckCircle2 size={19} aria-hidden="true" />
              <span>Reports include interface accessibility, package links, severity, confidence, evidence and limitations.</span>
            </div>
            <div className="statement-row">
              <AlertTriangle size={19} aria-hidden="true" />
              <span>packsight does not claim that every finding is exploitable or replace manual audit review.</span>
            </div>
          </div>
        </div>
        <ScanForm />
      </section>

      <section className="section" aria-labelledby="checked-heading">
        <h2 id="checked-heading">What packsight checks now</h2>
        <div className="section-grid">
          <article className="compact-card">
            <Radar size={20} aria-hidden="true" />
            <h3>Sui package lineage</h3>
            <p>
              Resolves package versions, Move modules, public/friend/private function accessibility, latest-package
              function diffs and Sui linkage changes.
            </p>
          </article>
          <article className="compact-card">
            <Network size={20} aria-hidden="true" />
            <h3>Solana program posture</h3>
            <p>
              Fetches program account metadata, parses upgradeable ProgramData when available and uses Anchor IDL for
              instruction-level coverage.
            </p>
          </article>
          <article className="compact-card">
            <Route size={20} aria-hidden="true" />
            <h3>EVM contract shape</h3>
            <p>
              Checks deployed bytecode, scan block, EIP-1967 proxy slots and ABI-derived functions when local or explorer
              ABI data is available.
            </p>
          </article>
          <article className="compact-card">
            <FileSearch size={20} aria-hidden="true" />
            <h3>Source and dependencies</h3>
            <p>
              Parses supplied source artifacts for Move heuristics, lockfile gaps, mutable dependencies, ABI files and IDL
              files without executing scanned project code.
            </p>
          </article>
          <article className="compact-card">
            <GitBranch size={20} aria-hidden="true" />
            <h3>Normalized reports</h3>
            <p>
              Every chain feeds the same report model: versions, callable surface, package links, dependencies, findings,
              coverage and scan point.
            </p>
          </article>
          <article className="compact-card">
            <LockKeyhole size={20} aria-hidden="true" />
            <h3>Manual-review boundaries</h3>
            <p>Runtime reachability and governance safety remain explicit limitations unless proven by source or chain evidence.</p>
          </article>
        </div>
      </section>
    </div>
  );
}

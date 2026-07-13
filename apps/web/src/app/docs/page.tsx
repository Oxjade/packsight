const sections = [
  { href: "#overview", label: "Overview" },
  { href: "#chains", label: "Chain coverage" },
  { href: "#reports", label: "Report model" },
  { href: "#evidence", label: "Evidence and limits" },
  { href: "#api", label: "API" },
  { href: "#operations", label: "Operations" }
];

export default function DocsPage() {
  return (
    <div className="page">
      <section className="report-band">
        <h1>Documentation</h1>
        <p>
          packsight is a multichain audit support tool for understanding legacy on-chain interfaces, upgrade posture,
          callable surfaces and missing evidence. The scanner is designed to help auditors decide what to inspect next,
          not to declare exploitability from metadata alone.
        </p>
      </section>

      <div className="docs-layout">
        <nav className="docs-nav" aria-label="Documentation sections">
          {sections.map((section) => (
            <a href={section.href} key={section.href}>
              {section.label}
            </a>
          ))}
        </nav>

        <div className="doc-stack">
          <section className="doc-section" id="overview">
            <h2>Overview</h2>
            <p>
              A scan starts with a chain target and optional source/interface material. packsight fetches on-chain
              metadata, builds a normalized callable-surface model, records dependency or linkage facts, evaluates rules
              and renders a report with confidence, evidence, limitations and manual-review guidance.
            </p>
            <div className="doc-grid">
              <div className="doc-note">
                <strong>Confirmed facts</strong>
                <p>Direct observations from RPC, GraphQL, source files, ABI, IDL, manifests or lockfiles.</p>
              </div>
              <div className="doc-note">
                <strong>Static analysis</strong>
                <p>Parser-derived source and manifest findings, such as missing version gates or mutable dependencies.</p>
              </div>
              <div className="doc-note">
                <strong>Manual review</strong>
                <p>Governance, runtime reachability and state-migration questions that need auditor judgment.</p>
              </div>
            </div>
          </section>

          <section className="doc-section" id="chains">
            <h2>Chain Coverage</h2>
            <h3>Sui</h3>
            <p>
              Sui scans use GraphQL to resolve package versions, modules, function visibility, package lineage and Move
              linkage entries. The report labels functions as <code>transaction_entry</code>, <code>public_move_call</code>,{" "}
              <code>friend_only</code>, <code>private</code> or <code>unknown</code>. For older packages, packsight compares
              the scanned package against the latest observed package and reports functions that are still present, added
              or removed.
            </p>
            <h3>Solana</h3>
            <p>
              Solana scans fetch program account metadata through JSON-RPC. When the program is owned by the BPF
              upgradeable loader, packsight parses ProgramData to report deployment slot and active upgrade authority. If
              an Anchor IDL is supplied under <code>target/idl</code> or <code>idl</code>, instructions are listed as callable
              surface. Without IDL or source, instruction names remain unavailable by design.
            </p>
            <h3>EVM</h3>
            <p>
              EVM scans fetch bytecode, chain ID, block number and selected EIP-1967 storage slots. If a local{" "}
              <code>abi.json</code> is supplied or an explorer ABI is configured, packsight enumerates contract functions
              and state mutability. Without ABI/source, the report records a wildcard contract surface rather than
              guessing functions from bytecode.
            </p>
          </section>

          <section className="doc-section" id="reports">
            <h2>Report Model</h2>
            <p>Every chain feeds the same report shape so auditors can compare targets without learning a new UI.</p>
            <ul>
              <li>
                <strong>Version history:</strong> package versions, deployed slots, scan blocks or active deployment facts.
              </li>
              <li>
                <strong>Callable surface:</strong> functions, instructions or contract interface entries with reachability
                and accessibility labels when known.
              </li>
              <li>
                <strong>Legacy-to-upgrade function diff:</strong> Sui old-vs-latest function comparison for deprecated
                package review.
              </li>
              <li>
                <strong>Package linkage:</strong> Sui linked package resolutions and whether the latest package resolves
                them differently.
              </li>
              <li>
                <strong>Runtime checks:</strong> public old-function proof checklist with mutation hints, guard evidence
                status and required simulation evidence.
              </li>
              <li>
                <strong>Dependencies:</strong> source and manifest dependencies, including Move linkage and lockfile facts.
              </li>
              <li>
                <strong>Coverage:</strong> explicit completeness state for on-chain metadata, source, history, interface,
                dependency graph and runtime reachability.
              </li>
            </ul>
          </section>

          <section className="doc-section" id="evidence">
            <h2>Evidence and Limits</h2>
            <p>
              packsight keeps uncertainty visible. A public function is interface-accessible, but that does not prove a
              successful exploit path. Runtime success may require live objects, capabilities, signer authorization,
              shared-state gates or protocol configuration.
            </p>
            <ul>
              <li>Missing source is an information gap, not proof that a target is safe or unsafe.</li>
              <li>Function names can raise review priority, but severity is not assigned from names alone.</li>
              <li>Upgradeable proxies or authorities are governance facts until ownership and process are reviewed.</li>
              <li>Legacy package linkage is a stale-dependency signal, not a transaction simulation.</li>
            </ul>
          </section>

          <section className="doc-section" id="api">
            <h2>API</h2>
            <p>Create a scan with <code>POST /v1/scans</code>. Use <code>Idempotency-Key</code> to avoid duplicate work.</p>
            <pre className="mono">{`{
  "targetType": "chain_address",
  "chainFamily": "sui | solana | evm",
  "network": "mainnet | monad",
  "chainId": "1 for Ethereum, 143 for Monad",
  "address": "target address",
  "repositoryUrl": "https://github.com/org/repo",
  "commitSha": "optional exact source commit"
}`}</pre>
            <p>
              Local development can include <code>sourcePath</code>, <code>customGraphqlUrl</code> for Sui or{" "}
              <code>customRpcUrl</code> for Solana/EVM. EVM requests must include a decimal <code>chainId</code>, and
              packsight compares it with <code>eth_chainId</code> when RPC metadata is available. Monad mainnet is
              available as <code>network: "monad"</code> with <code>chainId: "143"</code>. Fetch reports with{" "}
              <code>GET /v1/scans/:scanId/report</code>.
            </p>
          </section>

          <section className="doc-section" id="operations">
            <h2>Operations</h2>
            <p>
              The current local API keeps scan state in memory. Restarting the API clears prior scan IDs. Production
              deployments should run analyzers in isolated workers, persist scan records, rate-limit public submission and
              redact provider credentials from logs.
            </p>
            <p>
              Additional repository documentation lives under <code>docs/</code>: architecture, detection rules, security
              model, false positives, API details and deployment notes.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}

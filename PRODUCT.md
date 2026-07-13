# Product

## Register

product

## Users
Security engineers, protocol teams, auditors, DevRel engineers and CI owners who need to understand whether deployed Web3 code, interfaces and repository configuration still expose old or deprecated logic. They are usually triaging a concrete package, program, contract or repository and need evidence they can hand to maintainers without overstating exploitability.

## Product Purpose
packsight is a multichain security scanner that detects outdated dependencies, unsafe upgrades and deprecated smart-contract logic that may still be callable. Success means a user can submit a target, watch the scan progress, and receive a report that separates confirmed facts, static-analysis findings, heuristic findings, missing information and manual-review recommendations.

## Brand Personality
Precise, sober, evidence-led. The product should feel like a careful security workbench: confident enough to guide action, restrained enough to avoid fearmongering, and transparent about uncertainty.

## Anti-references
It must not look or sound like an exploit alarm, generic vulnerability scanner, crypto casino dashboard, malware scanner, or audit-replacement product. Avoid inflated severity language, decorative Web3 tropes, vague "AI security" claims, and any wording that implies a finding is exploitable merely because a function name looks risky.

## Design Principles
- Evidence before assertion: every claim needs evidence, confidence and limitations.
- Unknown stays unknown: missing source, incomplete lineage and unavailable runtime data must remain visible.
- One normalized model: chain-specific details feed a shared report rather than leaking into UI structure.
- Security without theater: use calm severity, plain remediation and governance language.
- Useful chain coverage: expose what each chain can prove today, and label missing source, IDL, ABI or runtime evidence clearly.

## Accessibility & Inclusion
Target WCAG 2.2 AA. Preserve keyboard navigation, visible focus states, reduced-motion alternatives, strong text contrast, non-color-only severity indicators, and clear language for users who are not native English speakers.

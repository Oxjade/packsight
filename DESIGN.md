# Design

## Style
packsight uses a restrained product interface: white working surfaces, near-black ink, neutral grey structure and red primary actions. The physical scene is a security review room in daylight: dense evidence, quiet controls, and instrumentation that makes uncertainty visible. Red is a disciplined audit accent, not exploit theater.

## Color
Use OKLCH tokens only.

```css
:root {
  --bg: oklch(1 0 0);
  --surface: oklch(0.975 0.003 20);
  --surface-strong: oklch(0.925 0.004 20);
  --surface-red: oklch(0.965 0.018 25);
  --ink: oklch(0.15 0.012 20);
  --muted: oklch(0.39 0.012 20);
  --border: oklch(0.86 0.006 20);
  --primary: oklch(0.47 0.18 25);
  --primary-ink: oklch(1 0 0);
  --accent: oklch(0.59 0.16 32);
  --accent-ink: oklch(0.15 0.012 20);
  --critical: oklch(0.43 0.2 25);
  --high: oklch(0.5 0.19 28);
  --medium: oklch(0.62 0.14 45);
  --low: oklch(0.48 0.015 20);
  --info: oklch(0.36 0.012 20);
  --success: oklch(0.48 0.1 145);
}
```

## Typography
Use Geist Sans or a system sans stack for all UI. Use Geist Mono or a system monospace for addresses, selectors, rule IDs, hashes and timestamps. Product headings use fixed rem sizes, balanced wrapping and no negative letter spacing.

## Layout
The public scanner starts as a working interface rather than a marketing hero. The first viewport includes scan inputs, chain coverage, trust boundaries and report framing. Reports use dense but readable sections: summary bands, filter bars, tables and evidence panels. Chain-specific facts should appear inside normalized sections rather than separate chain-specific report pages.

## Components
Buttons, inputs, tabs, filter chips, status badges, score rings, report tables, evidence callouts, progress steps and remediation checklists share one radius scale: 8px for cards/panels and 999px for pills only. Interactive controls need default, hover, focus, disabled and loading states.

## Motion
Motion is limited to scan progress, row disclosure and route-level affordance changes. Keep transitions between 150ms and 220ms and provide a reduced-motion path.

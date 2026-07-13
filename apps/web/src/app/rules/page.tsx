import { ruleDefinitions } from "@packsight/rule-engine";

export default function RulesPage() {
  return (
    <div className="page">
      <section className="report-band">
        <h1>Rule documentation</h1>
        <p>
          Each rule lists why it matters, how packsight detects it, evidence needed to support the finding and common
          false-positive conditions.
        </p>
      </section>
      <section className="section-grid">
        {ruleDefinitions.map((rule) => (
          <article className="compact-card" key={rule.id}>
            <h2 className="mono">{rule.id}</h2>
            <h3>{rule.title}</h3>
            <p>{rule.description}</p>
            <p>
              <strong>Why it matters:</strong> {rule.whyItMatters}
            </p>
            <p>
              <strong>Detection:</strong> {rule.detectionMethod}
            </p>
            <p>
              <strong>Recommendation:</strong> {rule.recommendation}
            </p>
          </article>
        ))}
      </section>
    </div>
  );
}

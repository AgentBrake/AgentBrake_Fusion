import type { BrakeTrace } from "../../types";

export function BrakeTracePanel({ trace }: { trace: BrakeTrace }) {
  const recovery = trace.recovery_guidance || [];
  return (
    <section className="card brake-trace" data-testid="braketrace-panel">
      <div className="section-heading compact">
        <h2>刹车轨迹</h2>
        <p>裁决可以复核：原因、证据、允许和禁止的下一步。</p>
      </div>
      <div className="trace-grid">
        <TraceList title="原因码" items={trace.reason_codes} tone="confirm" />
        <TraceList title="可信证据" items={trace.trusted_evidence} tone="allow" />
        <TraceList title="不安全证据" items={trace.unsafe_evidence} tone="attack" />
        <TraceList title="允许的下一步" items={trace.allowed_next_steps} tone="defense" />
        <TraceList title="禁止的下一步" items={trace.disallowed_next_steps} tone="attack" />
        {recovery.length ? <TraceList title="恢复建议" items={recovery} tone="allow" /> : null}
      </div>
    </section>
  );
}

function TraceList({ title, items, tone }: { title: string; items: string[]; tone: "allow" | "attack" | "confirm" | "defense" }) {
  return (
    <div className={`trace-list ${tone}`}>
      <h3>{title}</h3>
      <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>
    </div>
  );
}

import { useCountUp } from "../hooks.js";
import Gauge from "./Gauge.jsx";

/** The message as returned by the server, with suspicious phrases lit up as a scan line passes. */
function MessageScan({ segments, resultId }) {
  const total = Math.max(1, segments.reduce((n, s) => n + s.text.length, 0));
  let offset = 0;
  return (
    <div className="scan" key={resultId}>
      <span className="scan-line" aria-hidden="true" />
      <p className="scan-text">
        {segments.map((segment, index) => {
          const start = offset;
          offset += segment.text.length;
          if (!segment.flagged) return <span key={index}>{segment.text}</span>;
          // Light up when the scan line reaches this phrase
          const delay = Math.round(150 + (start / total) * 750);
          return <mark key={index} style={{ "--delay": `${delay}ms` }}>{segment.text}</mark>;
        })}
      </p>
    </div>
  );
}

function Count({ value }) {
  return <>{Math.round(useCountUp(value, 700))}</>;
}

function Figures({ result }) {
  const flagged = result.urls.filter((u) => u.warnings.length).length;
  const level = result.risk.level.toLowerCase();
  return (
    <dl className="figures">
      <div>
        <dt>Overall risk</dt>
        <dd className={`risk-text risk-${level}`}><i className={`dot dot-${level}`} />{result.risk.level} risk</dd>
        <p>{result.risk.raised_by_indicators ? "Raised one level by the extra indicators" : "Based on the model score"}</p>
      </div>
      <div>
        <dt>Phrases found</dt>
        <dd><Count value={result.phrases.length} /></dd>
        <p>Indicators, not proof</p>
      </div>
      <div>
        <dt>Links flagged</dt>
        <dd>{result.urls.length ? <><Count value={flagged} /><small> of {result.urls.length}</small></> : <small>No links</small>}</dd>
        <p>Structure only, never opened</p>
      </div>
    </dl>
  );
}

function Phrases({ phrases }) {
  if (!phrases.length) {
    return <p className="quiet">No phrases from the suspicious-phrase list were found.</p>;
  }
  return (
    <>
      <ul className="phrase-list">
        {phrases.map((p, i) => (
          <li key={p.phrase} className="stagger" style={{ "--i": i }}>
            <span className="phrase">“{p.matched_text}”{p.count > 1 && <small> ×{p.count}</small>}</span>
            <span className="phrase-why">{p.description}</span>
          </li>
        ))}
      </ul>
      <p className="quiet">Highlighted phrases come from an editable list. Legitimate messages can contain
        them too, so they are indicators, not proof.</p>
    </>
  );
}

function Links({ urls }) {
  if (!urls.length) return <p className="quiet">No URL detected.</p>;
  return (
    <>
      <ul className="link-list">
        {urls.map((u, i) => (
          <li key={u.url} className="stagger" style={{ "--i": i }}>
            <div className="link-head">
              <span className="link-url">{u.url}</span>
              <span className="link-host">{u.hostname || "(could not be read)"}</span>
            </div>
            {u.warnings.length ? (
              <ul className="warnings">{u.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
            ) : (
              <p className="quiet">No structural warning signs found.</p>
            )}
          </li>
        ))}
      </ul>
      <p className="quiet">Links were not opened or checked online. A warning describes the link's
        structure only: it does not confirm that a link is malicious, and no warning does not make it safe.</p>
    </>
  );
}

function TestResults({ results }) {
  const names = { overall: "Overall", email: "Email", sms: "SMS" };
  return (
    <table className="results-table">
      <thead>
        <tr><th>Group</th><th className="num">Messages</th><th className="num">Precision</th>
          <th className="num">Recall</th><th className="num">F1</th></tr>
      </thead>
      <tbody>
        {Object.entries(results).map(([group, m]) => (
          <tr key={group}>
            <td>{names[group] || group}</td>
            <td className="num">{m.messages.toLocaleString()}</td>
            <td className="num">{m.precision.toFixed(3)}</td>
            <td className="num">{m.recall.toFixed(3)}</td>
            <td className="num">{m.f1.toFixed(3)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EmptyState({ meta }) {
  return (
    <>
      <div className="verdict-head">
        <h2 className="panel-title">Verdict</h2>
      </div>
      <p className="empty-note">No message checked yet. Paste an email or SMS, or load one of the examples,
        and the dial will show where its score lands.</p>
      {meta && <Gauge thresholds={meta.thresholds} />}
      {meta?.test_results && (
        <section className="block">
          <h3 className="block-title">How the model did on held-out test messages</h3>
          <TestResults results={meta.test_results} />
          <p className="quiet">From reports/evaluation.json. Email scores are likely optimistic because its
            legitimate and phishing emails come from different years; see "How it works".</p>
        </section>
      )}
    </>
  );
}

export { TestResults };

export default function ResultPanel({ panelRef, meta, metaError, result, resultId, pending, error }) {
  const problem = metaError || error;
  return (
    <section ref={panelRef} className={`panel result rise ${pending ? "is-pending" : ""}`} style={{ "--i": 2 }}
      aria-labelledby="verdict-title" aria-busy={pending}>
      <span className="progress" aria-hidden="true" />

      {problem && (
        <div className="problem" role="alert">
          <h2 id="verdict-title" className="panel-title">Verdict</h2>
          <p className="problem-message">{problem.message}</p>
          {problem.instructions && <pre className="problem-code">{problem.instructions}</pre>}
        </div>
      )}

      {!problem && !result && <EmptyState meta={meta} />}

      {!problem && result && (
        <div className="verdict" key={resultId}>
          <div className="verdict-head">
            <h2 id="verdict-title" className="panel-title">Verdict</h2>
          </div>
          <div className="verdict-top">
            <div className="verdict-words" aria-live="polite">
              <p className={`verdict-title risk-${result.risk.level.toLowerCase()}`}>{result.verdict.title}</p>
              <span className={`pill pill-${result.risk.level.toLowerCase()}`}>{result.risk.level} risk</span>
              <p className="verdict-caption">Model prediction: {result.verdict.caption}</p>
            </div>
            {meta && (
              <Gauge
                thresholds={meta.thresholds}
                score={result.prediction.score}
                scoreDisplay={result.prediction.score_display}
                level={result.risk.level}
              />
            )}
          </div>

          <p className="finding">{result.risk.explanation}</p>
          <Figures result={result} />
          <p className="quiet">The score is the model's estimate, not a guaranteed probability.</p>

          <section className="block">
            <h3 className="block-title">Message analysis</h3>
            <MessageScan segments={result.segments} resultId={resultId} />
            <Phrases phrases={result.phrases} />
          </section>

          <section className="block">
            <h3 className="block-title">URL analysis</h3>
            <Links urls={result.urls} />
          </section>

          <section className="block">
            <h3 className="block-title">Recommended next steps</h3>
            <ol className="steps">
              {result.risk.recommendations.map((tip, i) => (
                <li key={tip} className="stagger" style={{ "--i": i }}>{tip}</li>
              ))}
            </ol>
            <p className="quiet">This result is an automated estimate. It is not a guarantee that the message
              is safe or malicious.</p>
          </section>
        </div>
      )}
    </section>
  );
}

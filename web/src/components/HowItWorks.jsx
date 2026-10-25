import { useState } from "react";

import { TestResults } from "./ResultPanel.jsx";

const STEPS = [
  ["Text preprocessing", "The message is lower-cased, HTML and extra spaces are removed, and useful clues such as links, numbers and currency symbols are kept. Exactly the same steps are used when training the model and when analysing your message."],
  ["TF-IDF (turning text into numbers)", "TF-IDF gives every word and two-word phrase a weight. A phrase scores highly when it appears in this message but is uncommon across all messages, so words like \"verify your\" or \"claim\" stand out more than \"the\" or \"and\"."],
  ["Logistic Regression (the classifier)", "The model learned a weight for each word or phrase from thousands of labelled phishing and legitimate messages. It adds up the weights for your message and turns the total into a score between 0 and 1. Scores at or above the threshold are labelled potential phishing. The score is the model's estimate, not a guaranteed probability."],
  ["Suspicious phrase detection", "A separate, editable list of phrases (such as \"verify your account\" or \"click here\") is searched for and highlighted. These are hints for you, not the main decision."],
  ["URL analysis", "Links are checked only by their structure: IP addresses instead of names, URL shorteners, very long links, a hidden \"@\", many subdomains, look-alike characters and official-sounding words. Links are never visited."],
  ["Risk level", "The model score sets the starting level. A URL warning or two or more suspicious phrases can raise it by one level, but the extra checks never lower the risk and cannot turn a model \"legitimate\" result into High risk."],
];

export default function HowItWorks({ meta }) {
  const [open, setOpen] = useState(false);
  const t = meta?.thresholds;
  return (
    <section className={`panel how rise ${open ? "is-open" : ""}`} style={{ "--i": 3 }}>
      <h2 className="how-heading">
        <button type="button" className="how-toggle" aria-expanded={open} aria-controls="how-body"
          onClick={() => setOpen((o) => !o)}>
          <span>How it works</span>
          <svg className="chevron" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor"
            strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M4 6l4 4 4-4" /></svg>
        </button>
      </h2>
      <div id="how-body" className={`fold how-fold ${open ? "is-open" : ""}`} inert={!open}>
        <div className="fold-inner">
          <div className="how-grid">
            <ol className="how-steps">
              {STEPS.map(([title, text]) => (
                <li key={title}><strong>{title}.</strong> {text}</li>
              ))}
            </ol>
            <div className="how-side">
              {t && (
                <div className="how-card">
                  <h3 className="block-title">Current thresholds</h3>
                  <p><strong>Prediction:</strong> phishing if the score is ≥ {t.display.classification}, otherwise legitimate.</p>
                  <p><strong>Risk level:</strong> Low below {t.display.medium}, Medium from {t.display.medium},
                    High from {t.display.high}{t.source === "validation" ? " (risk bands chosen on validation data)" : " (default values)"}.</p>
                  <p className="quiet">The two are separate: a message can be classified as legitimate and still be
                    Medium risk if its score is in the Medium range or link/phrase warnings raise it.</p>
                </div>
              )}
              {meta?.test_results && (
                <div className="how-card">
                  <h3 className="block-title">Measured results on the held-out test set</h3>
                  <TestResults results={meta.test_results} />
                </div>
              )}
              <div className="how-card">
                <h3 className="block-title">Main limitations</h3>
                <ul className="limits">
                  <li>The model only knows patterns from its training data: public datasets of older emails and SMS messages. New scam styles may be missed.</li>
                  <li>The legitimate emails (2002) and phishing emails (2016–2022) come from different sources and years, so test scores are likely more optimistic than real-world performance.</li>
                  <li>Genuine messages that look like scams (for example, real bank OTP messages) can be flagged.</li>
                  <li>Sender details, email headers and attachments are not analysed, and links are not checked online.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

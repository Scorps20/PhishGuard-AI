const CHANNELS = [
  { value: "email", label: "Email" },
  { value: "sms", label: "SMS" },
];

/** Email/SMS switch: real radio buttons (keyboard and screen readers work), drawn as a sliding toggle. */
function ChannelToggle({ channel, onChannel }) {
  return (
    <fieldset className="segmented" data-active={channel}>
      <legend className="visually-hidden">Message type</legend>
      <span className="segmented-thumb" aria-hidden="true" />
      {CHANNELS.map((option) => (
        <label key={option.value} className={channel === option.value ? "is-on" : ""}>
          <input
            type="radio"
            name="channel"
            value={option.value}
            checked={channel === option.value}
            onChange={() => onChannel(option.value)}
          />
          {option.label} Analysis
        </label>
      ))}
    </fieldset>
  );
}

export default function Composer({
  channel, onChannel, subject, onSubject, message, onMessage, live, onLive,
  limits, examples, onExample, onAnalyse, onClear, pending,
}) {
  const limit = limits?.[channel] ?? (channel === "sms" ? 2000 : 20000);
  const isEmail = channel === "email";

  return (
    <section className="panel composer rise" style={{ "--i": 1 }} aria-labelledby="composer-title">
      <h2 id="composer-title" className="panel-title">Check a message</h2>

      <ChannelToggle channel={channel} onChannel={onChannel} />

      <form
        className="composer-form"
        onSubmit={(event) => { event.preventDefault(); onAnalyse(); }}
      >
        {/* The subject folds away for SMS */}
        <div className={`fold ${isEmail ? "is-open" : ""}`} inert={!isEmail}>
          <div className="fold-inner">
            <label className="field-label" htmlFor="subject">Email subject <span className="optional">(optional)</span></label>
            <input
              id="subject"
              className="field"
              value={subject}
              maxLength={limits?.subject ?? 500}
              onChange={(event) => onSubject(event.target.value)}
              placeholder="e.g. Action required: account suspended"
              tabIndex={isEmail ? 0 : -1}
              autoComplete="off"
            />
          </div>
        </div>

        <div className="field-head">
          <label className="field-label" htmlFor="message">{isEmail ? "Email body" : "SMS message"}</label>
          <span className="counter" aria-live="off">
            {message.length.toLocaleString()} / {limit.toLocaleString()}
          </span>
        </div>
        <textarea
          id="message"
          className="field field-message"
          value={message}
          maxLength={limit}
          onChange={(event) => onMessage(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) onAnalyse();
          }}
          placeholder={isEmail ? "Paste the email text here..." : "Paste the SMS text here..."}
          rows={isEmail ? 8 : 5}
          spellCheck="false"
        />

        <label className="live-switch">
          <input type="checkbox" checked={live} onChange={(event) => onLive(event.target.checked)} />
          <span className="switch-track" aria-hidden="true"><span className="switch-knob" /></span>
          Analyse as I type
        </label>

        <div className="actions">
          <button type="submit" className="button button-primary" disabled={pending && !live}>
            <span>Analyse Message</span>
            <kbd className="shortcut" aria-hidden="true">Ctrl ↵</kbd>
          </button>
          <button type="button" className="button button-secondary" onClick={onClear}>Clear Input</button>
        </div>
      </form>

      {examples.length > 0 && (
        <div className="examples">
          <h3 className="examples-title">Try an example <span>made up for demonstration</span></h3>
          <ul>
            {examples.map((example) => (
              <li key={example.key}>
                <button type="button" className="example" onClick={() => onExample(example)}>
                  <span className="example-title">{example.title}</span>
                  <span className={`tag tag-${example.channel}`}>{example.channel === "sms" ? "SMS" : "Email"}</span>
                  <span className="example-arrow" aria-hidden="true">
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8"
                      strokeLinecap="round" strokeLinejoin="round"><path d="M3 8h10M9 4l4 4-4 4" /></svg>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

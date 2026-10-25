import { useCallback, useEffect, useRef, useState } from "react";

import { analyseMessage, fetchMeta } from "./api.js";
import { usePrefersReducedMotion } from "./hooks.js";
import Header from "./components/Header.jsx";
import Composer from "./components/Composer.jsx";
import ResultPanel from "./components/ResultPanel.jsx";
import HowItWorks from "./components/HowItWorks.jsx";

const LIVE_DELAY_MS = 500; // wait this long after the last keystroke before analysing

const hasWords = (text) => /\p{L}/u.test(text);

export default function App() {
  const reducedMotion = usePrefersReducedMotion();

  const [meta, setMeta] = useState(null);
  const [metaError, setMetaError] = useState(null);

  // The form
  const [channel, setChannel] = useState("email");
  const [subject, setSubject] = useState("");
  const [bodies, setBodies] = useState({ email: "", sms: "" });
  const [live, setLive] = useState(true);
  const message = bodies[channel];

  // The result
  const [result, setResult] = useState(null);
  const [resultId, setResultId] = useState(0); // changes on every new result, to replay animations
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(null);

  const controllerRef = useRef(null);
  const typingRef = useRef(null);
  const skipLiveRef = useRef(false); // set when an analysis was just started directly
  const scrollToResultRef = useRef(false); // on a phone, show the verdict after a button press
  const resultRef = useRef(null);

  useEffect(() => {
    fetchMeta().then(setMeta).catch(setMetaError);
  }, []);

  /** Send the current message to the server. A newer request cancels an older one. */
  const runAnalysis = useCallback(async (input) => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setPending(true);
    try {
      const data = await analyseMessage(input, controller.signal);
      setResult(data);
      setResultId((id) => id + 1);
      setError(null);
      if (scrollToResultRef.current && window.innerWidth < 860) {
        requestAnimationFrame(() => resultRef.current?.scrollIntoView({
          behavior: reducedMotion ? "auto" : "smooth", block: "start" }));
      }
      scrollToResultRef.current = false;
    } catch (err) {
      if (err.name === "AbortError") return;
      setError(err);
      setResult(null);
    } finally {
      if (controllerRef.current === controller) setPending(false);
    }
  }, [reducedMotion]);

  // Live mode: analyse shortly after typing stops
  useEffect(() => {
    if (!live || typingRef.current) return undefined;
    if (skipLiveRef.current) {
      skipLiveRef.current = false;
      return undefined;
    }
    const text = `${channel === "email" ? subject : ""} ${message}`;
    if (!text.trim()) {
      controllerRef.current?.abort();
      setResult(null);
      setError(null);
      setPending(false);
      return undefined;
    }
    if (!hasWords(text)) return undefined;
    const timer = setTimeout(() => runAnalysis({ channel, message, subject }), LIVE_DELAY_MS);
    return () => clearTimeout(timer);
  }, [live, channel, subject, message, runAnalysis]);

  function analyseNow() {
    const text = `${channel === "email" ? subject : ""} ${message}`;
    if (!text.trim()) {
      setError(new Error("Please paste a message to analyse. The text box is empty."));
      setResult(null);
      return;
    }
    if (!hasWords(text)) {
      setError(new Error("The message contains no words. Please paste the actual text of the email or SMS."));
      setResult(null);
      return;
    }
    scrollToResultRef.current = true;
    runAnalysis({ channel, message, subject });
  }

  function stopTyping() {
    if (typingRef.current) {
      clearInterval(typingRef.current);
      typingRef.current = null;
    }
  }

  function clearAll() {
    stopTyping();
    controllerRef.current?.abort();
    setSubject("");
    setBodies({ email: "", sms: "" });
    setResult(null);
    setError(null);
    setPending(false);
  }

  function setMessage(text) {
    stopTyping();
    setBodies((b) => ({ ...b, [channel]: text }));
  }

  /** Load an example: it types itself into the form, then gets analysed. */
  const loadExample = useCallback((example, { instant = false } = {}) => {
    stopTyping();
    setChannel(example.channel);
    setSubject(example.subject || "");
    const finish = () => {
      typingRef.current = null;
      skipLiveRef.current = true;
      scrollToResultRef.current = !instant;
      setBodies((b) => ({ ...b, [example.channel]: example.body }));
      runAnalysis({ channel: example.channel, message: example.body, subject: example.subject || "" });
    };
    if (instant || reducedMotion) {
      finish();
      return;
    }
    const steps = 28; // about 0.7 s whatever the length
    let step = 0;
    typingRef.current = setInterval(() => {
      step += 1;
      const shown = example.body.slice(0, Math.ceil((example.body.length * step) / steps));
      setBodies((b) => ({ ...b, [example.channel]: shown }));
      if (step >= steps) {
        clearInterval(typingRef.current);
        finish();
      }
    }, 25);
  }, [reducedMotion, runAnalysis]);

  // ?example=<key> in the address loads an example at once (handy for demos)
  useEffect(() => {
    if (!meta) return;
    const key = new URLSearchParams(window.location.search).get("example");
    const example = meta.examples.find((e) => e.key === key);
    if (example) loadExample(example, { instant: true });
  }, [meta, loadExample]);

  useEffect(() => () => stopTyping(), []);

  return (
    <div className="page">
      <Header meta={meta} />
      <main className="workspace">
        <Composer
          channel={channel}
          onChannel={(c) => { stopTyping(); setChannel(c); }}
          subject={subject}
          onSubject={(s) => { stopTyping(); setSubject(s); }}
          message={message}
          onMessage={setMessage}
          live={live}
          onLive={setLive}
          limits={meta?.limits}
          examples={meta?.examples || []}
          onExample={loadExample}
          onAnalyse={analyseNow}
          onClear={clearAll}
          pending={pending}
        />
        <ResultPanel
          panelRef={resultRef}
          meta={meta}
          metaError={metaError}
          result={result}
          resultId={resultId}
          pending={pending}
          error={error}
        />
      </main>
      <HowItWorks meta={meta} />
      <footer className="footer">
        PhishGuard AI is an educational phishing-detection tool. Predictions are automated estimates
        and should not be treated as proof that a message is safe or malicious.
      </footer>
    </div>
  );
}

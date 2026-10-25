import { useTheme } from "../hooks.js";
import Mark from "./Mark.jsx";

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8"
      strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="12" r="4.2" />
      <path d="M12 2.5v2.2M12 19.3v2.2M4.6 4.6l1.6 1.6M17.8 17.8l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.6 19.4l1.6-1.6M17.8 6.2l1.6-1.6" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" />
    </svg>
  );
}

export default function Header({ meta }) {
  const [theme, toggleTheme] = useTheme();
  const trained = meta?.trained_at
    ? new Date(meta.trained_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })
    : null;
  const dark = theme === "dark";

  return (
    <header className="header rise" style={{ "--i": 0 }}>
      <div className="brand">
        <Mark />
        <div>
          <h1>PhishGuard AI</h1>
          <p className="tagline">NLP-Powered Email and SMS Phishing Detection</p>
        </div>
      </div>
      <div className="header-side">
        {trained && <span className="stamp">Model trained {trained}</span>}
        <button
          type="button"
          className="theme-switch"
          onClick={toggleTheme}
          aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
          title={dark ? "Light theme" : "Dark theme"}
        >
          <span className={`theme-icon ${dark ? "is-hidden" : ""}`}><MoonIcon /></span>
          <span className={`theme-icon ${dark ? "" : "is-hidden"}`}><SunIcon /></span>
        </button>
      </div>
    </header>
  );
}

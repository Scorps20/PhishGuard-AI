import { useEffect, useRef, useState } from "react";

/** True when the visitor has asked their system to reduce motion. */
export function usePrefersReducedMotion() {
  const query = "(prefers-reduced-motion: reduce)";
  const [reduced, setReduced] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setReduced(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  return reduced;
}

/** Animate a number from its previous value to `target` (ease-out), for counters. */
export function useCountUp(target, duration = 800) {
  const reduced = usePrefersReducedMotion();
  const [value, setValue] = useState(target ?? 0);
  const fromRef = useRef(target ?? 0);

  useEffect(() => {
    if (target == null) return undefined;
    if (reduced) {
      setValue(target);
      fromRef.current = target;
      return undefined;
    }
    const from = fromRef.current;
    const start = performance.now();
    let frame;
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(from + (target - from) * eased);
      if (t < 1) frame = requestAnimationFrame(step);
      else fromRef.current = target;
    };
    frame = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(frame);
      fromRef.current = target;
    };
  }, [target, duration, reduced]);

  return value;
}

/** Light/dark theme: follows the system until the visitor chooses, then remembers the choice. */
export function useTheme() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "light");

  function toggle(event) {
    const next = theme === "dark" ? "light" : "dark";
    const apply = () => {
      document.documentElement.dataset.theme = next;
      setTheme(next);
    };
    try { localStorage.setItem("pg-theme", next); } catch { /* private mode: not remembered */ }

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!document.startViewTransition || reduced) {
      apply();
      return;
    }
    // A circular reveal of the new theme, growing from the switch that was pressed
    const rect = event.currentTarget.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    document.documentElement.style.setProperty("--reveal-x", `${x}px`);
    document.documentElement.style.setProperty("--reveal-y", `${y}px`);
    document.startViewTransition(apply);
  }

  return [theme, toggle];
}

/** Score shown while it counts up: 4 decimals, cut off (never rounded up past a threshold). */
export function formatCounting(value) {
  return (Math.floor(Math.max(0, Math.min(0.9999, value)) * 10000) / 10000).toFixed(4);
}

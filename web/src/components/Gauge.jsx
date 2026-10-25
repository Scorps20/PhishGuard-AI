import { useEffect, useState } from "react";

import { formatCounting, useCountUp } from "../hooks.js";

// Geometry of the dial (SVG units). Score 0 sits on the left, 1 on the right.
const CX = 170, CY = 178, R = 140;

function point(value, radius) {
  const angle = Math.PI * value;
  return [CX - radius * Math.cos(angle), CY - radius * Math.sin(angle)];
}

function arc(from, to, radius = R) {
  const [x1, y1] = point(from, radius);
  const [x2, y2] = point(to, radius);
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radius} ${radius} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/**
 * The risk dial: the three risk bands at their real thresholds, the phishing
 * cut-off as a tick, and a needle that swings to this message's score.
 */
export default function Gauge({ thresholds, score = null, scoreDisplay = null, level = null }) {
  const { medium, high, classification } = thresholds;
  const gap = 0.006;
  const bands = [
    { name: "Low", from: 0, to: medium },
    { name: "Medium", from: medium, to: high },
    { name: "High", from: high, to: 1 },
  ];

  // Start the needle at 0 and move it on the next frame, so the swing is animated
  const [needleAt, setNeedleAt] = useState(0);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setNeedleAt(score ?? 0));
    return () => cancelAnimationFrame(frame);
  }, [score]);

  const counting = useCountUp(score ?? 0, 1000);
  const shown = score == null ? "–" : (Math.abs(counting - score) < 1e-6 ? scoreDisplay : formatCounting(counting));
  const [tickInner, tickOuter] = [point(classification, R - 19), point(classification, R + 19)];
  const label = score == null
    ? `Risk dial. Low below ${thresholds.display.medium}, Medium from ${thresholds.display.medium}, `
      + `High from ${thresholds.display.high}. Phishing from ${thresholds.display.classification}.`
    : `Risk dial. This message scored ${scoreDisplay}, ${level} risk. Phishing from ${thresholds.display.classification}.`;

  return (
    <figure className={`gauge ${score == null ? "is-empty" : ""}`} data-level={level || undefined}>
      <svg viewBox="0 0 340 204" role="img" aria-label={label}>
        {bands.map((band) => (
          <path
            key={band.name}
            className={`gauge-band band-${band.name.toLowerCase()} ${level === band.name ? "is-active" : ""}`}
            d={arc(band.from + (band.from > 0 ? gap : 0), band.to - (band.to < 1 ? gap : 0))}
          />
        ))}
        <line className="gauge-cut" x1={tickInner[0]} y1={tickInner[1]} x2={tickOuter[0]} y2={tickOuter[1]} />
        <g className="gauge-needle" style={{ transform: `rotate(${180 * needleAt}deg)` }}>
          <line x1={CX} y1={CY} x2={CX - (R - 34)} y2={CY} />
          <circle cx={CX} cy={CY} r="7" />
        </g>
        <text className="gauge-score" x={CX} y={CY - 52} textAnchor="middle">{shown}</text>
        <text className="gauge-caption" x={CX} y={CY - 26} textAnchor="middle">
          {score == null ? "no message yet" : "model score"}
        </text>
        <text className="gauge-end" x={CX - R} y={CY + 24} textAnchor="middle">0</text>
        <text className="gauge-end" x={CX + R} y={CY + 24} textAnchor="middle">1</text>
      </svg>
      <figcaption className="gauge-legend">
        <span><i className="key key-low" />Low below {thresholds.display.medium}</span>
        <span><i className="key key-medium" />Medium from {thresholds.display.medium}</span>
        <span><i className="key key-high" />High from {thresholds.display.high}</span>
        <span><i className="key key-cut" />Phishing if ≥ {thresholds.display.classification}</span>
      </figcaption>
    </figure>
  );
}

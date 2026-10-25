// The product's mark: a shield with a fish-hook inside.
export default function Mark() {
  return (
    <svg className="mark" viewBox="0 0 24 24" width="40" height="40" fill="none"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path className="mark-shield" d="M12 2.5 19.5 5.3v5.6c0 4.6-3.1 8.3-7.5 10.1-4.4-1.8-7.5-5.5-7.5-10.1V5.3Z" />
      <path className="mark-hook" d="M13 6.8v6.4a2.6 2.6 0 0 1-5.2 0v-.9M13 6.8l1.6 1.3" />
    </svg>
  );
}

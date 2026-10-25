// Small helpers for talking to the FastAPI server (api.py).

async function request(path, options) {
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new Error("Can't reach the PhishGuard server. Is it running? (python -m uvicorn api:app)");
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.detail || {};
    const error = new Error(detail.message || `The server answered with an error (${response.status}).`);
    error.instructions = detail.instructions;
    error.status = response.status;
    throw error;
  }
  return body;
}

export function fetchMeta() {
  return request("/api/meta");
}

export function analyseMessage({ channel, message, subject }, signal) {
  return request("/api/analyse", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ channel, message, subject: channel === "email" ? subject : null }),
    signal,
  });
}

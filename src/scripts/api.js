// API client — talks to the Express backend mounted at /api.
export async function api(path, options = {}) {
  const opts = {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options,
  };
  if (opts.body && typeof opts.body !== 'string') {
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch('/api' + path, opts);
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) {
    const err = new Error((data && data.error) || 'request_failed');
    err.status = res.status;
    err.code = data && data.error;
    throw err;
  }
  return data;
}

export function errCode(err) {
  return (err && err.code) || 'server_error';
}

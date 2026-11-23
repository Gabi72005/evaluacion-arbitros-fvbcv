// Env vars needed: EVAL_KV (binding), ADMIN_SECRET, DERIVE_SALT, ALLOWED_ORIGIN

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status, env) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env) },
  });
}

async function sha256hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function normalizeName(name) {
  return String(name || '').normalize('NFD').replace(/[̀-ͯ]/g, '')
    .toLowerCase().replace(/\s+/g, ' ').trim();
}

// Derives a deterministic code from a name using HMAC-SHA256.
// Returns "XXXX-XXXX" in uppercase hex (0-9, A-F).
async function deriveCode(name, salt) {
  const keyMat = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(salt),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', keyMat, new TextEncoder().encode(normalizeName(name)));
  const hex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  const code = hex.slice(0, 8).toUpperCase();
  return code.slice(0, 4) + '-' + code.slice(4);
}

function nowIso() { return new Date().toISOString(); }

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }
    const path = new URL(request.url).pathname;

    if (path === '/auth/validate' && request.method === 'POST') return handleValidate(request, env);
    if (path === '/auth/verify'  && request.method === 'POST') return handleVerify(request, env);
    if (path === '/log/pdf'      && request.method === 'POST') return handleLogPdf(request, env);

    if (path.startsWith('/admin/')) {
      const auth = request.headers.get('Authorization') || '';
      if (auth !== `Bearer ${env.ADMIN_SECRET}`) return json({ error: 'No autorizado' }, 401, env);

      if (path === '/admin/data'       && request.method === 'GET')  return handleAdminData(env);
      if (path === '/admin/names'      && request.method === 'POST') return handleAddName(request, env);
      if (path === '/admin/revoke'     && request.method === 'POST') return handleRevoke(request, env);
      if (path === '/admin/reactivate' && request.method === 'POST') return handleReactivate(request, env);
    }

    return json({ error: 'Not found' }, 404, env);
  },
};

async function handleValidate(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: 'Petición inválida' }, 400, env); }

  const { code, deviceId, deviceInfo } = body;
  if (!code || !deviceId) return json({ ok: false, error: 'Datos incompletos' }, 400, env);

  const normalized = String(code).trim().toUpperCase().replace(/[^0-9A-F]/g, '');
  if (normalized.length !== 8) return json({ ok: false, error: 'Código incorrecto' }, 200, env);

  const hash = await sha256hex(normalized);
  const record = await env.EVAL_KV.get(`c:${hash}`, 'json');

  if (!record) return json({ ok: false, error: 'Código incorrecto' }, 200, env);
  if (record.status === 'revoked') return json({ ok: false, error: 'Acceso revocado. Contacta con el examinador jefe.' }, 200, env);
  if (record.status === 'active' && record.deviceId && record.deviceId !== deviceId) {
    return json({ ok: false, error: 'Este código ya se usó en otro dispositivo' }, 200, env);
  }

  const token = randomHex(32);
  const ts = nowIso();

  if (record.status === 'pending') {
    record.status = 'active';
    record.deviceId = deviceId;
    record.deviceInfo = deviceInfo;
    record.usedAt = ts;
    await env.EVAL_KV.put(`c:${hash}`, JSON.stringify(record));
  }

  await env.EVAL_KV.put(`s:${token}`, JSON.stringify({
    codeHash: hash, label: record.label, deviceId, createdAt: ts, lastSeen: ts,
  }), { expirationTtl: 180 * 86400 });

  await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
    type: 'login', label: record.label, deviceId, deviceInfo, timestamp: ts,
  }), { expirationTtl: 365 * 86400 });

  return json({ ok: true, token, label: record.label }, 200, env);
}

async function handleVerify(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false }, 400, env); }

  const { token } = body;
  if (!token) return json({ ok: false }, 200, env);

  const session = await env.EVAL_KV.get(`s:${token}`, 'json');
  if (!session) return json({ ok: false }, 200, env);

  const record = await env.EVAL_KV.get(`c:${session.codeHash}`, 'json');
  if (!record || record.status === 'revoked') return json({ ok: false }, 200, env);

  session.lastSeen = nowIso();
  await env.EVAL_KV.put(`s:${token}`, JSON.stringify(session), { expirationTtl: 180 * 86400 });

  return json({ ok: true, label: session.label }, 200, env);
}

async function handleLogPdf(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false }, 400, env); }

  const { token, aspirant, role, examiner, nEval, fecha } = body;
  if (!token) return json({ ok: false }, 200, env);

  const session = await env.EVAL_KV.get(`s:${token}`, 'json');
  if (!session) return json({ ok: false }, 200, env);

  await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
    type: 'pdf', label: session.label, deviceId: session.deviceId,
    aspirant, role, examiner, nEval, fecha, timestamp: nowIso(),
  }), { expirationTtl: 365 * 86400 });

  return json({ ok: true }, 200, env);
}

async function handleAdminData(env) {
  // Codes — re-derive display code for each entry
  const cl = await env.EVAL_KV.list({ prefix: 'c:' });
  const records = (await Promise.all(cl.keys.map(k => env.EVAL_KV.get(k.name, 'json')))).filter(Boolean);
  const codes = await Promise.all(records.map(async r => ({
    ...r,
    code: await deriveCode(r.label, env.DERIVE_SALT),
  })));

  // Logs — most recent first
  const ll = await env.EVAL_KV.list({ prefix: 'l:' });
  const sortedKeys = [...ll.keys].sort((a, b) => b.name.localeCompare(a.name)).slice(0, 100);
  const logs = (await Promise.all(sortedKeys.map(k => env.EVAL_KV.get(k.name, 'json')))).filter(Boolean);

  return json({ codes, logs }, 200, env);
}

async function handleAddName(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Petición inválida' }, 400, env); }

  const { name } = body;
  if (!name || !name.trim()) return json({ error: 'Falta el nombre' }, 400, env);

  const code = await deriveCode(name, env.DERIVE_SALT);
  const normalized = code.replace('-', '');
  const hash = await sha256hex(normalized);

  const existing = await env.EVAL_KV.get(`c:${hash}`, 'json');

  if (existing) {
    if (existing.status === 'revoked') {
      // Reactivate
      existing.status = 'pending';
      existing.deviceId = null;
      existing.deviceInfo = null;
      existing.usedAt = null;
      await env.EVAL_KV.put(`c:${hash}`, JSON.stringify(existing));
      return json({ ok: true, code, reactivated: true }, 200, env);
    }
    // Already exists and active/pending — return same code
    return json({ ok: true, code, alreadyExists: true }, 200, env);
  }

  await env.EVAL_KV.put(`c:${hash}`, JSON.stringify({
    id: randomHex(8),
    codeHash: hash,
    label: name.trim(),
    status: 'pending',
    deviceId: null,
    deviceInfo: null,
    usedAt: null,
    createdAt: nowIso(),
  }));

  return json({ ok: true, code }, 200, env);
}

async function handleRevoke(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Petición inválida' }, 400, env); }

  const { codeHash } = body;
  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);

  record.status = 'revoked';
  await env.EVAL_KV.put(`c:${codeHash}`, JSON.stringify(record));
  return json({ ok: true }, 200, env);
}

async function handleReactivate(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Petición inválida' }, 400, env); }

  const { codeHash } = body;
  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);

  record.status = 'pending';
  record.deviceId = null;
  record.deviceInfo = null;
  record.usedAt = null;
  await env.EVAL_KV.put(`c:${codeHash}`, JSON.stringify(record));
  return json({ ok: true }, 200, env);
}

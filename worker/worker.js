function corsHeaders(env) {
  const origin = env.ALLOWED_ORIGIN || '*';
  return {
    'Access-Control-Allow-Origin': origin,
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

function generateCode() {
  // Chars without ambiguous 0/O/1/I
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = '';
  for (let i = 0; i < 8; i++) {
    if (i === 4) code += '-';
    code += chars[bytes[i] % chars.length];
  }
  return code;
}

function normalizeCode(code) {
  return String(code).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function nowIso() {
  return new Date().toISOString();
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/auth/validate' && request.method === 'POST') {
      return handleValidate(request, env);
    }
    if (path === '/auth/verify' && request.method === 'POST') {
      return handleVerify(request, env);
    }
    if (path === '/log/pdf' && request.method === 'POST') {
      return handleLogPdf(request, env);
    }

    if (path.startsWith('/admin/')) {
      const auth = request.headers.get('Authorization') || '';
      if (auth !== `Bearer ${env.ADMIN_SECRET}`) {
        return json({ error: 'No autorizado' }, 401, env);
      }
      if (path === '/admin/data' && request.method === 'GET') return handleAdminData(env);
      if (path === '/admin/codes' && request.method === 'POST') return handleCreateCode(request, env);
      if (path === '/admin/revoke' && request.method === 'POST') return handleRevoke(request, env);
    }

    return json({ error: 'Not found' }, 404, env);
  },
};

async function handleValidate(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: 'Petición inválida' }, 400, env); }

  const { code, deviceId, deviceInfo } = body;
  if (!code || !deviceId) return json({ ok: false, error: 'Datos incompletos' }, 400, env);

  const hash = await sha256hex(normalizeCode(code));
  const record = await env.EVAL_KV.get(`c:${hash}`, 'json');

  if (!record) return json({ ok: false, error: 'Código incorrecto' }, 200, env);
  if (record.status === 'revoked') return json({ ok: false, error: 'Código revocado. Contacta con el examinador jefe.' }, 200, env);
  if (record.status === 'active' && record.deviceId && record.deviceId !== deviceId) {
    return json({ ok: false, error: 'Este código ya se activó en otro dispositivo' }, 200, env);
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
  const cl = await env.EVAL_KV.list({ prefix: 'c:' });
  const codes = (await Promise.all(cl.keys.map(k => env.EVAL_KV.get(k.name, 'json')))).filter(Boolean);

  const ll = await env.EVAL_KV.list({ prefix: 'l:' });
  const sortedKeys = [...ll.keys].sort((a, b) => b.name.localeCompare(a.name)).slice(0, 100);
  const logs = (await Promise.all(sortedKeys.map(k => env.EVAL_KV.get(k.name, 'json')))).filter(Boolean);

  return json({ codes, logs }, 200, env);
}

async function handleCreateCode(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Petición inválida' }, 400, env); }

  const { label } = body;
  if (!label || !label.trim()) return json({ error: 'Falta el nombre' }, 400, env);

  const code = generateCode();
  const hash = await sha256hex(normalizeCode(code));
  const id = randomHex(8);

  await env.EVAL_KV.put(`c:${hash}`, JSON.stringify({
    id, codeHash: hash, label: label.trim(),
    status: 'pending', deviceId: null, deviceInfo: null,
    usedAt: null, createdAt: nowIso(),
  }));

  return json({ ok: true, code, id }, 200, env);
}

async function handleRevoke(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Petición inválida' }, 400, env); }

  const { codeHash } = body;
  if (!codeHash) return json({ error: 'Falta codeHash' }, 400, env);

  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);

  record.status = 'revoked';
  await env.EVAL_KV.put(`c:${codeHash}`, JSON.stringify(record));

  return json({ ok: true }, 200, env);
}

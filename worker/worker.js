// Env vars needed: EVAL_KV (binding), ADMIN_SECRET, DERIVE_SALT, SESSION_SECRET, ALLOWED_ORIGIN

// ── Security headers added to every response ────────────────────────────────
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status, env, extra) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(env),
      ...SEC_HEADERS,
      ...(extra || {}),
    },
  });
}

function noStoreJson(data, status, env) {
  return json(data, status, env, { 'Cache-Control': 'no-store' });
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function sha256hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Constant-time comparison of two ASCII strings (same length).
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
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

// ── Admin session tokens ──────────────────────────────────────────────────────

async function issueAdminToken(env) {
  const jti = randomHex(32);
  const exp = Date.now() + 8 * 3600 * 1000;
  const sig = await hmacSha256Hex(env.SESSION_SECRET, `${jti}:${exp}`);
  const token = `${jti}.${exp}.${sig}`;
  await env.EVAL_KV.put(`adm:tok:${jti}`, '1', { expirationTtl: 8 * 3600 });
  return token;
}

async function verifyAdminToken(authHeader, env) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7).trim();
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [jti, expStr, sig] = parts;
  const exp = parseInt(expStr, 10);
  if (isNaN(exp) || Date.now() > exp) return false;
  const expectedSig = await hmacSha256Hex(env.SESSION_SECRET, `${jti}:${exp}`);
  if (!timingSafeEqual(sig, expectedSig)) return false;
  const stored = await env.EVAL_KV.get(`adm:tok:${jti}`);
  return stored !== null;
}

// ── Rate limiting (KV counters with TTL) ──────────────────────────────────────

const RL_MAX = 5;
const RL_WINDOW = 900; // seconds (15 min)

async function checkRateLimit(env, key) {
  const rlKey = `rl:${key}`;
  const now = Date.now();
  let rl = await env.EVAL_KV.get(rlKey, 'json');
  if (!rl || now - rl.firstAt > RL_WINDOW * 1000) {
    rl = { count: 0, firstAt: now };
  }
  if (rl.count >= RL_MAX) {
    const retryAfter = Math.ceil((rl.firstAt + RL_WINDOW * 1000 - now) / 1000);
    return { blocked: true, retryAfter: Math.max(1, retryAfter) };
  }
  rl.count++;
  await env.EVAL_KV.put(rlKey, JSON.stringify(rl), { expirationTtl: RL_WINDOW });
  return { blocked: false };
}

function clientKey(request) {
  return request.headers.get('CF-Connecting-IP') || 'local';
}

// ── Body parsing with size limit ─────────────────────────────────────────────

async function parseJsonBody(request, maxBytes = 4096) {
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.includes('application/json')) return null;
  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) return null;
  try { return JSON.parse(new TextDecoder().decode(buf)); } catch { return null; }
}

// ── Input validation helpers ──────────────────────────────────────────────────

function validStr(val, maxLen, pattern) {
  if (val === null || val === undefined) return true; // optional fields OK if absent
  if (typeof val !== 'string') return false;
  if (val.length > maxLen) return false;
  if (pattern && !pattern.test(val)) return false;
  return true;
}

const VALID_ROLES = new Set(['primero', 'segundo', 'anotador']);

// ── Log size enforcement ──────────────────────────────────────────────────────

async function pruneLogIfNeeded(env) {
  try {
    const ll = await env.EVAL_KV.list({ prefix: 'l:' });
    if (ll.keys.length > 1000) {
      const sorted = [...ll.keys].sort((a, b) => a.name.localeCompare(b.name));
      const toDelete = sorted.slice(0, sorted.length - 1000);
      await Promise.all(toDelete.map(k => env.EVAL_KV.delete(k.name)));
    }
  } catch {}
}

// ── Main router ───────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders(env), ...SEC_HEADERS } });
    }
    const path = new URL(request.url).pathname;

    if (path === '/auth/validate'  && request.method === 'POST') return handleValidate(request, env);
    if (path === '/auth/verify'    && request.method === 'POST') return handleVerify(request, env);
    if (path === '/log/pdf'        && request.method === 'POST') return handleLogPdf(request, env);
    if (path === '/feedback'       && request.method === 'POST') return handleFeedback(request, env);
    if (path === '/admin/login'    && request.method === 'POST') return handleAdminLogin(request, env);
    if (path === '/admin/logout'   && request.method === 'POST') return handleAdminLogout(request, env);

    if (path.startsWith('/admin/')) {
      if (!env.SESSION_SECRET) return noStoreJson({ error: 'Configuración incompleta' }, 503, env);
      if (!await verifyAdminToken(request.headers.get('Authorization'), env)) {
        return noStoreJson({ error: 'No autorizado' }, 401, env);
      }
      if (path === '/admin/data'          && request.method === 'GET')  return handleAdminData(env);
      if (path === '/admin/feedback'        && request.method === 'GET')    return handleAdminFeedback(env);
      if (path === '/admin/feedback/delete' && request.method === 'POST')   return handleAdminFeedbackDelete(request, env);
      if (path === '/admin/names'         && request.method === 'POST') return handleAddName(request, env);
      if (path === '/admin/revoke'        && request.method === 'POST') return handleRevoke(request, env);
      if (path === '/admin/reactivate'    && request.method === 'POST') return handleReactivate(request, env);
      if (path === '/admin/multidevice'   && request.method === 'POST') return handleMultiDevice(request, env);
      if (path === '/admin/create-fixed'  && request.method === 'POST') return handleCreateFixed(request, env);
      if (path === '/admin/delete'        && request.method === 'POST') return handleDelete(request, env);
    }

    return json({ error: 'Not found' }, 404, env);
  },
};

// ── Handlers ──────────────────────────────────────────────────────────────────

async function handleAdminLogin(request, env) {
  if (!env.SESSION_SECRET || !env.ADMIN_SECRET) {
    return noStoreJson({ error: 'Configuración incompleta' }, 503, env);
  }

  const ip = clientKey(request);
  const rl = await checkRateLimit(env, `adm:${ip}`);
  if (rl.blocked) {
    return noStoreJson({ error: 'Demasiados intentos. Espera antes de volver a intentar.' }, 429, env,
      { 'Retry-After': String(rl.retryAfter) });
  }

  const body = await parseJsonBody(request);
  if (!body) return noStoreJson({ error: 'Petición inválida' }, 400, env);

  const { password } = body;
  if (!password || typeof password !== 'string') {
    return noStoreJson({ error: 'Falta la contraseña' }, 400, env);
  }

  // Constant-time password comparison via HMAC
  const submittedHash = await hmacSha256Hex(env.SESSION_SECRET, password);
  const expectedHash  = await hmacSha256Hex(env.SESSION_SECRET, env.ADMIN_SECRET);
  if (!timingSafeEqual(submittedHash, expectedHash)) {
    // Log failed attempt
    await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
      type: 'login_fail', label: 'admin', deviceId: 'admin', timestamp: nowIso(),
      country: request.cf?.country || null, city: request.cf?.city || null,
    }), { expirationTtl: 365 * 86400 });
    return noStoreJson({ error: 'Contraseña incorrecta' }, 401, env);
  }

  const token = await issueAdminToken(env);
  return noStoreJson({ ok: true, token }, 200, env);
}

async function handleAdminLogout(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7).trim();
    const parts = token.split('.');
    if (parts.length === 3) {
      await env.EVAL_KV.delete(`adm:tok:${parts[0]}`);
    }
  }
  return noStoreJson({ ok: true }, 200, env);
}

async function handleValidate(request, env) {
  const ip = clientKey(request);
  const body = await parseJsonBody(request);
  if (!body) return json({ ok: false, error: 'Petición inválida' }, 400, env);

  const { code, deviceId, deviceInfo } = body;

  // Validate deviceId
  if (!code || !deviceId) return json({ ok: false, error: 'Datos incompletos' }, 400, env);
  if (typeof deviceId !== 'string' || deviceId.length > 64 || !/^[A-Za-z0-9\-_]+$/.test(deviceId)) {
    return json({ ok: false, error: 'deviceId inválido' }, 400, env);
  }

  // Validate deviceInfo fields if present
  if (deviceInfo && typeof deviceInfo === 'object') {
    if (!validStr(deviceInfo.ua, 200)) return json({ ok: false, error: 'deviceInfo inválido' }, 400, env);
    if (!validStr(deviceInfo.screen, 20, /^\d{2,5}x\d{2,5}$/)) return json({ ok: false, error: 'deviceInfo inválido' }, 400, env);
    if (!validStr(deviceInfo.lang, 20)) return json({ ok: false, error: 'deviceInfo inválido' }, 400, env);
    if (!validStr(deviceInfo.tz, 64)) return json({ ok: false, error: 'deviceInfo inválido' }, 400, env);
  }

  const normalized = String(code).trim().toUpperCase().replace(/[^0-9A-F]/g, '');
  if (normalized.length !== 8) return json({ ok: false, error: 'Código incorrecto' }, 200, env);

  // Rate limit by IP and deviceId
  const rlIp = await checkRateLimit(env, `val:ip:${ip}`);
  if (rlIp.blocked) {
    return json({ ok: false, error: 'Demasiados intentos. Espera antes de volver a intentar.' }, 429, env,
      { 'Retry-After': String(rlIp.retryAfter) });
  }
  const rlDev = await checkRateLimit(env, `val:did:${deviceId}`);
  if (rlDev.blocked) {
    return json({ ok: false, error: 'Demasiados intentos. Espera antes de volver a intentar.' }, 429, env,
      { 'Retry-After': String(rlDev.retryAfter) });
  }

  // Master code: stored as MASTER_CODE secret, never binds to a device
  if (env.MASTER_CODE && env.SESSION_SECRET) {
    const masterNorm = String(env.MASTER_CODE).trim().toUpperCase().replace(/[^0-9A-F]/g, '');
    const inputHmac  = await hmacSha256Hex(env.SESSION_SECRET, normalized);
    const masterHmac = await hmacSha256Hex(env.SESSION_SECRET, masterNorm);
    if (timingSafeEqual(inputHmac, masterHmac)) {
      const token = randomHex(32);
      const ts = nowIso();
      await env.EVAL_KV.put(`s:${token}`, JSON.stringify({
        masterSession: true, label: 'Demo', deviceId, createdAt: ts, lastSeen: ts,
      }), { expirationTtl: 8 * 3600 });
      await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
        type: 'master_login', label: 'Demo', deviceId, deviceInfo, timestamp: ts,
        country: request.cf?.country || null, city: request.cf?.city || null,
      }), { expirationTtl: 365 * 86400 });
      pruneLogIfNeeded(env);
      return json({ ok: true, token, label: 'Demo' }, 200, env);
    }
  }

  const hash = await sha256hex(normalized);
  const record = await env.EVAL_KV.get(`c:${hash}`, 'json');

  if (!record) {
    await logLoginFail(env, request, deviceId, deviceInfo);
    return json({ ok: false, error: 'Código incorrecto' }, 200, env);
  }
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
    country: request.cf?.country || null,
    city: request.cf?.city || null,
  }), { expirationTtl: 365 * 86400 });

  pruneLogIfNeeded(env); // fire-and-forget

  return json({ ok: true, token, label: record.label }, 200, env);
}

async function logLoginFail(env, request, deviceId, deviceInfo) {
  try {
    await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
      type: 'login_fail', deviceId, deviceInfo, timestamp: nowIso(),
      country: request.cf?.country || null, city: request.cf?.city || null,
    }), { expirationTtl: 365 * 86400 });
  } catch {}
}

async function appendAdminLog(env, request, event, extra) {
  try {
    await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
      type: event, timestamp: nowIso(),
      ip: clientKey(request),
      country: request.cf?.country || null,
      ...extra,
    }), { expirationTtl: 365 * 86400 });
    pruneLogIfNeeded(env);
  } catch {}
}

async function handleVerify(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ ok: false }, 400, env);

  const { token } = body;
  if (!token) return json({ ok: false }, 200, env);

  const session = await env.EVAL_KV.get(`s:${token}`, 'json');
  if (!session) return json({ ok: false }, 200, env);

  if (session.masterSession) {
    session.lastSeen = nowIso();
    await env.EVAL_KV.put(`s:${token}`, JSON.stringify(session), { expirationTtl: 8 * 3600 });
    return json({ ok: true, label: session.label }, 200, env);
  }

  const record = await env.EVAL_KV.get(`c:${session.codeHash}`, 'json');
  if (!record || record.status === 'revoked') return json({ ok: false }, 200, env);

  session.lastSeen = nowIso();
  await env.EVAL_KV.put(`s:${token}`, JSON.stringify(session), { expirationTtl: 180 * 86400 });

  return json({ ok: true, label: session.label }, 200, env);
}

async function handleLogPdf(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ ok: false }, 400, env);

  const { token, aspirant, role, examiner, nEval, fecha } = body;
  if (!token) return json({ ok: false }, 200, env);

  // Validate fields
  if (nEval !== null && nEval !== undefined) {
    const n = Number(nEval);
    if (!Number.isInteger(n) || n < 1 || n > 20) return json({ ok: false, error: 'nEval inválido' }, 400, env);
  }
  if (role !== null && role !== undefined && !VALID_ROLES.has(role)) {
    return json({ ok: false, error: 'role inválido' }, 400, env);
  }
  if (!validStr(aspirant, 120)) return json({ ok: false, error: 'aspirant inválido' }, 400, env);
  if (!validStr(examiner, 120)) return json({ ok: false, error: 'examiner inválido' }, 400, env);
  if (fecha !== null && fecha !== undefined && !validStr(fecha, 10, /^\d{4}-\d{2}-\d{2}$/)) {
    return json({ ok: false, error: 'fecha inválida' }, 400, env);
  }

  const session = await env.EVAL_KV.get(`s:${token}`, 'json');
  if (!session) return json({ ok: false }, 200, env);
  if (!session.masterSession) {
    const rec = await env.EVAL_KV.get(`c:${session.codeHash}`, 'json');
    if (!rec || rec.status === 'revoked') return json({ ok: false }, 200, env);
  }

  // Store normalized nEval as integer
  const nEvalNorm = (nEval !== null && nEval !== undefined) ? Number(nEval) : null;

  await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
    type: 'pdf', label: session.label, deviceId: session.deviceId,
    aspirant, role, examiner, nEval: nEvalNorm, fecha, timestamp: nowIso(),
  }), { expirationTtl: 365 * 86400 });

  pruneLogIfNeeded(env);

  return json({ ok: true }, 200, env);
}

async function handleAdminData(env) {
  const cl = await env.EVAL_KV.list({ prefix: 'c:' });
  const records = (await Promise.all(cl.keys.map(k => env.EVAL_KV.get(k.name, 'json')))).filter(Boolean);
  const codes = await Promise.all(records.map(async r => ({
    ...r,
    code: await deriveCode(r.label, env.DERIVE_SALT),
  })));

  const ll = await env.EVAL_KV.list({ prefix: 'l:' });
  const sortedKeys = [...ll.keys].sort((a, b) => b.name.localeCompare(a.name)).slice(0, 100);
  const logs = (await Promise.all(sortedKeys.map(k => env.EVAL_KV.get(k.name, 'json')))).filter(Boolean);

  return noStoreJson({ codes, logs }, 200, env);
}

async function handleAddName(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ error: 'Petición inválida' }, 400, env);

  const { name } = body;
  if (!name || typeof name !== 'string' || !name.trim()) return json({ error: 'Falta el nombre' }, 400, env);
  if (name.trim().length > 120) return json({ error: 'Nombre demasiado largo' }, 400, env);

  const code = await deriveCode(name, env.DERIVE_SALT);
  const normalized = code.replace('-', '');
  const hash = await sha256hex(normalized);

  const existing = await env.EVAL_KV.get(`c:${hash}`, 'json');

  if (existing) {
    if (existing.status === 'revoked') {
      existing.status = 'pending';
      existing.deviceId = null;
      existing.deviceInfo = null;
      existing.usedAt = null;
      await env.EVAL_KV.put(`c:${hash}`, JSON.stringify(existing));
      await appendAdminLog(env, request, 'code_reactivate', { label: existing.label, codeHash: hash });
      return json({ ok: true, code, reactivated: true }, 200, env);
    }
    return json({ ok: true, code, alreadyExists: true }, 200, env);
  }

  const newRecord = {
    id: randomHex(8),
    codeHash: hash,
    label: name.trim(),
    status: 'pending',
    deviceId: null,
    deviceInfo: null,
    usedAt: null,
    createdAt: nowIso(),
  };
  await env.EVAL_KV.put(`c:${hash}`, JSON.stringify(newRecord));
  await appendAdminLog(env, request, 'code_add', { label: newRecord.label, codeHash: hash });

  return json({ ok: true, code, codeHash: hash }, 200, env);
}

async function handleRevoke(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ error: 'Petición inválida' }, 400, env);

  const { codeHash } = body;
  if (!codeHash || typeof codeHash !== 'string') return json({ error: 'Datos inválidos' }, 400, env);
  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);

  record.status = 'revoked';
  await env.EVAL_KV.put(`c:${codeHash}`, JSON.stringify(record));
  await appendAdminLog(env, request, 'code_revoke', { label: record.label, codeHash });
  return json({ ok: true }, 200, env);
}

async function handleCreateFixed(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ error: 'Petición inválida' }, 400, env);
  const { label, code } = body;
  if (!label || typeof label !== 'string' || label.trim().length > 120) return json({ error: 'Nombre inválido' }, 400, env);
  if (!code) return json({ error: 'Faltan datos' }, 400, env);
  const normalized = String(code).trim().toUpperCase().replace(/[^0-9A-F]/g, '');
  if (normalized.length !== 8) return json({ error: 'Código debe ser 8 dígitos hex' }, 400, env);
  const hash = await sha256hex(normalized);
  const existing = await env.EVAL_KV.get(`c:${hash}`, 'json');
  if (existing) return json({ ok: true, codeHash: hash, alreadyExists: true }, 200, env);
  await env.EVAL_KV.put(`c:${hash}`, JSON.stringify({
    id: randomHex(8), codeHash: hash, label: label.trim(),
    status: 'active', deviceId: null, deviceInfo: null, usedAt: null, createdAt: nowIso(),
  }));
  return json({ ok: true, codeHash: hash }, 200, env);
}

async function handleMultiDevice(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ error: 'Petición inválida' }, 400, env);
  const { codeHash } = body;
  if (!codeHash || typeof codeHash !== 'string') return json({ error: 'Datos inválidos' }, 400, env);
  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);
  record.status = 'active';
  record.deviceId = null;
  record.deviceInfo = null;
  await env.EVAL_KV.put(`c:${codeHash}`, JSON.stringify(record));
  return json({ ok: true }, 200, env);
}

async function handleDelete(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ error: 'Petición inválida' }, 400, env);

  const { codeHash } = body;
  if (!codeHash || typeof codeHash !== 'string') return json({ error: 'Datos inválidos' }, 400, env);
  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);
  if (record.status !== 'revoked') return json({ error: 'Solo se pueden eliminar árbitros revocados' }, 400, env);

  await env.EVAL_KV.delete(`c:${codeHash}`);
  await appendAdminLog(env, request, 'code_delete', { label: record.label, codeHash });
  return json({ ok: true }, 200, env);
}

async function handleReactivate(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return json({ error: 'Petición inválida' }, 400, env);

  const { codeHash } = body;
  if (!codeHash || typeof codeHash !== 'string') return json({ error: 'Datos inválidos' }, 400, env);
  const record = await env.EVAL_KV.get(`c:${codeHash}`, 'json');
  if (!record) return json({ error: 'No encontrado' }, 404, env);

  record.status = 'pending';
  record.deviceId = null;
  record.deviceInfo = null;
  record.usedAt = null;
  await env.EVAL_KV.put(`c:${codeHash}`, JSON.stringify(record));
  await appendAdminLog(env, request, 'code_reactivate', { label: record.label, codeHash });
  return json({ ok: true }, 200, env);
}

async function handleFeedback(request, env) {
  const ip = clientKey(request);
  const rl = await checkRateLimit(env, `fb:ip:${ip}`);
  if (rl.blocked) {
    return json({ ok: false, error: 'Demasiados envíos. Espera antes de volver a intentar.' }, 429, env,
      { 'Retry-After': String(rl.retryAfter) });
  }

  const body = await parseJsonBody(request);
  if (!body) return json({ ok: false, error: 'Petición inválida' }, 400, env);

  const { type, message } = body;
  const VALID_TYPES = new Set(['sugerencia', 'queja']);
  if (!VALID_TYPES.has(type)) return json({ ok: false, error: 'Tipo inválido' }, 400, env);
  if (!message || typeof message !== 'string' || message.trim().length < 1 || message.length > 1000) {
    return json({ ok: false, error: 'Mensaje inválido' }, 400, env);
  }

  await env.EVAL_KV.put(`fb:${Date.now()}-${randomHex(4)}`, JSON.stringify({
    type, message: message.trim(), timestamp: nowIso(),
    country: request.cf?.country || null,
  }), { expirationTtl: 365 * 86400 });

  return json({ ok: true }, 200, env);
}

async function handleAdminFeedback(env) {
  const list = await env.EVAL_KV.list({ prefix: 'fb:' });
  const sorted = [...list.keys].sort((a, b) => b.name.localeCompare(a.name));
  const items = await Promise.all(sorted.map(async k => {
    const item = await env.EVAL_KV.get(k.name, 'json');
    return item ? { ...item, _key: k.name } : null;
  }));
  return noStoreJson({ ok: true, feedbacks: items.filter(Boolean) }, 200, env);
}

async function handleAdminFeedbackDelete(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return noStoreJson({ ok: false }, 400, env);
  const { key } = body;
  if (!key || typeof key !== 'string' || !key.startsWith('fb:')) {
    return noStoreJson({ ok: false, error: 'Clave inválida' }, 400, env);
  }
  await env.EVAL_KV.delete(key);
  return noStoreJson({ ok: true }, 200, env);
}

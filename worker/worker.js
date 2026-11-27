// Env vars needed: EVAL_KV (binding), ADMIN_SECRET, DERIVE_SALT, SESSION_SECRET, ALLOWED_ORIGIN
// Opcionales (aviso por correo de PDFs subidos): RESEND_API_KEY (secret), NOTIFY_EMAIL, NOTIFY_FROM, ADMIN_URL

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

async function checkRateLimit(env, key, max = RL_MAX) {
  const rlKey = `rl:${key}`;
  const now = Date.now();
  let rl = await env.EVAL_KV.get(rlKey, 'json');
  if (!rl || now - rl.firstAt > RL_WINDOW * 1000) {
    rl = { count: 0, firstAt: now };
  }
  if (rl.count >= max) {
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
const VALID_CURSOS = new Set(['nivel1', 'nivel2', 'anotador']); // curso que realiza el aspirante
const cursoOk = c => c === null || c === undefined || VALID_CURSOS.has(c);

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
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders(env), ...SEC_HEADERS } });
    }
    const path = new URL(request.url).pathname;

    if (path === '/auth/validate'  && request.method === 'POST') return handleValidate(request, env);
    if (path === '/auth/verify'    && request.method === 'POST') return handleVerify(request, env);
    if (path === '/log/pdf'        && request.method === 'POST') return handleLogPdf(request, env);
    if (path === '/feedback'       && request.method === 'POST') return handleFeedback(request, env);
    if (path === '/upload/pdf'     && request.method === 'POST') return handleUploadPdf(request, env, ctx);
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
      if (path === '/admin/log/delete'      && request.method === 'POST')   return handleLogDelete(request, env);
      if (path === '/admin/uploads'         && request.method === 'GET')    return handleAdminUploads(env);
      if (path === '/admin/uploads/file'    && request.method === 'GET')    return handleAdminUploadFile(request, env);
      if (path === '/admin/uploads/seen'    && request.method === 'POST')   return handleAdminUploadsSeen(request, env);
      if (path === '/admin/uploads/delete'  && request.method === 'POST')   return handleAdminUploadsDelete(request, env);
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
      return json({ ok: true, token, label: 'Demo', masterSession: true }, 200, env);
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
  }
  // Always refresh last-login metadata so the admin sees current device & timestamp
  record.lastLogin = ts;
  record.lastDeviceId = deviceId;
  record.lastDeviceInfo = deviceInfo;
  await env.EVAL_KV.put(`c:${hash}`, JSON.stringify(record));

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
    return json({ ok: true, label: session.label, masterSession: true }, 200, env);
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

  const { token, aspirant, role, examiner, nEval, fecha, passed, curso } = body;
  if (!token) return json({ ok: false }, 200, env);
  if (!cursoOk(curso)) return json({ ok: false, error: 'curso inválido' }, 400, env);

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

  const passedNorm = passed === true ? true : passed === false ? false : null;

  await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
    type: 'pdf', label: session.label, deviceId: session.deviceId,
    aspirant, role, examiner, nEval: nEvalNorm, curso: curso || null, fecha, passed: passedNorm, timestamp: nowIso(),
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
  const rawLogs = await Promise.all(sortedKeys.map(async k => {
    const v = await env.EVAL_KV.get(k.name, 'json');
    return v ? { ...v, _key: k.name } : null;
  }));
  const logs = rawLogs.filter(Boolean);

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

async function handleLogDelete(request, env) {
  const body = await parseJsonBody(request);
  if (!body) return noStoreJson({ ok: false }, 400, env);
  const { key } = body;
  if (!key || typeof key !== 'string' || !key.startsWith('l:')) {
    return noStoreJson({ ok: false, error: 'Clave inválida' }, 400, env);
  }
  await env.EVAL_KV.delete(key);
  return noStoreJson({ ok: true }, 200, env);
}

// ── PDFs subidos por los árbitros ─────────────────────────────────────────────
// KV:  up:<id>   → bytes del PDF (metadata con los datos de la evaluación)
//      upn:<id>  → '1' mientras la admin no lo ha abierto/descargado (aviso "nuevo")
// <id> = sha256(label|evId) recortado: si el árbitro reenvía la misma evaluación, se sustituye.

const UPLOAD_MAX_BYTES = 5 * 1024 * 1024;   // 5 MB por PDF (los informes pesan ~100-400 KB)
const UPLOAD_TTL = 365 * 86400;             // se conservan 1 año, igual que la actividad
const UPLOAD_RL_MAX = 10;                   // subidas por árbitro cada 15 min
const UPLOAD_ID_RE = /^[0-9a-f]{24}$/;
const ROLE_LABELS = { primero: '1º árbitro', segundo: '2º árbitro', anotador: 'Anotador' };
const CURSO_LABELS = { nivel1: 'Nivel 1', nivel2: 'Nivel 2', anotador: 'Anotador' };

const cut = (v, n) => (typeof v === 'string' ? v.slice(0, n) : null);

async function listAllKeys(env, prefix) {
  const keys = [];
  let cursor;
  do {
    const r = await env.EVAL_KV.list({ prefix, cursor });
    keys.push(...r.keys);
    cursor = r.list_complete ? null : r.cursor;
  } while (cursor);
  return keys;
}

async function handleUploadPdf(request, env, ctx) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > UPLOAD_MAX_BYTES + 64 * 1024) return json({ ok: false, error: 'El PDF es demasiado grande (máx. 5 MB)' }, 413, env);
  if (!(request.headers.get('Content-Type') || '').includes('multipart/form-data')) {
    return json({ ok: false, error: 'Petición inválida' }, 400, env);
  }

  let form;
  try { form = await request.formData(); } catch { return json({ ok: false, error: 'Petición inválida' }, 400, env); }
  const token = form.get('token');
  const file = form.get('file');
  let meta;
  try { meta = JSON.parse(String(form.get('meta') || '{}')); } catch { meta = null; }
  if (!token || typeof token !== 'string' || !meta || typeof meta !== 'object') {
    return json({ ok: false, error: 'Petición inválida' }, 400, env);
  }

  // Sesión del árbitro (mismas reglas que /log/pdf)
  const session = await env.EVAL_KV.get(`s:${token}`, 'json');
  if (!session) return json({ ok: false, error: 'Sesión no válida' }, 401, env);
  if (!session.masterSession) {
    const rec = await env.EVAL_KV.get(`c:${session.codeHash}`, 'json');
    if (!rec || rec.status === 'revoked') return json({ ok: false, error: 'Sesión no válida' }, 401, env);
  }

  const rl = await checkRateLimit(env, `up:${session.codeHash || session.label}`, UPLOAD_RL_MAX);
  if (rl.blocked) {
    return json({ ok: false, error: 'Demasiados envíos. Espera unos minutos.' }, 429, env,
      { 'Retry-After': String(rl.retryAfter) });
  }

  // Validación de datos (mismas reglas que /log/pdf)
  const { evId, aspirant, role, examiner, nEval, fecha, passed, fileName, curso } = meta;
  if (!cursoOk(curso)) return json({ ok: false, error: 'curso inválido' }, 400, env);
  if (!validStr(evId, 64, /^[A-Za-z0-9_-]+$/) || !evId) return json({ ok: false, error: 'evId inválido' }, 400, env);
  if (nEval !== null && nEval !== undefined) {
    const n = Number(nEval);
    if (!Number.isInteger(n) || n < 1 || n > 20) return json({ ok: false, error: 'nEval inválido' }, 400, env);
  }
  if (role !== null && role !== undefined && !VALID_ROLES.has(role)) return json({ ok: false, error: 'role inválido' }, 400, env);
  if (!validStr(aspirant, 120)) return json({ ok: false, error: 'aspirant inválido' }, 400, env);
  if (!validStr(examiner, 120)) return json({ ok: false, error: 'examiner inválido' }, 400, env);
  if (fecha !== null && fecha !== undefined && !validStr(fecha, 10, /^\d{4}-\d{2}-\d{2}$/)) {
    return json({ ok: false, error: 'fecha inválida' }, 400, env);
  }
  if (!validStr(fileName, 160, /^[A-Za-z0-9_.-]+\.pdf$/)) return json({ ok: false, error: 'Nombre de archivo inválido' }, 400, env);

  // El archivo tiene que ser un PDF de verdad
  if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') {
    return json({ ok: false, error: 'Falta el archivo' }, 400, env);
  }
  if (file.size > UPLOAD_MAX_BYTES) return json({ ok: false, error: 'El PDF es demasiado grande (máx. 5 MB)' }, 413, env);
  const bytes = await file.arrayBuffer();
  const head = new TextDecoder().decode(new Uint8Array(bytes.slice(0, 5)));
  if (bytes.byteLength < 100 || head !== '%PDF-') return json({ ok: false, error: 'El archivo no es un PDF' }, 400, env);

  const id = (await sha256hex(`${session.label}|${evId}`)).slice(0, 24);
  const replaced = (await env.EVAL_KV.list({ prefix: `up:${id}`, limit: 1 })).keys.length > 0;
  const nEvalNorm = (nEval !== null && nEval !== undefined) ? Number(nEval) : null;
  const metadata = {
    label: cut(session.label, 80), aspirant: cut(aspirant, 80), examiner: cut(examiner, 80),
    role: role || null, nEval: nEvalNorm, curso: curso || null, fecha: fecha || null,
    passed: passed === true ? true : passed === false ? false : null,
    name: fileName || `Evaluacion_${id}.pdf`, size: bytes.byteLength, ts: nowIso(),
  };
  // KV limita la metadata a 1024 bytes
  while (new TextEncoder().encode(JSON.stringify(metadata)).length > 1000 && metadata.examiner) metadata.examiner = null;

  await env.EVAL_KV.put(`up:${id}`, bytes, { metadata, expirationTtl: UPLOAD_TTL });
  await env.EVAL_KV.put(`upn:${id}`, '1', { expirationTtl: UPLOAD_TTL });
  await env.EVAL_KV.put(`l:${Date.now()}-${randomHex(4)}`, JSON.stringify({
    type: 'upload', label: session.label, deviceId: session.deviceId,
    aspirant, role, examiner, nEval: nEvalNorm, curso: curso || null, fecha, passed: metadata.passed, replaced, timestamp: nowIso(),
  }), { expirationTtl: 365 * 86400 });
  pruneLogIfNeeded(env);

  const mail = sendUploadEmail(env, metadata, replaced).catch(e => console.error('Aviso por correo fallido', e));
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(mail); else await mail;

  return json({ ok: true, replaced }, 200, env);
}

// Aviso por correo con Resend (gratis hasta 3.000/mes). Si faltan las variables, no hace nada.
async function sendUploadEmail(env, m, replaced) {
  // NOTIFY_EMAIL admite uno o varios correos separados por comas
  const to = String(env.NOTIFY_EMAIL || '').split(',').map(e => e.trim()).filter(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)).slice(0, 10);
  if (!env.RESEND_API_KEY || !to.length) return;
  const h = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const oneLine = s => String(s ?? '').replace(/[\r\n]+/g, ' ').trim();
  const roleTxt = ROLE_LABELS[m.role] || '—';
  const result = m.passed === true ? 'Supera' : m.passed === false ? 'No supera' : '—';
  const subject = oneLine(`${replaced ? 'PDF actualizado' : 'Nuevo PDF'}: ${m.aspirant || 'aspirante'} · ${roleTxt}${m.nEval ? ' · ' + m.nEval + 'ª eval.' : ''}`).slice(0, 180);
  const row = (k, v) => `<tr><td style="padding:4px 12px 4px 0;color:#64748b">${k}</td><td style="padding:4px 0"><b>${h(v)}</b></td></tr>`;
  const panel = env.ADMIN_URL ? `<p><a href="${h(env.ADMIN_URL)}">Abrir el panel de administración</a></p>` : '';
  const html = `<div style="font-family:system-ui,Arial,sans-serif;font-size:14px;color:#0f172a">
    <p>${replaced ? 'Se ha <b>actualizado</b> un PDF de evaluación' : 'Se ha subido un <b>nuevo PDF</b> de evaluación'}:</p>
    <table style="border-collapse:collapse">${row('Árbitro', m.label)}${row('Aspirante', m.aspirant)}${row('Curso', CURSO_LABELS[m.curso] || '—')}${row('Rol evaluado', roleTxt)}${row('Nº evaluación', m.nEval ? m.nEval + 'ª' : '—')}${row('Fecha', m.fecha || '—')}${row('Resultado', result)}</table>
    ${panel}<p style="color:#64748b;font-size:12px">Lo tienes en la pestaña «PDFs» del panel.</p></div>`;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.NOTIFY_FROM || 'FVBCV Evaluaciones <onboarding@resend.dev>',
      to, subject, html,
    }),
  });
  // Si Resend rechaza el envío (clave mala, destinatario no permitido…) queda en los logs del Worker
  if (!res.ok) console.error('Resend error', res.status, (await res.text().catch(() => '')).slice(0, 300));
}

async function handleAdminUploads(env) {
  const [files, news] = await Promise.all([listAllKeys(env, 'up:'), listAllKeys(env, 'upn:')]);
  const isNew = new Set(news.map(k => k.name.slice(4)));
  const items = files.map(k => {
    const id = k.name.slice(3);
    return { id, ...(k.metadata || {}), isNew: isNew.has(id) };
  }).sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
  return noStoreJson({ ok: true, uploads: items, newCount: items.filter(i => i.isNew).length }, 200, env);
}

async function handleAdminUploadFile(request, env) {
  const id = new URL(request.url).searchParams.get('id') || '';
  if (!UPLOAD_ID_RE.test(id)) return noStoreJson({ ok: false, error: 'id inválido' }, 400, env);
  const { value, metadata } = await env.EVAL_KV.getWithMetadata(`up:${id}`, 'arrayBuffer');
  if (!value) return noStoreJson({ ok: false, error: 'No encontrado' }, 404, env);
  if (await env.EVAL_KV.get(`upn:${id}`)) await env.EVAL_KV.delete(`upn:${id}`); // ya visto
  const name = String(metadata?.name || `Evaluacion_${id}.pdf`).replace(/[^A-Za-z0-9_.-]/g, '_');
  return new Response(value, {
    status: 200,
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${name}"`,
      'Cache-Control': 'no-store',
      ...corsHeaders(env),
      ...SEC_HEADERS,
    },
  });
}

async function parseIds(request) {
  const body = await parseJsonBody(request, 16384);
  if (!body || !Array.isArray(body.ids) || body.ids.length < 1 || body.ids.length > 300) return null;
  if (!body.ids.every(i => typeof i === 'string' && UPLOAD_ID_RE.test(i))) return null;
  return [...new Set(body.ids)];
}

async function handleAdminUploadsSeen(request, env) {
  const ids = await parseIds(request);
  if (!ids) return noStoreJson({ ok: false, error: 'Datos inválidos' }, 400, env);
  await Promise.all(ids.map(id => env.EVAL_KV.delete(`upn:${id}`)));
  return noStoreJson({ ok: true }, 200, env);
}

async function handleAdminUploadsDelete(request, env) {
  const ids = await parseIds(request);
  if (!ids) return noStoreJson({ ok: false, error: 'Datos inválidos' }, 400, env);
  await Promise.all(ids.flatMap(id => [env.EVAL_KV.delete(`up:${id}`), env.EVAL_KV.delete(`upn:${id}`)]));
  await appendAdminLog(env, request, 'upload_delete', { count: ids.length });
  return noStoreJson({ ok: true }, 200, env);
}

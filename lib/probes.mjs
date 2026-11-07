// Sondas sin dependencias (Node ≥ 20): HTTP, handshake WebSocket, certificado TLS, PM2 y host.
import http from 'node:http';
import tls from 'node:tls';
import { readFileSync, statfsSync } from 'node:fs';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);

/** Clasifica un error de red en un tipo estable para decidir la capa de falla. */
export function classifyError(err) {
  const code = err?.cause?.code || err?.code || '';
  const name = err?.name || '';
  if (name === 'TimeoutError' || name === 'AbortError' || /TIMEOUT|ETIMEDOUT/.test(code)) return 'timeout';
  if (/ENOTFOUND|EAI_AGAIN/.test(code)) return 'dns';
  if (/CERT|SSL|TLS|UNABLE_TO_VERIFY|DEPTH_ZERO/.test(code)) return 'tls';
  if (/ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|UND_ERR_SOCKET/.test(code)) return 'connect';
  return 'unknown';
}

/**
 * GET con timeout. `ok` = respondió con status < okBelow (por defecto < 500).
 * @returns {Promise<{ ok: boolean, status: number|null, ms: number, json?: any, errorKind?: string, error?: string }>}
 */
export async function httpProbe(url, { timeoutMs = 5000, headers = {}, okBelow = 500, parseJson = false, fetchImpl = fetch } = {}) {
  const t0 = Date.now();
  try {
    const res = await fetchImpl(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    let json;
    if (parseJson) json = await res.json().catch(() => undefined);
    else await res.arrayBuffer().catch(() => undefined);
    const ok = res.status < okBelow;
    return { ok, status: res.status, ms: Date.now() - t0, json, ...(ok ? {} : { errorKind: 'http', error: `HTTP ${res.status}` }) };
  } catch (err) {
    return { ok: false, status: null, ms: Date.now() - t0, errorKind: classifyError(err), error: String(err?.cause?.code || err?.message || err).slice(0, 160) };
  }
}

/**
 * Handshake WebSocket crudo. El proceso está vivo si acepta la conexión y responde al Upgrade
 * (101, o un 4xx/5xx propio del servidor). Solo un timeout o un rechazo TCP cuentan como caída.
 */
export function wsProbe(host, port, { path = '/', timeoutMs = 5000 } = {}) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      req.destroy();
      resolve({ ms: Date.now() - t0, ...r });
    };
    const req = http.request({
      host,
      port,
      path,
      timeout: timeoutMs,
      headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': randomBytes(16).toString('base64') },
    });
    req.on('upgrade', (res, socket) => {
      socket.destroy();
      finish({ ok: true, status: res.statusCode });
    });
    req.on('response', (res) => {
      res.resume();
      finish({ ok: res.statusCode < 500, status: res.statusCode, ...(res.statusCode < 500 ? {} : { errorKind: 'http', error: `HTTP ${res.statusCode}` }) });
    });
    req.on('timeout', () => finish({ ok: false, status: null, errorKind: 'timeout', error: 'timeout' }));
    req.on('error', (err) => finish({ ok: false, status: null, errorKind: classifyError(err), error: String(err.code || err.message).slice(0, 160) }));
    req.end();
  });
}

/** Días restantes del certificado TLS presentado por host:443. */
export function tlsDaysLeft(host, { port = 443, timeoutMs = 8000, now = Date.now() } = {}) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host, port, servername: host, timeout: timeoutMs }, () => {
      const cert = sock.getPeerCertificate();
      sock.end();
      const validTo = cert?.valid_to ? Date.parse(cert.valid_to) : NaN;
      resolve(Number.isFinite(validTo)
        ? { ok: true, daysLeft: Math.floor((validTo - now) / 86_400_000), validTo: new Date(validTo).toISOString(), authorized: sock.authorized }
        : { ok: false, error: 'sin certificado' });
    });
    sock.on('timeout', () => {
      sock.destroy();
      resolve({ ok: false, errorKind: 'timeout', error: 'timeout' });
    });
    sock.on('error', (err) => resolve({ ok: false, errorKind: classifyError(err), error: String(err.code || err.message).slice(0, 160) }));
  });
}

/** Normaliza la salida de `pm2 jlist`. */
export function parsePm2(jsonText) {
  const list = JSON.parse(jsonText);
  return list.map((p) => ({
    name: p.name,
    status: p.pm2_env?.status ?? 'unknown',
    restarts: Number(p.pm2_env?.restart_time ?? 0),
    unstableRestarts: Number(p.pm2_env?.unstable_restarts ?? 0),
    uptimeMs: p.pm2_env?.pm_uptime ? Date.now() - p.pm2_env.pm_uptime : 0,
    memoryMb: Math.round((p.monit?.memory ?? 0) / 1048576),
    cpu: p.monit?.cpu ?? 0,
  }));
}

export async function pm2List({ bin = 'pm2', exec = execFileP } = {}) {
  const { stdout } = await exec(bin, ['jlist'], { timeout: 15_000, maxBuffer: 16 * 1024 * 1024 });
  return parsePm2(stdout);
}

// En Linux, os.freemem() es MemFree (excluye caché recuperable); MemAvailable es la métrica correcta.
function memAvailableBytes() {
  try {
    const m = /^MemAvailable:\s+(\d+)\s+kB/m.exec(readFileSync('/proc/meminfo', 'utf8'));
    if (m) return Number(m[1]) * 1024;
  } catch {}
  return os.freemem();
}

/** Métricas del host: disco de `/`, memoria disponible y carga. */
export function hostMetrics({ path = '/' } = {}) {
  const fsStat = statfsSync(path);
  const total = fsStat.blocks * fsStat.bsize;
  const free = fsStat.bavail * fsStat.bsize;
  return {
    diskUsedPct: total ? Math.round(((total - free) / total) * 1000) / 10 : 0,
    memAvailPct: Math.round((memAvailableBytes() / os.totalmem()) * 1000) / 10,
    load1: Math.round(os.loadavg()[0] * 100) / 100,
    cpus: os.cpus().length,
    uptimeS: Math.round(os.uptime()),
  };
}

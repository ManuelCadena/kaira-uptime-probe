// Utilidades de proceso: .env sin dependencias, estado JSON atómico y log estructurado.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/** Lee KEY=VALUE de un archivo .env. process.env tiene prioridad sobre el archivo. */
export function loadEnv(path, base = process.env) {
  const out = {};
  if (path && existsSync(path)) {
    for (const raw of readFileSync(path, 'utf8').split('\n')) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(raw);
      if (!m || raw.trim().startsWith('#')) continue;
      out[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  }
  return { ...out, ...Object.fromEntries(Object.entries(base).filter(([, v]) => v !== undefined && v !== '')) };
}

export function loadJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return fallback;
  }
}

/** Escritura atómica (tmp + rename) con permisos 600. */
export function saveJson(path, data) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

export function makeLogger(scope, sink = console.log) {
  return (event, data = {}) => sink(JSON.stringify({ scope, event, ...data, ts: new Date().toISOString() }));
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

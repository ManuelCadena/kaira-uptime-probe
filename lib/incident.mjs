// Máquina de estados de incidentes (pura, sin E/S). La usan el sentinel (M5) y la sonda externa.
// OK → SUSPECT → REMEDIATING → RECOVERED → OK, o bien → ESCALATED cuando se agota el presupuesto
// o la falla no es autorremediable. Cada transición emite como máximo una notificación.
import { createHash } from 'node:crypto';

export const S = Object.freeze({
  OK: 'OK',
  SUSPECT: 'SUSPECT',
  REMEDIATING: 'REMEDIATING',
  RECOVERED: 'RECOVERED',
  ESCALATED: 'ESCALATED',
});

export const DEFAULTS = Object.freeze({
  failThreshold: 2, // fallas consecutivas para abrir incidente
  recoverThreshold: 2, // éxitos consecutivos para declarar recuperación
  restartBudget: 3, // remediaciones máximas por ventana
  budgetWindowMs: 15 * 60_000,
  backoffMs: [30_000, 90_000, 240_000], // espera mínima tras el intento n antes del n+1
  startupGraceMs: 20_000, // tras remediar, no evaluar antes de este tiempo
  holdMs: 5 * 60_000, // RECOVERED estable antes de cerrar el incidente
  reminderMs: 60 * 60_000, // recordatorio mientras siga ESCALATED
});

export function initialState() {
  return { state: S.OK, since: 0, fails: 0, oks: 0, attempts: [], lastActionAt: 0, lastNotifyAt: 0, incidentId: null, lastError: null, layer: null };
}

export function incidentId(target, ts) {
  return `${target}-${createHash('sha256').update(`${target}:${ts}`).digest('hex').slice(0, 10)}`;
}

/**
 * @param {string} target
 * @param {ReturnType<typeof initialState>} prev
 * @param {{ ok: boolean, remediable?: boolean, layer?: string, detail?: string }} obs
 * @param {number} now epoch ms
 * @param {Partial<typeof DEFAULTS>} [cfgIn]
 * @returns {{ next: ReturnType<typeof initialState>, actions: Array<{ type: 'notify', kind: string } | { type: 'remediate', attempt: number }> }}
 */
export function step(target, prev, obs, now, cfgIn = {}) {
  const cfg = { ...DEFAULTS, ...cfgIn };
  const s = { ...initialState(), ...prev, attempts: (prev?.attempts || []).filter((t) => now - t < cfg.budgetWindowMs) };
  const actions = [];
  const notify = (kind) => {
    actions.push({ type: 'notify', kind });
    s.lastNotifyAt = now;
  };
  const go = (state) => {
    s.state = state;
    s.since = now;
  };
  const remediate = () => {
    s.attempts.push(now);
    s.lastActionAt = now;
    s.oks = 0;
    actions.push({ type: 'remediate', attempt: s.attempts.length });
    go(S.REMEDIATING);
  };
  const canRemediate = () => obs.remediable !== false && s.attempts.length < cfg.restartBudget;
  const backoffElapsed = () => now - s.lastActionAt >= cfg.backoffMs[Math.min(s.attempts.length, cfg.backoffMs.length) - 1];
  const escalate = () => {
    go(S.ESCALATED);
    notify('escalated');
  };

  if (obs.ok) {
    s.fails = 0;
    s.oks += 1;
  } else {
    s.oks = 0;
    s.fails += 1;
    s.lastError = obs.detail ?? s.lastError;
    s.layer = obs.layer ?? s.layer;
  }

  switch (s.state) {
    case S.OK:
    case S.SUSPECT:
      if (obs.ok) {
        if (s.state === S.SUSPECT) go(S.OK);
        break;
      }
      if (s.fails < cfg.failThreshold) {
        if (s.state === S.OK) go(S.SUSPECT);
        break;
      }
      s.incidentId = incidentId(target, now);
      if (canRemediate()) {
        notify('open');
        remediate();
      } else escalate();
      break;

    case S.REMEDIATING:
      if (now - s.lastActionAt < cfg.startupGraceMs) {
        s.oks = 0; // los éxitos durante el arranque no cuentan como recuperación
        break;
      }
      if (obs.ok) {
        if (s.oks >= cfg.recoverThreshold) {
          go(S.RECOVERED);
          notify('recovered');
        }
        break;
      }
      if (!canRemediate()) escalate();
      else if (backoffElapsed()) remediate();
      break;

    case S.RECOVERED:
      if (obs.ok) {
        if (now - s.since >= cfg.holdMs) {
          go(S.OK);
          s.incidentId = null;
          s.layer = null;
          s.lastError = null;
        }
        break;
      }
      // Recaída dentro del periodo de retención: mismo incidente, mismo presupuesto (anti-flapping).
      if (canRemediate()) remediate();
      else escalate();
      break;

    case S.ESCALATED:
      if (obs.ok) {
        if (s.oks >= cfg.recoverThreshold) {
          go(S.RECOVERED);
          notify('recovered');
        }
      } else if (now - s.lastNotifyAt >= cfg.reminderMs) notify('reminder');
      break;
  }
  return { next: s, actions };
}

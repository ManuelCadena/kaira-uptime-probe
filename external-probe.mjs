#!/usr/bin/env node
// Anillo B — sonda externa (GitHub Actions, fuera de AWS). Detecta lo que el sentinel no puede ver:
// M5 inalcanzable, sentinel muerto, app caída que el sentinel no levantó, y vencimiento TLS.
// Si M5 no responde a nivel de red, reinicia la instancia EC2 (IAM mínimo, 1 vez por hora) y verifica.
// El estado entre corridas se persiste en EXTERNAL_STATE_PATH (actions/cache en el workflow).
// Salida: 0 = todo OK; 2 = hay incidente abierto (el run queda rojo y GitHub avisa por correo).
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { initialState, step, S } from './lib/incident.mjs';
import { httpProbe, tlsDaysLeft } from './lib/probes.mjs';
import { createNotifier, formatAlert } from './lib/notify.mjs';
import { loadEnv, loadJson, makeLogger, saveJson, sleep as realSleep } from './lib/runtime.mjs';

const execFileP = promisify(execFile);
const MIN = 60_000;
const HOUR = 60 * MIN;
const NETWORK = new Set(['timeout', 'connect', 'dns', 'unknown']);

export const TARGET_CFG = {
  // Ya se confirmó con reintentos dentro de la corrida; 1 reinicio de instancia por hora como máximo.
  'm5-host': { failThreshold: 1, recoverThreshold: 1, restartBudget: 1, budgetWindowMs: HOUR, backoffMs: [HOUR], startupGraceMs: 0, holdMs: 0, reminderMs: HOUR },
  // 5xx con M5 vivo: le corresponde al sentinel; se escala si persiste 2 corridas.
  'kaira-web': { failThreshold: 2, recoverThreshold: 1, holdMs: 0, reminderMs: HOUR },
  sentinel: { failThreshold: 2, recoverThreshold: 1, holdMs: 0, reminderMs: 6 * HOUR },
  tls: { failThreshold: 1, recoverThreshold: 1, holdMs: 0, reminderMs: 24 * HOUR },
};

/**
 * @param {{ env: Record<string,string>, probes?: object, exec?: Function, notifier?: object, now?: () => number, sleep?: Function, log?: Function }} deps
 */
export function createExternalProbe({ env, probes = {}, exec = execFileP, notifier, now = Date.now, sleep = realSleep, log = makeLogger('kaira_external') }) {
  const P = { httpProbe, tlsDaysLeft, ...probes };
  const base = (env.KAIRA_PUBLIC_URL || 'https://mykaira.ai').replace(/\/$/, '');
  const liveUrl = `${base}/api/health?mode=live`;
  const deepUrl = `${base}/api/health?mode=deep`;
  const retries = Number(env.EXTERNAL_RETRIES || 3);
  const retryDelayMs = Number(env.EXTERNAL_RETRY_DELAY_MS || 20_000);
  const rebootWaitMs = Number(env.EXTERNAL_REBOOT_WAIT_MS || 6 * MIN);
  const canReboot = env.EXTERNAL_EC2_REBOOT === '1' && Boolean(env.EC2_INSTANCE_ID && env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY);
  const notify = notifier ?? createNotifier({ env, log });

  /** Sonda pública con reintentos: una falla aislada de red no abre incidente. */
  async function probeLive() {
    let r;
    for (let i = 0; i < retries; i++) {
      r = await P.httpProbe(liveUrl, { timeoutMs: 10_000 });
      if (r.ok) return r;
      if (i < retries - 1) await sleep(retryDelayMs);
    }
    return r;
  }

  const aws = (args) => exec('aws', [...args, '--region', env.AWS_REGION || 'us-west-2', '--output', 'json'], { timeout: 60_000 });

  async function rebootInstance() {
    const id = env.EC2_INSTANCE_ID;
    try {
      const { stdout } = await aws(['ec2', 'describe-instance-status', '--instance-ids', id, '--include-all-instances']);
      const st = JSON.parse(stdout).InstanceStatuses?.[0];
      const stateName = st?.InstanceState?.Name ?? 'desconocido';
      const checks = `sistema=${st?.SystemStatus?.Status ?? '?'} instancia=${st?.InstanceStatus?.Status ?? '?'}`;
      if (stateName !== 'running') return { ok: false, rebooted: false, detail: `instancia en estado ${stateName} (${checks}); no se reinicia automaticamente` };
      await aws(['ec2', 'reboot-instances', '--instance-ids', id]);
      log('ec2_reboot_requested', { instance: id, checks });
      return { ok: true, rebooted: true, detail: `reboot solicitado (${checks})` };
    } catch (err) {
      return { ok: false, rebooted: false, detail: `AWS: ${String(err?.stderr || err?.message || err).slice(0, 160)}` };
    }
  }

  async function waitForRecovery() {
    const deadline = now() + rebootWaitMs;
    while (now() < deadline) {
      await sleep(20_000);
      const r = await P.httpProbe(liveUrl, { timeoutMs: 10_000 });
      if (r.ok) return r;
    }
    return P.httpProbe(liveUrl, { timeoutMs: 10_000 });
  }

  async function observeAll() {
    const facts = {};
    const live = await probeLive();
    facts.live = { status: live.status, ms: live.ms, error: live.error, errorKind: live.errorKind };
    const networkDown = !live.ok && NETWORK.has(live.errorKind);
    const obs = {
      'm5-host': networkDown ? { ok: false, remediable: canReboot, layer: 'L3', detail: `M5 inalcanzable: ${live.error}` } : { ok: true },
      'kaira-web': networkDown ? null : live.ok ? { ok: true } : { ok: false, remediable: false, layer: live.errorKind === 'tls' ? 'L4' : 'L1', detail: `publico: ${live.error}` },
      sentinel: null,
      tls: null,
    };
    if (live.ok && env.HEALTH_TOKEN) {
      const deep = await P.httpProbe(deepUrl, { timeoutMs: 20_000, okBelow: 600, parseJson: true, headers: { 'x-health-token': env.HEALTH_TOKEN } });
      const hb = deep.json?.checks?.['sentinel:heartbeat']?.[0];
      facts.deep = { status: deep.status, overall: deep.json?.status, sentinel: hb };
      if (hb) obs.sentinel = hb.status === 'fail' ? { ok: false, remediable: false, layer: 'L1', detail: `sentinel sin latido: ${hb.output ?? ''}`.trim() } : { ok: true };
    }
    const host = new URL(base).hostname;
    const cert = await P.tlsDaysLeft(host);
    facts.tls = cert;
    if (cert.ok) obs.tls = cert.daysLeft < Number(env.EXTERNAL_TLS_MIN_DAYS || 14) ? { ok: false, remediable: false, layer: 'L4', detail: `certificado vence en ${cert.daysLeft} dias` } : { ok: true };
    return { obs, facts };
  }

  async function emit(target, next, kind) {
    const k = kind === 'escalated' && !(target === 'm5-host' && canReboot) ? 'alert' : kind;
    const extra = target === 'm5-host' && kind === 'escalated' ? ['Revisa la consola EC2 (estado, status checks, logs de sistema).'] : [];
    const res = await notify.send(formatAlert({ ring: 'EXTERNO', target, kind: k, detail: next.lastError, attempts: next.attempts.length, incidentId: next.incidentId, layer: next.layer, extra }));
    return { target, action: 'notify', kind: k, ok: res.ok, channel: res.channel };
  }

  async function run(state) {
    const s = { targets: {}, ...state };
    const { obs, facts } = await observeAll();
    const events = [];
    for (const [target, o] of Object.entries(obs)) {
      if (!o) continue;
      let prev = s.targets[target] ?? initialState();
      let { next, actions } = step(target, prev, o, now(), TARGET_CFG[target]);
      for (const a of actions) {
        if (a.type === 'notify') {
          events.push(await emit(target, next, a.kind));
          continue;
        }
        // Única remediación externa: reinicio de la instancia EC2, seguido de verificación en la misma corrida.
        const rb = await rebootInstance();
        events.push({ target, action: 'remediate', ok: rb.ok, detail: rb.detail });
        const after = rb.rebooted ? await waitForRecovery() : { ok: false, error: rb.detail };
        const v = step(target, next, after.ok ? { ok: true } : { ok: false, remediable: canReboot, layer: 'L3', detail: rb.rebooted ? `sigue inalcanzable tras reboot: ${after.error}` : rb.detail }, now(), TARGET_CFG[target]);
        next = v.next;
        for (const b of v.actions) if (b.type === 'notify') events.push(await emit(target, next, b.kind));
      }
      if (prev.state !== next.state) log('transition', { target, from: prev.state, to: next.state, detail: next.lastError });
      s.targets[target] = next;
    }
    s.lastRunAt = now();
    s.facts = facts;
    const open = Object.entries(s.targets).filter(([, v]) => v.state !== S.OK && v.state !== S.RECOVERED).map(([k, v]) => `${k}=${v.state}`);
    return { state: s, events, open, facts };
  }

  return { run, canReboot, notify };
}

function writeSummary(result) {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  const rows = Object.entries(result.state.targets).map(([k, v]) => `| ${k} | ${v.state} | ${v.layer ?? ''} | ${(v.lastError ?? '').replace(/\|/g, '/')} |`);
  appendFileSync(path, [`### Kaira — sonda externa (${new Date().toISOString()})`, '', '| Objetivo | Estado | Capa | Ultimo error |', '|---|---|---|---|', ...rows, '', `Eventos: ${result.events.length ? JSON.stringify(result.events) : 'ninguno'}`, ''].join('\n'));
}

async function main() {
  const env = loadEnv(process.env.EXTERNAL_ENV_FILE);
  const statePath = env.EXTERNAL_STATE_PATH || 'state/external-state.json';
  const probe = createExternalProbe({ env });
  if (process.argv.includes('--send-test')) {
    const r = await probe.notify.send(formatAlert({ ring: 'EXTERNO', target: 'canal de alertas', kind: 'test', extra: ['Si recibes esto, el canal WhatsApp de la sonda externa funciona.'] }));
    console.log(JSON.stringify({ ok: r.ok, channel: r.channel, error: r.error }));
    process.exit(r.ok ? 0 : 1);
  }
  const result = await probe.run(loadJson(statePath, {}));
  saveJson(statePath, result.state);
  writeSummary(result);
  console.log(JSON.stringify({ open: result.open, events: result.events, facts: result.facts, ec2Reboot: probe.canReboot }, null, 2));
  process.exit(result.open.length ? 2 : 0);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

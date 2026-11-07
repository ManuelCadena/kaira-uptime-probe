// Notificador independiente de chatita-comms: habla directo con la API de Twilio.
// chatita.ai corre en el mismo host M5 que Kaira; si M5 cae, chatita no puede avisar.
// WhatsApp proactivo (fuera de la ventana de 24 h) exige plantilla aprobada (ContentSid);
// Meta rechaza variables con saltos de línea, tabs o más de 4 espacios seguidos.

const TITLES = {
  open: 'CAIDO - intentando levantarlo',
  recovered: 'RECUPERADO',
  escalated: 'NO SE PUDO LEVANTAR - requiere intervencion',
  reminder: 'SIGUE CAIDO - recordatorio',
  alert: 'ALERTA - sin remediacion automatica',
  report: 'Reporte de salud',
  test: 'Prueba del canal de alertas',
};

/**
 * @param {{ ring: string, target: string, kind: string, detail?: string|null, attempts?: number, incidentId?: string|null, layer?: string|null, extra?: string[] }} e
 * @returns {string[]} líneas del mensaje
 */
export function formatAlert(e) {
  const lines = [`[KAIRA ${e.ring}] ${TITLES[e.kind] ?? e.kind}: ${e.target}`];
  if (e.layer) lines.push(`Capa: ${e.layer}`);
  if (e.detail) lines.push(`Detalle: ${String(e.detail).slice(0, 200)}`);
  if (e.attempts) lines.push(`Intentos automaticos: ${e.attempts}`);
  if (e.kind === 'escalated') lines.push('Accion: entra a M5 (ssh m5; pm2 status; pm2 logs) o revisa la consola EC2.');
  for (const x of e.extra ?? []) lines.push(x);
  if (e.incidentId) lines.push(`Incidente: ${e.incidentId}`);
  lines.push(new Date().toISOString());
  return lines;
}

/** Aplana las líneas para una variable de plantilla de WhatsApp. */
export function flattenForTemplate(lines, max = 900) {
  return lines.map((l) => String(l).replace(/\s+/g, ' ').trim()).filter(Boolean).join(' | ').slice(0, max);
}

/**
 * @param {{ env: Record<string,string|undefined>, fetchImpl?: typeof fetch, log?: (event: string, data?: object) => void }} opts
 */
export function createNotifier({ env, fetchImpl = fetch, log = () => {} }) {
  const sid = env.TWILIO_ACCOUNT_SID;
  const token = env.TWILIO_AUTH_TOKEN;
  const waFrom = env.TWILIO_WHATSAPP_FROM;
  const template = env.TWILIO_WA_TEMPLATE_SID;
  const to = env.KAIRA_ALERT_WHATSAPP_TO;
  const smsFrom = env.TWILIO_SMS_FROM || env.TWILIO_PHONE;
  const smsTo = env.KAIRA_ALERT_SMS_TO || to;
  const dryRun = env.MONITOR_DRY_RUN === '1';
  const configured = Boolean(sid && token && waFrom && to);

  async function post(params) {
    const res = await fetchImpl(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(`${sid}:${token}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params).toString(),
      signal: AbortSignal.timeout(15_000),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok && body.sid ? { ok: true, sid: body.sid, status: body.status } : { ok: false, error: `${res.status} ${body.code ?? ''} ${body.message ?? ''}`.trim().slice(0, 200) };
  }

  /** @param {string[]} lines */
  async function send(lines) {
    if (dryRun) {
      log('notify_dry_run', { text: lines.join(' | ') });
      return { ok: true, channel: 'dry-run' };
    }
    if (!configured) {
      log('notify_unconfigured', { missing: ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_WHATSAPP_FROM', 'KAIRA_ALERT_WHATSAPP_TO'].filter((k) => !env[k]) });
      return { ok: false, channel: 'none', error: 'notificador sin configurar' };
    }
    const wa = await post({
      From: `whatsapp:${waFrom}`,
      To: `whatsapp:${to}`,
      ...(template ? { ContentSid: template, ContentVariables: JSON.stringify({ 1: flattenForTemplate(lines) }) } : { Body: lines.join('\n').slice(0, 1500) }),
    }).catch((err) => ({ ok: false, error: String(err?.message || err).slice(0, 200) }));
    if (wa.ok) {
      log('notify_sent', { channel: 'whatsapp', sid: wa.sid, status: wa.status, mode: template ? 'template' : 'freeform' });
      return { ...wa, channel: 'whatsapp' };
    }
    log('notify_whatsapp_failed', { error: wa.error });
    if (!smsFrom || !smsTo) return { ...wa, channel: 'whatsapp' };
    const sms = await post({ From: smsFrom, To: smsTo, Body: lines.join('\n').slice(0, 1500) }).catch((err) => ({ ok: false, error: String(err?.message || err).slice(0, 200) }));
    log(sms.ok ? 'notify_sent' : 'notify_sms_failed', sms.ok ? { channel: 'sms', sid: sms.sid } : { error: sms.error });
    return { ...sms, channel: 'sms', whatsappError: wa.error };
  }

  return { send, configured, dryRun };
}

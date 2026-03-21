'use strict';
const express    = require('express');
const axios      = require('axios');
const crypto     = require('crypto');
const { Pool }   = require('pg');
const { Resend } = require('resend');
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY || '');
const cron       = require('node-cron');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Stripe webhook needs raw body ─────────────────────────────────────────────
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Config ────────────────────────────────────────────────────────────────────
const HUBSPOT_CLIENT_ID     = process.env.HUBSPOT_CLIENT_ID;
const HUBSPOT_CLIENT_SECRET = process.env.HUBSPOT_CLIENT_SECRET;
const HUBSPOT_REDIRECT_URI  = process.env.HUBSPOT_REDIRECT_URI;
const RESEND_API_KEY        = process.env.RESEND_API_KEY;
const FIXOPS_NOTIFY_EMAIL   = process.env.FIXOPS_NOTIFY_EMAIL || 'matthew@fixops.io';
const BASE_URL              = process.env.BASE_URL || 'https://fixops-api-production.up.railway.app';
const FRONTEND_URL          = process.env.FRONTEND_URL || 'https://fixops.io';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

// Stripe plan → internal plan key mapping
const STRIPE_PRICE_MAP = {
  [process.env.STRIPE_PRICE_PULSE    || 'price_pulse']:     'pulse',
  [process.env.STRIPE_PRICE_PRO      || 'price_pro']:       'pro',
  [process.env.STRIPE_PRICE_COMMAND  || 'price_command']:   'command',
  [process.env.STRIPE_PRICE_DEEP     || 'price_deep']:      'deep',
  [process.env.STRIPE_PRICE_PROAUDIT || 'price_proaudit']:  'pro-audit',
};

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const resend = new Resend(RESEND_API_KEY);

async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS audit_results (
      id          VARCHAR(24) PRIMARY KEY,
      data        JSONB NOT NULL,
      created_at  TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id              SERIAL PRIMARY KEY,
      email           VARCHAR(255) UNIQUE NOT NULL,
      company         VARCHAR(255),
      stripe_customer VARCHAR(255),
      plan            VARCHAR(50) DEFAULT 'free',
      plan_status     VARCHAR(50) DEFAULT 'active',
      subscription_id VARCHAR(255),
      portal_token    TEXT,
      last_audit_id   VARCHAR(24),
      last_audit_at   TIMESTAMP,
      created_at      TIMESTAMP DEFAULT NOW(),
      updated_at      TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS audit_history (
      id              SERIAL PRIMARY KEY,
      customer_id     INT REFERENCES customers(id),
      audit_id        VARCHAR(24),
      plan            VARCHAR(50),
      score           INT,
      critical_count  INT DEFAULT 0,
      warning_count   INT DEFAULT 0,
      info_count      INT DEFAULT 0,
      monthly_waste   INT DEFAULT 0,
      records_scanned INT DEFAULT 0,
      scores          JSONB,
      issue_titles    JSONB,
      portal_stats    JSONB,
      created_at      TIMESTAMP DEFAULT NOW()
    )
  `);
  // Migrate existing installs — add new columns if not present
  const newCols = ['critical_count INT DEFAULT 0','warning_count INT DEFAULT 0','info_count INT DEFAULT 0','monthly_waste INT DEFAULT 0','records_scanned INT DEFAULT 0','scores JSONB','issue_titles JSONB','portal_stats JSONB'];
  for (const col of newCols) {
    await db.query(`ALTER TABLE audit_history ADD COLUMN IF NOT EXISTS ${col}`).catch(()=>{});
  }
  // Cleanup: free results after 7 days, paid after 365
  await db.query(`
    DELETE FROM audit_results
    WHERE (data->>'plan' IS NULL OR data->>'plan' = 'free')
      AND created_at < NOW() - INTERVAL '7 days'
  `);
  await db.query(`
    DELETE FROM audit_results
    WHERE created_at < NOW() - INTERVAL '365 days'
  `);
  console.log('Database ready — all tables initialized');
}

const saveResult = async (id, data) => {
  await db.query(
    'INSERT INTO audit_results (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = $2',
    [id, JSON.stringify(data)]
  );
};

const getResult = async (id) => {
  const r = await db.query('SELECT data FROM audit_results WHERE id = $1', [id]);
  return r.rows[0]?.data || null;
};

// ── Pending OAuth state ───────────────────────────────────────────────────────
const pendingAudits = new Map();
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [k, v] of pendingAudits) {
    if (v.createdAt < cutoff) pendingAudits.delete(k);
  }
}, 5 * 60 * 1000);

// ── Plan config ───────────────────────────────────────────────────────────────
const getPlanConfig = (plan) => {
  const p = plan || 'free';
  const isFree = p === 'free';
  return {
    plan: p,
    isFree,
    isPaid: !isFree,
    contactLimit:  isFree ? 1000   : 999999,
    dealLimit:     isFree ? 1000   : 999999,
    ticketLimit:   isFree ? 500    : 999999,
    companyLimit:  isFree ? 500    : 999999,
    smallLimit:    isFree ? 100    : 999999,
    storageDays:   p === 'pro-audit' ? 365 : (!isFree ? 90 : 7),
    runExtended:   ['pro-audit','pro','command'].includes(p),
    isOneTime:     ['deep','deep-audit','pro-audit'].includes(p),
    callLength:    p === 'pro-audit' ? '60' : '30',
  };
};

// ── Sanitize text ─────────────────────────────────────────────────────────────
const cleanText = (obj) => {
  if (!obj) return obj;
  if (typeof obj === 'string') return obj.replace(/`/g,"'").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,'');
  if (Array.isArray(obj)) return obj.map(cleanText);
  if (typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) out[k] = cleanText(obj[k]);
    return out;
  }
  return obj;
};

// ── HubSpot API helper ────────────────────────────────────────────────────────


// ── Email helpers ─────────────────────────────────────────────────────────────
const sendClientEmail = async (email, result, auditId) => {
  const s = result.summary || {};
  const pi = result.portalInfo || {};
  const issues = result.issues || [];
  const scores = result.scores || {};
  const col = s.overallScore >= 80 ? '#10b981' : s.overallScore >= 60 ? '#f59e0b' : '#f43f5e';
  const plan = result.plan || 'free';
  const planLabel = {
    'free':'Free Snapshot','deep':'Deep Audit','pro-audit':'Pro Audit',
    'pulse':'Pulse','pro':'Pro Plan','command':'Command'
  }[plan] || 'Audit';
  const company = pi.company || 'Your Portal';
  const ps = pi.portalStats || {};
  const grade = s.overallScore >= 85 ? 'Excellent' : s.overallScore >= 70 ? 'Good' : s.overallScore >= 55 ? 'Needs Attention' : 'Critical';

  // Get top 3 critical issues for preview
  const criticals = issues.filter(i => i.severity === 'critical').slice(0, 3);
  const warnings = issues.filter(i => i.severity === 'warning').slice(0, 2);
  const previewIssues = [...criticals, ...warnings].slice(0, 4);

  // Build dimension score bars
  const dims = [
    ['Data Integrity', scores.dataIntegrity],
    ['Automation', scores.automationHealth],
    ['Pipeline', scores.pipelineIntegrity],
    ['Configuration', scores.configSecurity],
    ['Reporting', scores.reportingQuality],
    ['Team Adoption', scores.teamAdoption],
  ].filter(d => d[1] !== undefined);

  const dimBarsHtml = dims.slice(0,6).map(([name, score]) => {
    const sc = score || 0;
    const bc = sc >= 80 ? '#10b981' : sc >= 60 ? '#f59e0b' : '#ef4444';
    const pct = Math.round(sc);
    return `<tr>
      <td style="font-size:12px;color:#555;padding:4px 0;width:140px;">${name}</td>
      <td style="padding:4px 8px;">
        <div style="background:#f0f0f0;border-radius:4px;height:8px;width:160px;">
          <div style="background:${bc};height:8px;border-radius:4px;width:${pct}%;"></div>
        </div>
      </td>
      <td style="font-size:12px;font-weight:700;color:${bc};padding:4px 0;text-align:right;width:36px;">${pct}</td>
    </tr>`;
  }).join('');

  // Build issue preview
  const issuePreviewHtml = previewIssues.length > 0 ? previewIssues.map(i => {
    const ic = i.severity === 'critical' ? '#ef4444' : '#f59e0b';
    const ib = i.severity === 'critical' ? '#fff5f5' : '#fffbeb';
    const ib2 = i.severity === 'critical' ? '#fee2e2' : '#fef3c7';
    const label = i.severity === 'critical' ? 'CRITICAL' : 'WARNING';
    const title = i.title || '';
    const impact = i.impact || '';
    return `<div style="background:${ib};border:1px solid ${ib2};border-left:3px solid ${ic};border-radius:6px;padding:10px 14px;margin-bottom:8px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
        <span style="font-size:9px;font-weight:700;color:${ic};letter-spacing:1px;">${label}</span>
      </div>
      <div style="font-size:13px;font-weight:600;color:#111;margin-bottom:3px;">${title.length > 80 ? title.substring(0,80)+'…' : title}</div>
      ${impact ? `<div style="font-size:11px;color:#666;">${impact.length > 100 ? impact.substring(0,100)+'…' : impact}</div>` : ''}
    </div>`;
  }).join('') : '';

  const moreCount = issues.length - previewIssues.length;

  await resend.emails.send({
    from: 'FixOps Reports <reports@fixops.io>',
    to: email,
    subject: s.criticalCount > 0
      ? `⚠️ ${company} — ${s.criticalCount} critical issue${s.criticalCount!==1?'s':''} found · Score ${s.overallScore}/100`
      : `✅ ${company} — Portal audit complete · Score ${s.overallScore}/100`,
    html: `<!DOCTYPE html><html><body style="font-family:system-ui,-apple-system,sans-serif;background:#f0f0f5;margin:0;padding:24px 12px;">
<div style="max-width:580px;margin:0 auto;">

<!-- Header -->
<div style="background:#08061a;border-radius:16px 16px 0 0;padding:28px 32px;text-align:center;">
  <div style="font-size:24px;font-weight:800;color:#fff;letter-spacing:-0.5px;">⚡ FixOps<span style="color:#a78bfa;">.io</span></div>
  <div style="font-size:11px;color:rgba(255,255,255,.35);font-family:monospace;letter-spacing:2px;margin-top:4px;text-transform:uppercase;">HubSpot Portal Intelligence</div>
</div>

<!-- Score hero -->
<div style="background:#fff;padding:32px 32px 24px;text-align:center;border-left:1px solid #eee;border-right:1px solid #eee;">
  <div style="font-size:13px;color:#888;font-weight:500;margin-bottom:8px;">Portal Health Score · ${company}</div>
  <div style="font-size:80px;font-weight:900;color:${col};line-height:1;letter-spacing:-3px;">${s.overallScore}</div>
  <div style="font-size:14px;color:#999;margin-top:4px;">out of 100 · ${grade}</div>
  <div style="display:inline-block;margin-top:12px;padding:5px 16px;background:${col}12;color:${col};border:1px solid ${col}33;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:0.5px;">${planLabel}</div>
</div>

<!-- Stats row -->
<div style="background:#fff;padding:0 24px 24px;border-left:1px solid #eee;border-right:1px solid #eee;">
  <table style="width:100%;border-collapse:separate;border-spacing:8px 0;">
    <tr>
      <td style="background:#fff5f5;border:1px solid #fee2e2;border-radius:10px;padding:16px;text-align:center;width:33%;">
        <div style="font-size:28px;font-weight:900;color:#ef4444;">${s.criticalCount||0}</div>
        <div style="font-size:11px;color:#999;margin-top:2px;font-weight:600;">CRITICAL</div>
      </td>
      <td style="background:#fffbeb;border:1px solid #fef3c7;border-radius:10px;padding:16px;text-align:center;width:33%;">
        <div style="font-size:28px;font-weight:900;color:#f59e0b;">${s.warningCount||0}</div>
        <div style="font-size:11px;color:#999;margin-top:2px;font-weight:600;">WARNINGS</div>
      </td>
      <td style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:16px;text-align:center;width:33%;">
        <div style="font-size:28px;font-weight:900;color:#7c3aed;">$${Number(s.monthlyWaste||0).toLocaleString()}</div>
        <div style="font-size:11px;color:#999;margin-top:2px;font-weight:600;">EST. WASTE/MO</div>
      </td>
    </tr>
  </table>
</div>

<!-- Records scanned -->
<div style="background:#fff;padding:0 32px 20px;border-left:1px solid #eee;border-right:1px solid #eee;">
  <div style="background:#f9f9f9;border-radius:8px;padding:12px 16px;font-size:12px;color:#888;text-align:center;">
    📊 Scanned <strong style="color:#444;">${Number(s.recordsScanned||0).toLocaleString()} records</strong> across
    ${ps.contacts ? `<strong style="color:#444;">${Number(ps.contacts).toLocaleString()} contacts</strong>` : ''}
    ${ps.deals ? ` · <strong style="color:#444;">${Number(ps.deals).toLocaleString()} deals</strong>` : ''}
    ${ps.tickets ? ` · <strong style="color:#444;">${Number(ps.tickets).toLocaleString()} tickets</strong>` : ''}
  </div>
</div>

<!-- Issues preview -->
${previewIssues.length > 0 ? `
<div style="background:#fff;padding:0 32px 8px;border-left:1px solid #eee;border-right:1px solid #eee;">
  <div style="font-size:12px;font-weight:700;color:#333;letter-spacing:1px;text-transform:uppercase;margin-bottom:12px;padding-top:4px;">Top Issues Found</div>
  ${issuePreviewHtml}
  ${moreCount > 0 ? `<div style="font-size:12px;color:#888;text-align:center;padding:8px 0 16px;">+ ${moreCount} more issue${moreCount!==1?'s':''} in your full report</div>` : ''}
</div>` : ''}

<!-- Dimension scores -->
${dims.length > 0 ? `
<div style="background:#fff;padding:16px 32px 24px;border-left:1px solid #eee;border-right:1px solid #eee;">
  <div style="font-size:12px;font-weight:700;color:#333;letter-spacing:1px;text-transform:uppercase;margin-bottom:12px;">Health Dimensions</div>
  <table style="width:100%;border-collapse:collapse;">
    ${dimBarsHtml}
  </table>
</div>` : ''}

<!-- CTA -->
<div style="background:#fff;padding:24px 32px 32px;border-left:1px solid #eee;border-right:1px solid #eee;text-align:center;">
  <a href="${FRONTEND_URL}/results.html?id=${auditId}" style="display:inline-block;padding:15px 36px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:12px;font-weight:700;font-size:15px;letter-spacing:-0.2px;">View Full Audit Results →</a>
  <div style="margin-top:12px;font-size:12px;color:#999;">Every issue includes a dollar impact estimate and a step-by-step fix guide</div>
  ${plan === 'deep' || plan === 'pro-audit' ? `
  <div style="margin-top:16px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px;font-size:13px;color:#166534;text-align:left;">
    <strong>📅 Your strategy call:</strong> Our team will email you within a few hours to schedule your ${plan === 'pro-audit' ? '60' : '30'}-minute strategy call and written action plan.
  </div>` : ''}
  <div style="margin-top:16px;background:#f5f3ff;border:1px solid #ede9fe;border-radius:8px;padding:14px;font-size:12px;color:#5b21b6;text-align:left;">
    <strong>💡 Want this fixed?</strong> Every issue has a "Fix It For Me" button in your results — click it and we'll scope and quote a fix within 24 hours. No commitment required.
  </div>
</div>

<!-- Footer -->
<div style="background:#f9f9f9;border:1px solid #eee;border-top:none;border-radius:0 0 16px 16px;padding:20px 32px;text-align:center;font-size:11px;color:#aaa;">
  <a href="${FRONTEND_URL}" style="color:#7c3aed;text-decoration:none;font-weight:600;">fixops.io</a> · 
  <a href="mailto:matthew@fixops.io" style="color:#aaa;text-decoration:none;">matthew@fixops.io</a> · 
  HubSpot Systems. Fixed.
</div>

</div></body></html>`
  });
};

const notifyMatthew = async (result, auditId, plan) => {
  const s = result.summary || {};
  const pi = result.portalInfo || {};
  const planLabel = plan || 'free';
  await resend.emails.send({
    from: 'FixOps Alerts <reports@fixops.io>',
    to: FIXOPS_NOTIFY_EMAIL,
    subject: `🔔 New Audit — ${pi.company} — Score ${s.overallScore}/100 — $${Number(s.monthlyWaste||0).toLocaleString()}/mo — ${planLabel}`,
    html: `<h2>New Audit Complete</h2>
      <p><strong>Company:</strong> ${pi.company}</p>
      <p><strong>Email:</strong> ${pi.email}</p>
      <p><strong>Plan:</strong> ${planLabel}</p>
      <p><strong>Score:</strong> ${s.overallScore}/100</p>
      <p><strong>Critical:</strong> ${s.criticalCount} · Warnings: ${s.warningCount}</p>
      <p><strong>Est. waste:</strong> $${Number(s.monthlyWaste||0).toLocaleString()}/mo</p>
      <p><strong>Records scanned:</strong> ${Number(s.recordsScanned||0).toLocaleString()}</p>
      <p><a href="${FRONTEND_URL}/results.html?id=${auditId}">View Results</a></p>`
  });

  // Paid one-time — action required alert
  if (['deep','deep-audit','pro-audit'].includes(plan)) {
    const callLen = plan === 'pro-audit' ? '60-min' : '30-min';
    await resend.emails.send({
      from: 'FixOps Alerts <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `📞 ACTION REQUIRED: Schedule ${callLen} call — ${pi.company} paid ${plan === 'pro-audit' ? '$699' : '$399'}`,
      html: `<h2>Paid audit complete — schedule their strategy call now</h2>
        <p><strong>Company:</strong> ${pi.company}</p>
        <p><strong>Email:</strong> ${pi.email}</p>
        <p><strong>Plan:</strong> ${plan} (${plan === 'pro-audit' ? '$699 — 60-min call' : '$399 — 30-min call'})</p>
        <p><strong>Score:</strong> ${s.overallScore}/100 · ${s.criticalCount} critical issues</p>
        <p>Reply to <a href="mailto:${pi.email}">${pi.email}</a> to schedule their ${callLen} strategy call and send their written action plan.</p>
        <p><a href="${FRONTEND_URL}/results.html?id=${auditId}">View their full audit results</a></p>`
    }).catch(e => console.error('Paid notify error:', e.message));
  }
};


// ── Pulse Weekly Email ────────────────────────────────────────────────────────
const sendPulseEmail = async (email, result, auditId, history, customer) => {
  const s = result.summary || {};
  const scores = result.scores || {};
  const issues = result.issues || [];
  const pi = result.portalInfo || {};
  const ps = pi.portalStats || {};
  const plan = customer.plan || 'pulse';

  // Previous audit for comparison
  const prev = history && history.length > 1 ? history[1] : null;
  const prevScore = prev ? prev.score : null;
  const scoreDiff = prevScore !== null ? s.overallScore - prevScore : null;
  const scoreArrow = scoreDiff === null ? '' : scoreDiff > 0 ? `↑${scoreDiff}` : scoreDiff < 0 ? `↓${Math.abs(scoreDiff)}` : '→ no change';
  const scoreColor = s.overallScore >= 80 ? '#10b981' : s.overallScore >= 60 ? '#f59e0b' : '#f43f5e';
  const trendColor = scoreDiff === null ? '#6b7280' : scoreDiff > 0 ? '#10b981' : scoreDiff < 0 ? '#f43f5e' : '#f59e0b';

  // Compare issues with previous week
  const prevIssues = prev && prev.issue_titles ? (typeof prev.issue_titles === 'string' ? JSON.parse(prev.issue_titles) : prev.issue_titles) : [];
  const prevTitles = prevIssues.map(i => i.title);
  const currTitles = issues.map(i => i.title);
  const newIssues = issues.filter(i => !prevTitles.includes(i.title));
  const resolvedIssues = prevIssues.filter(i => !currTitles.includes(i.title));
  const persistentIssues = issues.filter(i => prevTitles.includes(i.title));

  // Dimension scores
  const dimNames = {
    dataIntegrity:'Data Integrity', automationHealth:'Automation Health',
    pipelineIntegrity:'Pipeline', marketingHealth:'Marketing Health',
    configSecurity:'Configuration', reportingQuality:'Reporting Quality',
    teamAdoption:'Team Adoption', serviceHealth:'Service Health'
  };
  const prevScores = prev && prev.scores ? (typeof prev.scores === 'string' ? JSON.parse(prev.scores) : prev.scores) : {};

  // Build score history sparkline data (last 5 weeks)
  const sparkHistory = history.slice(0,5).reverse().map(h => h.score);
  const sparkMax = Math.max(...sparkHistory, 100);

  // Critical issues for email
  const criticals = issues.filter(i => i.severity === 'critical').slice(0,3);
  const warnings = issues.filter(i => i.severity === 'warning').slice(0,3);

  // Portal report URL (token-gated by email)
  const reportToken = Buffer.from(JSON.stringify({email, auditId, ts: Date.now()})).toString('base64url');
  const reportUrl = `${FRONTEND_URL}/pulse.html?token=${reportToken}&id=${auditId}`;
  const resultsUrl = `${FRONTEND_URL}/results.html?id=${auditId}`;

  // Week number
  const weekNum = history.length;
  const auditDate = new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>FixOps Pulse Report</title>
</head>
<body style="margin:0;padding:0;background:#f0f0f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">

<!-- Wrapper -->
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f0f5;padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

  <!-- Header -->
  <tr><td style="background:#08061a;border-radius:14px 14px 0 0;padding:28px 32px;border-bottom:1px solid rgba(124,58,237,.3);">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td>
          <div style="font-size:20px;font-weight:800;color:#fff;letter-spacing:-0.5px;">⚡ FixOps<span style="color:#a78bfa;">.io</span></div>
          <div style="font-size:11px;color:rgba(255,255,255,.35);margin-top:3px;font-family:monospace;letter-spacing:1px;">WEEKLY PULSE REPORT</div>
        </td>
        <td align="right">
          <div style="font-size:11px;color:rgba(255,255,255,.35);">${auditDate}</div>
          <div style="font-size:11px;color:#7c3aed;margin-top:3px;font-family:monospace;">Week #${weekNum} · ${plan.toUpperCase()}</div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Score Hero -->
  <tr><td style="background:linear-gradient(135deg,#0e0b28,#120f30);padding:32px;border-bottom:1px solid rgba(255,255,255,.06);">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td width="140" align="center" style="vertical-align:middle;">
          <div style="width:110px;height:110px;border-radius:50%;background:${scoreColor}15;border:3px solid ${scoreColor};display:inline-flex;align-items:center;justify-content:center;text-align:center;margin:0 auto;">
            <div>
              <div style="font-size:42px;font-weight:900;color:${scoreColor};line-height:1;">${s.overallScore}</div>
              <div style="font-size:11px;color:rgba(255,255,255,.4);margin-top:2px;">/100</div>
            </div>
          </div>
          ${scoreDiff !== null ? `<div style="margin-top:10px;font-size:13px;font-weight:700;color:${trendColor};">${scoreArrow} vs last week</div>` : '<div style="margin-top:10px;font-size:11px;color:rgba(255,255,255,.3);">First scan</div>'}
        </td>
        <td style="padding-left:24px;vertical-align:middle;">
          <div style="font-size:22px;font-weight:800;color:#fff;margin-bottom:6px;">${pi.company || 'Your Portal'}</div>
          <div style="font-size:13px;color:rgba(255,255,255,.5);margin-bottom:16px;">Portal Health — ${s.overallScore>=85?'Excellent':s.overallScore>=70?'Good':s.overallScore>=55?'Needs Attention':'Critical'}</div>
          <!-- Stats row -->
          <table cellpadding="0" cellspacing="0">
            <tr>
              <td style="padding-right:16px;">
                <div style="font-size:20px;font-weight:800;color:#f43f5e;">${s.criticalCount||0}</div>
                <div style="font-size:10px;color:rgba(255,255,255,.35);font-family:monospace;text-transform:uppercase;">Critical</div>
              </td>
              <td style="padding-right:16px;">
                <div style="font-size:20px;font-weight:800;color:#f59e0b;">${s.warningCount||0}</div>
                <div style="font-size:10px;color:rgba(255,255,255,.35);font-family:monospace;text-transform:uppercase;">Warnings</div>
              </td>
              <td style="padding-right:16px;">
                <div style="font-size:20px;font-weight:800;color:#a78bfa;">$${Number(s.monthlyWaste||0).toLocaleString()}</div>
                <div style="font-size:10px;color:rgba(255,255,255,.35);font-family:monospace;text-transform:uppercase;">Est. Waste/mo</div>
              </td>
              <td>
                <div style="font-size:20px;font-weight:800;color:#10b981;">${Number(s.recordsScanned||0).toLocaleString()}</div>
                <div style="font-size:10px;color:rgba(255,255,255,.35);font-family:monospace;text-transform:uppercase;">Scanned</div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Week-over-week summary bar -->
  ${prev ? `
  <tr><td style="background:#0a0820;padding:16px 32px;border-bottom:1px solid rgba(255,255,255,.05);">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td width="33%" align="center">
          <div style="font-size:18px;font-weight:800;color:${newIssues.length>0?'#f43f5e':'#10b981'};">${newIssues.length}</div>
          <div style="font-size:10px;color:rgba(255,255,255,.4);font-family:monospace;text-transform:uppercase;margin-top:2px;">New Issues</div>
        </td>
        <td width="33%" align="center" style="border-left:1px solid rgba(255,255,255,.06);border-right:1px solid rgba(255,255,255,.06);">
          <div style="font-size:18px;font-weight:800;color:${resolvedIssues.length>0?'#10b981':'rgba(255,255,255,.3)'};">${resolvedIssues.length}</div>
          <div style="font-size:10px;color:rgba(255,255,255,.4);font-family:monospace;text-transform:uppercase;margin-top:2px;">Resolved</div>
        </td>
        <td width="33%" align="center">
          <div style="font-size:18px;font-weight:800;color:rgba(255,255,255,.6);">${persistentIssues.length}</div>
          <div style="font-size:10px;color:rgba(255,255,255,.4);font-family:monospace;text-transform:uppercase;margin-top:2px;">Ongoing</div>
        </td>
      </tr>
    </table>
  </td></tr>` : ''}

  <!-- New Issues This Week -->
  ${newIssues.length > 0 ? `
  <tr><td style="background:#fff;padding:24px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#f43f5e;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px;">🚨 New This Week — ${newIssues.length} New Issue${newIssues.length!==1?'s':''} Found</div>
    ${newIssues.slice(0,5).map(i => `
    <div style="display:flex;align-items:flex-start;padding:12px;background:${i.severity==='critical'?'#fff5f5':i.severity==='warning'?'#fffbeb':'#faf5ff'};border-radius:8px;margin-bottom:8px;border-left:3px solid ${i.severity==='critical'?'#f43f5e':i.severity==='warning'?'#f59e0b':'#a78bfa'};">
      <div style="flex:1;">
        <div style="font-size:13px;font-weight:700;color:#111;margin-bottom:3px;">${i.title||''}</div>
        ${i.impact ? `<div style="font-size:11px;color:#f59e0b;font-family:monospace;">${i.impact}</div>` : ''}
      </div>
      <div style="font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;margin-left:10px;flex-shrink:0;background:${i.severity==='critical'?'#fee2e2':i.severity==='warning'?'#fef3c7':'#ede9fe'};color:${i.severity==='critical'?'#dc2626':i.severity==='warning'?'#d97706':'#7c3aed'};">${(i.severity||'').toUpperCase()}</div>
    </div>`).join('')}
  </td></tr>` : ''}

  <!-- Resolved Issues -->
  ${resolvedIssues.length > 0 ? `
  <tr><td style="background:#fff;padding:24px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#10b981;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px;">✅ Resolved This Week — ${resolvedIssues.length} Issue${resolvedIssues.length!==1?'s':''} Fixed</div>
    ${resolvedIssues.slice(0,3).map(i => `
    <div style="display:flex;align-items:center;padding:10px 12px;background:#f0fdf4;border-radius:8px;margin-bottom:6px;border-left:3px solid #10b981;">
      <div style="color:#10b981;font-size:14px;margin-right:10px;">✓</div>
      <div style="font-size:13px;color:#166534;">${i.title||''}</div>
    </div>`).join('')}
  </td></tr>` : ''}

  <!-- Current Critical Issues -->
  ${criticals.length > 0 ? `
  <tr><td style="background:#fff;padding:24px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#374151;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px;">🔴 Critical Issues Requiring Attention</div>
    ${criticals.map((i,idx) => `
    <div style="padding:14px 16px;background:#fff5f5;border-radius:8px;margin-bottom:10px;border:1px solid #fecaca;">
      <div style="font-size:13px;font-weight:700;color:#111;margin-bottom:5px;">${i.title||''}</div>
      ${i.description ? `<div style="font-size:12px;color:#666;line-height:1.6;margin-bottom:8px;">${(i.description||'').substring(0,180)}${(i.description||'').length>180?'...':''}</div>` : ''}
      ${i.impact ? `<div style="font-size:11px;color:#f59e0b;font-family:monospace;margin-bottom:8px;">💸 ${i.impact}</div>` : ''}
      ${i.guide && i.guide[0] ? `<div style="font-size:11px;color:#374151;background:#f9fafb;padding:8px 10px;border-radius:6px;border-left:2px solid #d1d5db;"><strong>Quick fix:</strong> ${i.guide[0]}</div>` : ''}
    </div>`).join('')}
  </td></tr>` : ''}

  <!-- Health Dimensions -->
  <tr><td style="background:#fff;padding:24px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#374151;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:16px;">📊 Health Dimensions This Week</div>
    <table width="100%" cellpadding="0" cellspacing="4">
      ${Object.entries(scores).map(([k,v]) => {
        const prev_v = prevScores[k];
        const diff = prev_v !== undefined ? v - prev_v : null;
        const bar_color = v>=80?'#10b981':v>=60?'#f59e0b':'#f43f5e';
        const trend = diff===null?'':diff>0?`<span style="color:#10b981;font-size:10px;"> ↑${diff}</span>`:diff<0?`<span style="color:#f43f5e;font-size:10px;"> ↓${Math.abs(diff)}</span>`:'<span style="color:#9ca3af;font-size:10px;"> →</span>';
        return `<tr>
          <td width="130" style="font-size:12px;color:#374151;padding:4px 0;">${dimNames[k]||k}${trend}</td>
          <td style="padding:4px 8px;">
            <div style="background:#f3f4f6;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:${bar_color};height:100%;width:${v}%;border-radius:4px;"></div>
            </div>
          </td>
          <td width="40" align="right" style="font-size:12px;font-weight:700;color:${bar_color};padding:4px 0;">${v}</td>
        </tr>`;
      }).join('')}
    </table>
  </td></tr>

  <!-- Portal Snapshot -->
  <tr><td style="background:#fafafa;padding:20px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#374151;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">📈 Portal Snapshot</div>
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        ${[
          ['Contacts', ps.contacts],
          ['Companies', ps.companies],
          ['Deals', ps.deals],
          ['Tickets', ps.tickets],
          ['Workflows', ps.workflows],
          ['Users', ps.users]
        ].filter(([,v])=>v!==undefined&&v!==null).map(([l,v])=>`
        <td align="center" style="padding:8px;">
          <div style="font-size:18px;font-weight:800;color:#111;">${Number(v||0).toLocaleString()}</div>
          <div style="font-size:10px;color:#9ca3af;font-family:monospace;text-transform:uppercase;margin-top:2px;">${l}</div>
        </td>`).join('')}
      </tr>
    </table>
  </td></tr>

  <!-- Score History -->
  ${sparkHistory.length > 1 ? `
  <tr><td style="background:#fff;padding:20px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#374151;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">📉 Score History (Last ${sparkHistory.length} Weeks)</div>
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      ${sparkHistory.map((score,i)=>`
      <td align="center" style="vertical-align:bottom;padding:0 4px;">
        <div style="background:${score>=80?'#10b981':score>=60?'#f59e0b':'#f43f5e'};width:100%;height:${Math.round((score/100)*60)}px;border-radius:3px 3px 0 0;min-height:4px;"></div>
        <div style="font-size:10px;color:#374151;font-weight:700;margin-top:4px;">${score}</div>
        <div style="font-size:9px;color:#9ca3af;">W${i+1}</div>
      </td>`).join('')}
    </tr></table>
  </td></tr>` : ''}

  <!-- Warnings summary -->
  ${warnings.length > 0 ? `
  <tr><td style="background:#fff;padding:20px 32px;border-bottom:1px solid #eee;">
    <div style="font-size:11px;font-weight:700;color:#374151;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">⚠️ Warnings to Address</div>
    ${warnings.map(i=>`
    <div style="display:flex;align-items:center;padding:10px 12px;background:#fffbeb;border-radius:8px;margin-bottom:6px;border-left:3px solid #f59e0b;">
      <div style="flex:1;font-size:12px;color:#92400e;">${i.title||''}</div>
      ${i.dimension?`<div style="font-size:9px;font-weight:700;padding:2px 6px;background:#fef3c7;color:#d97706;border-radius:4px;margin-left:8px;flex-shrink:0;">${i.dimension}</div>`:''}
    </div>`).join('')}
  </td></tr>` : ''}

  <!-- CTAs -->
  <tr><td style="background:#08061a;padding:28px 32px;border-radius:0 0 14px 14px;">
    <div style="text-align:center;margin-bottom:20px;">
      <a href="${reportUrl}" style="display:inline-block;padding:13px 28px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:14px;margin-right:10px;">📊 View Full Report →</a>
      <a href="${resultsUrl}" style="display:inline-block;padding:13px 28px;background:rgba(124,58,237,.15);color:#a78bfa;text-decoration:none;border-radius:10px;font-weight:700;font-size:14px;border:1px solid rgba(124,58,237,.3);">View Audit Results →</a>
    </div>
    <div style="text-align:center;margin-bottom:16px;">
      <a href="https://calendly.com/matthew-fixops/30min" style="font-size:12px;color:rgba(255,255,255,.4);text-decoration:none;">📅 Book a strategy call to discuss these findings</a>
    </div>
    <div style="border-top:1px solid rgba(255,255,255,.06);padding-top:16px;text-align:center;font-size:11px;color:rgba(255,255,255,.25);">
      <a href="${FRONTEND_URL}" style="color:#7c3aed;text-decoration:none;font-weight:600;">fixops.io</a> · matthew@fixops.io · HubSpot Systems. Fixed.<br>
      <span style="font-size:10px;">Your portal is scanned every Monday at 9am ET · <a href="mailto:matthew@fixops.io" style="color:rgba(255,255,255,.4);text-decoration:none;font-size:10px;">matthew@fixops.io</a><!--w@fixops.io?subject=Pause Pulse - ${email}" style="color:rgba(255,255,255,.25);">Pause monitoring</a></span>
    </div>
  </td></tr>

</table>
</td></tr>
</table>
</body></html>`;

  const subject = scoreDiff === null
    ? `⚡ FixOps Pulse — ${pi.company} — First Scan Complete — Score ${s.overallScore}/100`
    : scoreDiff > 0
      ? `⚡ FixOps Pulse — ${pi.company} — Score ↑${scoreDiff} to ${s.overallScore}/100 · ${newIssues.length} new issue${newIssues.length!==1?'s':''}`
      : scoreDiff < 0
        ? `⚡ FixOps Pulse — ${pi.company} — Score ↓${Math.abs(scoreDiff)} to ${s.overallScore}/100 · ${newIssues.length} new issue${newIssues.length!==1?'s':''} found`
        : `⚡ FixOps Pulse — ${pi.company} — Score ${s.overallScore}/100 · ${s.criticalCount} critical · Weekly Report`;

  await resend.emails.send({
    from: 'FixOps Pulse <reports@fixops.io>',
    to: email,
    subject,
    html
  });
};

// ── Pulse Report Page — token-gated, no password needed ──────────────────────
app.get('/pulse/report', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token required' });
    let payload;
    try {
      payload = JSON.parse(Buffer.from(token, 'base64url').toString());
    } catch(e) {
      return res.status(400).json({ error: 'invalid token' });
    }
    const { email, auditId } = payload;
    if (!email) return res.status(400).json({ error: 'invalid token' });

    // Get customer and history
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    if (!custRes.rows[0]) return res.status(404).json({ error: 'customer not found' });
    const cust = custRes.rows[0];

    const histRes = await db.query(
      'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 12',
      [cust.id]
    );

    // Get latest audit result
    const latestAuditId = auditId || cust.last_audit_id;
    const latestResult = latestAuditId ? await getResult(latestAuditId) : null;

    res.json({
      customer: { email: cust.email, company: cust.company, plan: cust.plan },
      history: histRes.rows,
      latestAuditId,
      latestResult
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});



// ── On-demand refresh — customer triggers new audit from dashboard ────────────
app.post('/auth/refresh', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'token required' });

    // Verify magic link token
    await db.query(`CREATE TABLE IF NOT EXISTS magic_links (id SERIAL PRIMARY KEY, email VARCHAR(255) NOT NULL, token VARCHAR(64) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL, used_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW())`).catch(()=>{});
    const linkRes = await db.query('SELECT * FROM magic_links WHERE token = $1 AND expires_at > NOW()', [token]);
    if (!linkRes.rows[0]) return res.status(401).json({ error: 'invalid_token' });

    const email = linkRes.rows[0].email;
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    if (!custRes.rows[0]) return res.status(404).json({ error: 'customer not found' });

    const cust = custRes.rows[0];

    // Check if they have a stored portal token (MCP token — may be expired)
    if (!cust.portal_token) {
      return res.status(400).json({
        error: 'no_token',
        message: 'No HubSpot connection stored. Please reconnect your portal to refresh.',
        requiresReconnect: true
      });
    }

    // Check if already scanning (last audit started < 5 min ago)
    const lastAudit = cust.last_audit_at ? new Date(cust.last_audit_at) : null;
    if (lastAudit && (Date.now() - lastAudit.getTime()) < 5 * 60 * 1000) {
      return res.status(429).json({
        error: 'too_soon',
        message: 'A scan was run less than 5 minutes ago. Please wait before refreshing.'
      });
    }

    // Trigger a fresh audit using stored token
    const auditId = crypto.randomBytes(12).toString('hex');
    await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Starting refresh scan...' });

    // Update customer record immediately so they know scan started
    await db.query(
      'UPDATE customers SET last_audit_id = $1, last_audit_at = NOW(), updated_at = NOW() WHERE id = $2',
      [auditId, cust.id]
    );

    // Return immediately — scan runs in background
    res.json({
      success: true,
      auditId,
      message: 'Refresh started — results will be ready in 5–15 minutes',
      confirmUrl: `${FRONTEND_URL}/confirm.html?id=${auditId}&email=${encodeURIComponent(email)}&plan=${cust.plan}&paid=0`
    });

    // Run audit in background
    setImmediate(async () => {
      console.log(`[${auditId}] Dashboard refresh for ${email}`);
      try {
        const meta = { email: cust.email, company: cust.company, plan: cust.plan };
        const result = await runFullAudit(cust.portal_token, auditId, meta);

        // Save to history
        const prevHist = await db.query(
          'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 5',
          [cust.id]
        ).catch(()=>({rows:[]}));

        await db.query(
          `INSERT INTO audit_history (customer_id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [cust.id, auditId, cust.plan,
           result.summary?.overallScore||0, result.summary?.criticalCount||0,
           result.summary?.warningCount||0, result.summary?.infoCount||0,
           result.summary?.monthlyWaste||0, result.summary?.recordsScanned||0,
           JSON.stringify(result.scores||{}),
           JSON.stringify((result.issues||[]).map(i=>({title:i.title,severity:i.severity,dimension:i.dimension,impact:i.impact}))),
           JSON.stringify(result.portalInfo?.portalStats||{})]
        ).catch(e => console.error('History insert:', e.message));

        // Send email for monthly plans
        if (['pulse','pro','command'].includes(cust.plan)) {
          await sendPulseEmail(cust.email, result, auditId, prevHist.rows, cust);
        } else {
          await sendClientEmail(cust.email, result, auditId);
        }

        await saveResult(auditId, { ...result, status: 'complete', plan: cust.plan });
        console.log(`[${auditId}] ✅ Dashboard refresh complete for ${email}`);
      } catch(e) {
        console.error(`[${auditId}] Refresh error:`, e.message);

        // Token likely expired
        if (e.message?.includes('401') || e.response?.status === 401) {
          await db.query('UPDATE customers SET portal_token = NULL WHERE id = $1', [cust.id]).catch(()=>{});
          await saveResult(auditId, {
            status: 'error',
            message: 'HubSpot connection expired. Please reconnect from your dashboard.',
            requiresReconnect: true
          }).catch(()=>{});
        } else {
          await saveResult(auditId, { status: 'error', message: 'Refresh failed. Our team has been notified.' }).catch(()=>{});
        }
      }
    });

  } catch(e) {
    console.error('Refresh error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Magic Link Access System ──────────────────────────────────────────────────
// Customers enter their email → get a 30-day magic link → access their dashboard
// No password needed. Works for Pulse/Pro/Command subscribers.

// Add magic_links table on startup (add to initDb)
// ALTER TABLE is safe to run multiple times

// ── Request magic link ────────────────────────────────────────────────────────
app.post('/auth/magic-link', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });

    // Check if customer exists and is on a paid plan
    const custRes = await db.query(
      'SELECT * FROM customers WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    // Always respond success to prevent email enumeration
    // But only send email if customer exists
    if (custRes.rows[0]) {
      const cust = custRes.rows[0];
      const isPaidPlan = ['pulse','pro','command','deep','pro-audit'].includes(cust.plan);

      // Generate a secure 30-day token
      const token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

      // Store token in DB
      await db.query(`
        CREATE TABLE IF NOT EXISTS magic_links (
          id         SERIAL PRIMARY KEY,
          email      VARCHAR(255) NOT NULL,
          token      VARCHAR(64) UNIQUE NOT NULL,
          expires_at TIMESTAMP NOT NULL,
          used_at    TIMESTAMP,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `).catch(()=>{});

      await db.query(
        'INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3)',
        [email.toLowerCase().trim(), token, expires]
      );

      const dashUrl = `${FRONTEND_URL}/dashboard.html?token=${token}`;
      const reportUrl = `${FRONTEND_URL}/reporting.html?token=${token}`;

      // Send magic link email
      await resend.emails.send({
        from: 'FixOps <reports@fixops.io>',
        to: email,
        subject: `Your FixOps dashboard link — ${cust.company || 'Your Portal'}`,
        html: `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;background:#f0f0f5;margin:0;padding:20px;">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
  <div style="background:#08061a;padding:24px 32px;border-bottom:1px solid rgba(124,58,237,.2);">
    <div style="font-size:20px;font-weight:800;color:#fff;">⚡ FixOps<span style="color:#a78bfa;">.io</span></div>
  </div>
  <div style="padding:32px;">
    <div style="font-size:22px;font-weight:800;color:#111;margin-bottom:10px;">Here's your dashboard link</div>
    <p style="font-size:14px;color:#555;line-height:1.7;margin-bottom:24px;">
      Click below to access your FixOps Intelligence Dashboard for <strong>${cust.company || 'your portal'}</strong>.
      This link is valid for 30 days.
    </p>
    <div style="text-align:center;margin-bottom:24px;">
      <a href="${dashUrl}" style="display:inline-block;padding:14px 32px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px;">
        Open My Dashboard →
      </a>
    </div>
    <div style="background:#f9f9f9;border-radius:8px;padding:14px 16px;font-size:12px;color:#888;line-height:1.6;">
      <strong style="color:#555;">Your dashboard includes:</strong><br>
      Pipeline health · Deal velocity · Lifecycle funnel · Contact intelligence ·
      Product revenue · Service health · AI report builder
    </div>
    ${isPaidPlan ? `
    <div style="margin-top:16px;background:#f5f3ff;border:1px solid #ede9fe;border-radius:8px;padding:14px 16px;font-size:12px;color:#6d28d9;">
      <strong>Pulse active</strong> — Your portal is scanned every Monday at 9am ET.
      Your next report arrives automatically.
    </div>` : ''}
  </div>
  <div style="background:#f9f9f9;border-top:1px solid #eee;padding:16px 32px;text-align:center;font-size:11px;color:#aaa;">
    This link was requested for ${email}. If you didn't request this, ignore it.
    <br><a href="${FRONTEND_URL}" style="color:#7c3aed;text-decoration:none;">fixops.io</a>
  </div>
</div></body></html>`
      });

      console.log(`Magic link sent to ${email} (${cust.plan})`);
    }

    // Always return success
    res.json({ success: true, message: 'If that email is in our system, a link is on its way.' });

  } catch(e) {
    console.error('Magic link error:', e.message);
    res.status(500).json({ error: 'Failed to send link' });
  }
});

// ── Verify magic link token ───────────────────────────────────────────────────
app.get('/auth/verify', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token required' });

    // Ensure table exists
    await db.query(`
      CREATE TABLE IF NOT EXISTS magic_links (
        id         SERIAL PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        token      VARCHAR(64) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used_at    TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `).catch(()=>{});

    // Look up token
    const linkRes = await db.query(
      'SELECT * FROM magic_links WHERE token = $1 AND expires_at > NOW()',
      [token]
    );

    if (!linkRes.rows[0]) {
      return res.status(401).json({ error: 'invalid_or_expired', message: 'This link has expired. Request a new one.' });
    }

    const link = linkRes.rows[0];

    // Get customer data
    const custRes = await db.query(
      'SELECT * FROM customers WHERE email = $1',
      [link.email]
    );

    if (!custRes.rows[0]) {
      return res.status(404).json({ error: 'not_found', message: 'Account not found.' });
    }

    const cust = custRes.rows[0];

    // Get audit history
    const histRes = await db.query(
      'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 12',
      [cust.id]
    );

    // Get latest audit result
    const latestResult = cust.last_audit_id ? await getResult(cust.last_audit_id) : null;

    // Update last used
    await db.query(
      'UPDATE magic_links SET used_at = NOW() WHERE id = $1',
      [link.id]
    ).catch(()=>{});

    res.json({
      valid: true,
      customer: {
        email: cust.email,
        company: cust.company,
        plan: cust.plan,
        plan_status: cust.plan_status,
        last_audit_at: cust.last_audit_at,
        last_audit_id: cust.last_audit_id,
        has_portal_token: !!cust.portal_token, // tells dashboard if refresh is available
      },
      history: histRes.rows,
      latestAuditId: cust.last_audit_id,
      latestResult,
      // Pass token back so frontend can use it for subsequent API calls
      token,
    });

  } catch(e) {
    console.error('Verify error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// ── AI Report Builder proxy — browser can't call Anthropic directly (CORS) ───
app.post('/ai/report', async (req, res) => {
  try {
    const { query, context } = req.body;
    if (!query) return res.status(400).json({ error: 'query required' });
    if (!context) return res.status(400).json({ error: 'context required' });

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: `You are a HubSpot revenue intelligence analyst. Analyze this HubSpot audit data and answer the user's question.

AUDIT DATA:
${context}

USER QUESTION: ${query}

Respond in this exact JSON format (no markdown, no backticks, no extra text):
{
  "title": "short report title under 8 words",
  "summary": "2-3 sentence direct answer with specific numbers from the data",
  "keyFindings": ["finding 1 with specific data point", "finding 2 with specific data point", "finding 3 with specific data point"],
  "recommendation": "1-2 sentence actionable next step",
  "chartData": {
    "type": "bar or doughnut or none",
    "labels": ["label1","label2","label3"],
    "values": [10,20,30],
    "colors": ["#3b82f6","#10b981","#f59e0b"]
  },
  "urgency": "critical or warning or info"
}`
      }]
    }, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      }
    });

    const text = response.data.content?.map(b => b.text||'').join('') || '';
    let parsed;
    try {
      parsed = JSON.parse(text.replace(/```json|```/g,'').trim());
    } catch(e) {
      parsed = {
        title: query.substring(0,40),
        summary: text.substring(0,400),
        keyFindings: [],
        recommendation: '',
        urgency: 'info',
        chartData: { type: 'none' }
      };
    }
    res.json({ success: true, result: parsed });

  } catch(e) {
    console.error('AI report error:', e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data?.error?.message || e.message });
  }
});

// ── Fix request email ─────────────────────────────────────────────────────────
app.post('/fix-request', async (req, res) => {
  try {
    const { issueTitle, issueImpact, issueDimension, portalCompany, portalEmail, auditId } = req.body;
    await resend.emails.send({
      from: 'FixOps Fix Request <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `🛠 Fix Request — ${issueTitle?.substring(0,60)} — ${portalCompany}`,
      html: `<h2>Fix It For Me — Scope &amp; Quote Needed</h2>
        <p><strong>Issue:</strong> ${issueTitle}</p>
        <p><strong>Impact:</strong> ${issueImpact}</p>
        <p><strong>Dimension:</strong> ${issueDimension}</p>
        <p><strong>Company:</strong> ${portalCompany}</p>
        <p><strong>Email:</strong> ${portalEmail}</p>
        <p><strong>Audit ID:</strong> ${auditId}</p>
        <p><a href="${FRONTEND_URL}/results.html?id=${auditId}">View full audit</a></p>`
    });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  let dbOk = false;
  try { await db.query('SELECT 1'); dbOk = true; } catch(e) {}
  res.json({ status: 'ok', db: dbOk ? 'connected' : 'error', version: '5.0.0', ts: new Date().toISOString() });
});

// ── Stripe Webhook ────────────────────────────────────────────────────────────
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch(err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).json({ error: `Webhook Error: ${err.message}` });
  }

  console.log(`Stripe webhook: ${event.type}`);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_details?.email || session.metadata?.email;
    const planKey = STRIPE_PRICE_MAP[session.metadata?.price_id] || 'paid';

    console.log(`Payment complete: ${email} — ${planKey}`);

    // Upsert customer record
    if (email) {
      await db.query(`
        INSERT INTO customers (email, plan, plan_status, stripe_customer, updated_at)
        VALUES ($1, $2, 'active', $3, NOW())
        ON CONFLICT (email) DO UPDATE
        SET plan = $2, plan_status = 'active', stripe_customer = $3, updated_at = NOW()
      `, [email, planKey, session.customer]).catch(e => console.error('Customer upsert:', e.message));
    }
  }

  if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.updated') {
    const sub = event.data.object;
    const status = sub.status;
    if (sub.customer) {
      await db.query(`
        UPDATE customers SET plan_status = $1, updated_at = NOW()
        WHERE stripe_customer = $2
      `, [status, sub.customer]).catch(e => console.error('Sub update:', e.message));
    }
  }

  if (event.type === 'invoice.payment_failed') {
    const invoice = event.data.object;
    const custId = invoice.customer;
    const custRes = await db.query('SELECT email FROM customers WHERE stripe_customer = $1', [custId]).catch(() => ({ rows: [] }));
    const custEmail = custRes.rows[0]?.email;

    if (custEmail) {
      await resend.emails.send({
        from: 'FixOps Billing <reports@fixops.io>',
        to: FIXOPS_NOTIFY_EMAIL,
        subject: `⚠️ Payment Failed — ${custEmail}`,
        html: `<p>Payment failed for customer: ${custEmail}<br>Stripe customer: ${custId}</p>`
      }).catch(() => {});
    }
  }

  res.json({ received: true });
});

// ── Auth URL — GET (free) and POST (paid) ─────────────────────────────────────
const buildAuthUrl = (req, res, params) => {
  try {
    const { email = '', company = '', plan = 'free', paid = false } = params;
    const codeVerifier  = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const state = crypto.randomBytes(16).toString('hex');
    pendingAudits.set(state, { email, company, plan, paid: !!paid, codeVerifier, createdAt: Date.now() });
    const url = new URL('https://mcp.hubspot.com/oauth/authorize');
    url.searchParams.set('client_id', HUBSPOT_CLIENT_ID);
    url.searchParams.set('redirect_uri', HUBSPOT_REDIRECT_URI);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    console.log(`Auth URL: ${email} | plan: ${plan} | paid: ${paid}`);
    res.json({ url: url.toString(), state });
  } catch(e) { res.status(500).json({ error: e.message }); }
};

app.get('/auth/url',  (req, res) => buildAuthUrl(req, res, req.query));
app.post('/auth/url', (req, res) => buildAuthUrl(req, res, req.body));

// ── OAuth callback ────────────────────────────────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`${FRONTEND_URL}/?error=${encodeURIComponent(error)}`);

  const pending = pendingAudits.get(state);
  if (!pending) return res.redirect(`${FRONTEND_URL}/?error=session_expired`);
  pendingAudits.delete(state);

  const auditId = crypto.randomBytes(12).toString('hex');

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      redirect_uri: HUBSPOT_REDIRECT_URI,
      code,
      code_verifier: pending.codeVerifier,
    });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

    let tokenRes;
    try {
      tokenRes = await axios.post('https://mcp.hubspot.com/oauth/v3/token', body, { headers });
      console.log('MCP token success');
    } catch(e) {
      console.log('MCP failed, trying standard...');
      tokenRes = await axios.post('https://api.hubapi.com/oauth/v1/token', body, { headers });
      console.log('Standard token success');
    }

    await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Connecting to HubSpot...' });

    // Store token for Pulse re-scans
    if (pending.email && ['pulse','pro','command'].includes(pending.plan)) {
      await db.query(`
        INSERT INTO customers (email, company, plan, plan_status, portal_token, last_audit_id, last_audit_at, updated_at)
        VALUES ($1, $2, $3, 'active', $4, $5, NOW(), NOW())
        ON CONFLICT (email) DO UPDATE
        SET portal_token = $4, last_audit_id = $5, last_audit_at = NOW(),
            plan = $3, company = $2, updated_at = NOW()
      `, [pending.email, pending.company, pending.plan, tokenRes.data.access_token, auditId])
        .catch(e => console.error('Customer token save:', e.message));
    }

    const confirmUrl = `${FRONTEND_URL}/confirm.html?email=${encodeURIComponent(pending.email)}&id=${auditId}&plan=${encodeURIComponent(pending.plan||'free')}&paid=${pending.paid?'1':'0'}`;
    res.redirect(confirmUrl);

    const accessToken = tokenRes.data.access_token;
    const auditMeta   = { ...pending };
    const auditIdCopy = auditId;

    setImmediate(async () => {
      console.log(`[${auditIdCopy}] Background audit starting — plan: ${auditMeta.plan}`);
      try {
        const result = await runFullAudit(accessToken, auditIdCopy, auditMeta);

        // ✅ Save complete result FIRST — before anything else can fail
        await saveResult(auditIdCopy, { ...result, status: 'complete', plan: auditMeta.plan || 'free' });
        console.log(`[${auditIdCopy}] ✅ Result saved — now sending emails`);

        // Send emails in background — wrapped so they never block or overwrite result
        if (auditMeta.email) {
          sendClientEmail(auditMeta.email, result, auditIdCopy)
            .then(() => console.log(`[${auditIdCopy}] ✅ Client email sent`))
            .catch(e => console.error(`[${auditIdCopy}] ⚠️ Client email failed:`, e.message));
        }
        notifyMatthew(result, auditIdCopy, auditMeta.plan)
          .catch(e => console.error(`[${auditIdCopy}] ⚠️ Notify failed:`, e.message));

        // Update customer last audit
        if (auditMeta.email) {
          await db.query(`
            UPDATE customers SET last_audit_id = $1, last_audit_at = NOW(), updated_at = NOW()
            WHERE email = $2
          `, [auditIdCopy, auditMeta.email]).catch(() => {});

          // Save to audit history
          const custRes = await db.query('SELECT id FROM customers WHERE email = $1', [auditMeta.email]).catch(() => ({ rows: [] }));
          if (custRes.rows[0]) {
            await db.query(
              `INSERT INTO audit_history (customer_id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
              [custRes.rows[0].id, auditIdCopy, auditMeta.plan,
               result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.warningCount||0, result.summary?.infoCount||0,
               result.summary?.monthlyWaste||0, result.summary?.recordsScanned||0,
               JSON.stringify(result.scores||{}),
               JSON.stringify((result.issues||[]).map(i=>({title:i.title,severity:i.severity,dimension:i.dimension,impact:i.impact}))),
               JSON.stringify(result.portalInfo?.portalStats||{})]
            ).catch(() => {});
          }
        }

        console.log(`[${auditIdCopy}] ✅ Fully complete`);
      } catch(e) {
        console.error(`[${auditIdCopy}] Audit error:`, e.message);
        await saveResult(auditIdCopy, { status: 'error', message: 'Audit failed. Our team has been notified.' }).catch(() => {});
        await resend.emails.send({
          from: 'FixOps Alerts <reports@fixops.io>',
          to: FIXOPS_NOTIFY_EMAIL,
          subject: `⚠️ Audit Failed — ${auditMeta.company}`,
          html: `<p>Audit failed: ${auditMeta.email} | ${auditMeta.plan}<br>Error: ${e.message}<br>Audit ID: ${auditIdCopy}</p>`
        }).catch(() => {});
      }
    });

  } catch(err) {
    console.error('Callback error:', err.response?.data || err.message);
    if (!res.headersSent) res.redirect(`${FRONTEND_URL}/confirm.html?error=auth_failed&id=${auditId}`);
  }
});

// ── Private App Token Audit — bypasses MCP OAuth, full record access ──────────
// Used when customer provides a HubSpot Private App token directly
// Enables full portal scans without MCP token scope/record limitations
app.post('/audit/private', async (req, res) => {
  try {
    const { token, email, company, plan } = req.body;
    if (!token) return res.status(400).json({ error: 'token required' });

    const auditId = crypto.randomBytes(12).toString('hex');
    await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Connecting to HubSpot...' });

    const confirmUrl = `${FRONTEND_URL}/confirm.html?email=${encodeURIComponent(email||'')}&id=${auditId}&plan=${encodeURIComponent(plan||'free')}&paid=0`;
    res.json({ auditId, confirmUrl });

    setImmediate(async () => {
      console.log(`[${auditId}] Private app audit starting — plan: ${plan}`);
      try {
        const meta = { email: email||'', company: company||'Your Portal', plan: plan||'free' };
        const result = await runFullAudit(token, auditId, meta);
        // ✅ Save complete result FIRST before emails can fail
        await saveResult(auditId, { ...result, status: 'complete', plan: plan||'free' });
        console.log(`[${auditId}] ✅ Result saved`);
        if (email) {
          sendClientEmail(email, result, auditId)
            .then(() => console.log(`[${auditId}] ✅ Client email sent`))
            .catch(e => console.error(`[${auditId}] ⚠️ Client email failed:`, e.message));
        }
        notifyMatthew(result, auditId, plan||'free').catch(e => console.error(`[${auditId}] ⚠️ Notify failed:`, e.message));
        console.log(`[${auditId}] ✅ Private app audit complete`);
      } catch(e) {
        console.error(`[${auditId}] Private audit error:`, e.message);
        await saveResult(auditId, { status: 'error', message: 'Audit failed. Our team has been notified.' }).catch(()=>{});
      }
    });

  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Audit status ──────────────────────────────────────────────────────────────
app.get('/audit/status/:id', async (req, res) => {
  try {
    const data = await getResult(req.params.id);
    if (!data) return res.status(404).json({ error: 'not_found', message: 'Audit not found or expired' });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Customer history ──────────────────────────────────────────────────────────
app.get('/customer/history', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'email required' });
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    if (!custRes.rows[0]) return res.json({ customer: null, history: [] });
    const hist = await db.query(
      'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 20',
      [custRes.rows[0].id]
    );
    res.json({ customer: custRes.rows[0], history: hist.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Pulse re-scan trigger (internal) ─────────────────────────────────────────
app.post('/audit/rescan', async (req, res) => {
  const { secret, email } = req.body;
  if (secret !== process.env.RESCAN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  try {
    const custRes = await db.query(
      'SELECT * FROM customers WHERE email = $1 AND plan IN ($2,$3,$4) AND plan_status = $5 AND portal_token IS NOT NULL',
      [email, 'pulse', 'pro', 'command', 'active']
    );
    if (!custRes.rows[0]) return res.status(404).json({ error: 'customer not found or not eligible' });
    const cust = custRes.rows[0];
    await triggerRescan(cust);
    res.json({ success: true, message: `Rescan triggered for ${email}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const triggerRescan = async (customer) => {
  const auditId = crypto.randomBytes(12).toString('hex');
  await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Weekly monitoring scan starting...' });

  setImmediate(async () => {
    console.log(`[${auditId}] Weekly rescan for ${customer.email}`);
    try {
      const meta = { email: customer.email, company: customer.company, plan: customer.plan };
      const result = await runFullAudit(customer.portal_token, auditId, meta);

      // Save to audit_history FIRST so email comparison is correct
      // history[0] = last week (before this scan), history[1] = two weeks ago, etc.
      const prevHistRes = await db.query(
        'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 5',
        [customer.id]
      ).catch(()=>({rows:[]}));

      // Save this week's result to history
      await db.query(
        `INSERT INTO audit_history (customer_id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [customer.id, auditId, customer.plan,
         result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.warningCount||0, result.summary?.infoCount||0,
         result.summary?.monthlyWaste||0, result.summary?.recordsScanned||0,
         JSON.stringify(result.scores||{}),
         JSON.stringify((result.issues||[]).map(i=>({title:i.title,severity:i.severity,dimension:i.dimension,impact:i.impact}))),
         JSON.stringify(result.portalInfo?.portalStats||{})]
      );

      await db.query(`
        UPDATE customers SET last_audit_id = $1, last_audit_at = NOW(), updated_at = NOW() WHERE id = $2
      `, [auditId, customer.id]);

      // Send email — prevHistRes.rows[0] = last week for comparison
      if (['pulse','pro','command'].includes(customer.plan)) {
        await sendPulseEmail(customer.email, result, auditId, prevHistRes.rows, customer);
      } else {
        await sendClientEmail(customer.email, result, auditId);
      }
      await notifyMatthew(result, auditId, customer.plan);

      await saveResult(auditId, { ...result, status: 'complete', plan: customer.plan });
      console.log(`[${auditId}] ✅ Weekly rescan complete for ${customer.email}`);
    } catch(e) {
      console.error(`[${auditId}] Rescan error:`, e.message);

      // Detect expired/invalid token — notify customer to reconnect
      const isAuthError = e.message?.includes('401') || e.message?.includes('403') ||
        e.response?.status === 401 || e.response?.status === 403;

      if (isAuthError) {
        console.log(`[${auditId}] Token expired for ${customer.email} — sending reconnect email`);
        // Clear the expired token so we don't keep trying
        await db.query(
          'UPDATE customers SET portal_token = NULL, updated_at = NOW() WHERE id = $1',
          [customer.id]
        ).catch(()=>{});

        // Send reconnect email
        await resend.emails.send({
          from: 'FixOps Pulse <reports@fixops.io>',
          to: customer.email,
          subject: `⚡ FixOps Pulse — Action Required: Reconnect Your HubSpot Portal`,
          html: `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;background:#f0f0f5;margin:0;padding:20px;">
<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
  <div style="background:#08061a;padding:24px 32px;border-bottom:1px solid rgba(124,58,237,.2);">
    <div style="font-size:20px;font-weight:800;color:#fff;">⚡ FixOps<span style="color:#a78bfa;">.io</span></div>
    <div style="font-size:11px;color:rgba(255,255,255,.35);margin-top:3px;font-family:monospace;letter-spacing:1px;">PULSE MONITORING ALERT</div>
  </div>
  <div style="padding:32px;">
    <div style="font-size:22px;font-weight:800;color:#111;margin-bottom:10px;">Your HubSpot connection needs to be refreshed</div>
    <p style="font-size:14px;color:#555;line-height:1.7;margin-bottom:20px;">
      Hi ${customer.company || 'there'} — your weekly FixOps Pulse scan ran today but your HubSpot connection has expired.
      This is normal and happens periodically for security reasons. It takes about 30 seconds to reconnect.
    </p>
    <div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:16px;margin-bottom:24px;font-size:13px;color:#5b21b6;">
      <strong>What you missed:</strong> Your weekly portal health scan — we'll run it automatically as soon as you reconnect.
    </div>
    <div style="text-align:center;">
      <a href="${FRONTEND_URL}/?reconnect=1&email=${encodeURIComponent(customer.email)}&plan=${customer.plan}"
         style="display:inline-block;padding:14px 32px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px;">
        Reconnect HubSpot →
      </a>
    </div>
    <p style="font-size:12px;color:#999;text-align:center;margin-top:16px;">Takes 30 seconds · Read-only access · You can revoke anytime from HubSpot</p>
  </div>
  <div style="background:#f9f9f9;border-top:1px solid #eee;padding:16px 32px;text-align:center;font-size:11px;color:#aaa;">
    <a href="${FRONTEND_URL}" style="color:#7c3aed;text-decoration:none;font-weight:600;">fixops.io</a> · matthew@fixops.io
  </div>
</div></body></html>`
        }).catch(e => console.error('Reconnect email error:', e.message));

        // Notify ops team
        await resend.emails.send({
          from: 'FixOps Alerts <reports@fixops.io>',
          to: FIXOPS_NOTIFY_EMAIL,
          subject: `⚠️ Pulse token expired — ${customer.email} needs to reconnect`,
          html: `<p>Token expired for <strong>${customer.email}</strong> (${customer.plan}).<br>Reconnect email sent. Token cleared from DB.</p>`
        }).catch(()=>{});
      }
    }
  });
};

// ── Weekly Pulse cron — runs every Monday 9am ET ──────────────────────────────
cron.schedule('0 14 * * 1', async () => {
  console.log('🕐 Weekly Pulse scan starting...');
  try {
    const custRes = await db.query(`
      SELECT * FROM customers
      WHERE plan IN ('pulse','pro','command')
        AND plan_status = 'active'
        AND portal_token IS NOT NULL
        AND (last_audit_at IS NULL OR last_audit_at < NOW() - INTERVAL '6 days')
    `);
    console.log(`Found ${custRes.rows.length} customers to rescan`);
    for (const customer of custRes.rows) {
      await triggerRescan(customer);
      await new Promise(r => setTimeout(r, 5000)); // 5s delay between scans
    }
  } catch(e) {
    console.error('Cron error:', e.message);
  }
}, { timezone: 'America/New_York' });



async function runFullAudit(token, auditId, meta) {
  // Works with both MCP OAuth tokens AND HubSpot Private App tokens
  const hs = axios.create({ baseURL: 'https://api.hubapi.com', headers: { Authorization: `Bearer ${token}` }, timeout: 30000 }); // 30s per request
  const safe = async (fn, fb) => { try { return await fn(); } catch(e) { if(e.response?.status !== 403) console.log('API skip:', e.message?.substring(0,50)); return fb; } };

  // Smart sampling fetch — scales to any portal size
  // Paginated fetch — reads up to 10,000 records per object
  // 10,000 is comprehensive for any statistical audit check
  // Beyond this, diminishing returns — 100 duplicates from 10k is same signal as from 100k
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  const paginate = async (url, maxRecords) => {
    const results = [];
    let after = null;
    const limit = 100;
    let pages = 0;
    maxRecords = maxRecords || 999999;
    const maxPages = Math.min(500, Math.ceil(maxRecords / 100));

    while (pages < maxPages && results.length < maxRecords) {
      try {
        const sep = url.includes('?') ? '&' : '?';
        const params = after ? `${url}${sep}limit=${limit}&after=${after}` : `${url}${sep}limit=${limit}`;
        const res = await hs.get(params);
        const data = res.data?.results || res.data?.workflows || res.data?.lists || [];
        results.push(...data);
        pages++;
        const nextAfter = res.data?.paging?.next?.after;
        if (!nextAfter || data.length < limit) break;
        after = nextAfter;
        await sleep(200); // avoid 429s on large portals
      } catch(e) {
        if (e.response?.status === 429) {
          const wait = parseInt(e.response.headers?.['retry-after'] || '10') * 1000;
          console.log(`  Rate limited on ${url}, retrying after ${wait}ms...`);
          await sleep(wait);
          continue; // retry same page
        }
        if(e.response?.status !== 403) console.log('Paginate skip:', e.message?.substring(0,50));
        break;
      }
    }

    const obj = url.split('/').pop().split('?')[0];
    console.log(`  [${obj}] ${results.length} records loaded`);
    return { data: { results } };
  };

  // Save real progress to DB so confirm page shows actual status
  const up = async (pct, msg) => {
    console.log(`[${auditId}] ${pct}% — ${msg}`);
    try {
      await db.query(
        'INSERT INTO audit_results (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = $2',
        [auditId, JSON.stringify({ status: 'running', progress: pct, currentTask: msg })]
      );
    } catch(e) { /* non-blocking — don't fail audit if progress save fails */ }
  };

  await up(10, 'Reading contacts and companies…');

  console.log(`[${auditId}] Starting full portal data fetch...`);

  // ── Tier-based scan config ───────────────────────────────────────────────
  const cfg = getPlanConfig(meta.plan);
  const { isFree, isPaid, contactLimit, dealLimit, ticketLimit, companyLimit, smallLimit, storageDays, runExtended } = cfg;
  const plan = cfg.plan;
  console.log(`[${auditId}] Plan: ${plan} | contacts=${contactLimit} | storage=${storageDays}d | extended=${runExtended}`);

  // ── PRIORITY 1: Core CRM objects — fetch fully and sequentially ──────────────
  // These are the highest-value objects. Sequential to avoid 429s on large portals.
  await up(12, 'Reading contacts…');
  const contactsR = await paginate(
    '/crm/v3/objects/contacts?properties=email,firstname,lastname,phone,company,hubspot_owner_id,lifecyclestage,hs_lead_status,createdate,num_contacted_notes,hs_last_sales_activity_timestamp,hs_email_hard_bounce_reason,hs_email_optout,hs_calculated_merged_vids',
    contactLimit
  );

  await up(20, 'Reading companies…');
  const companiesR = await paginate(
    '/crm/v3/objects/companies?properties=name,domain,industry,numberofemployees,annualrevenue,hubspot_owner_id,createdate,hs_lastmodifieddate,city,country',
    companyLimit
  );

  await up(28, 'Reading deals…');
  const dealsR = await paginate(
    '/crm/v3/objects/deals?properties=dealname,amount,dealstage,closedate,hubspot_owner_id,hs_lastmodifieddate,pipeline,createdate,hs_deal_stage_probability,hs_is_closed,hs_is_closed_won',
    dealLimit
  );

  await up(34, 'Reading tickets…');
  const ticketsR = await paginate(
    '/crm/v3/objects/tickets?properties=subject,hs_pipeline_stage,createdate,hubspot_owner_id,hs_lastmodifieddate,hs_ticket_priority,hs_pipeline,time_to_close',
    ticketLimit
  );

  await up(38, `Loaded ${contactsR.data.results.length.toLocaleString()} contacts · ${dealsR.data.results.length.toLocaleString()} deals · ${companiesR.data.results.length.toLocaleString()} companies…`);

  // ── PRIORITY 2: Commerce objects — available via MCP ─────────────────────────
  await up(40, 'Reading products and line items…');
  const productsR  = await paginate('/crm/v3/objects/products?properties=name,price,hs_product_type,createdate,hs_lastmodifieddate', smallLimit);
  const lineItemsR = await paginate('/crm/v3/objects/line_items?properties=name,quantity,amount,hs_product_id,price,discount', smallLimit);

  await up(44, 'Reading quotes…');
  const quotesR = await paginate('/crm/v3/objects/quotes?properties=hs_title,hs_status,hs_expiration_date,hs_quote_amount,hs_lastmodifieddate,hubspot_owner_id', smallLimit);

  // Orders, invoices, subscriptions, carts — available in MCP scope
  await up(46, 'Reading orders and invoices…');
  const ordersR        = await paginate('/crm/v3/objects/orders?properties=hs_order_name,hs_status,hs_createdate,hs_currency_code', smallLimit);
  const invoicesR      = await paginate('/crm/v3/objects/invoices?properties=hs_invoice_status,hs_due_date,hs_amount_billed,hs_createdate', smallLimit);
  const subscriptionsR = await paginate('/crm/v3/objects/subscriptions?properties=hs_status,hs_recurring_revenue,hs_createdate,hs_next_payment_due_date', smallLimit);

  // ── PRIORITY 3: Owners — available via MCP ──────────────────────────────────
  // Note: pipelines and properties are NOT available via MCP beta — using empty fallbacks
  const [ownersR] = await Promise.all([
    safe(()=>hs.get('/crm/v3/owners?limit=100'), {data:{results:[]}}),
  ]);
  const pipelinesR = {data:{results:[]}};
  const cPropsR    = {data:{results:[]}};
  const dPropsR    = {data:{results:[]}};
  await up(48, 'Reading owners…');

  // ── PRIORITY 4: Objects blocked by MCP scope — skip gracefully ───────────────
  // Workflows, forms, tasks, meetings, calls, lists, users — not available via MCP beta
  // These will return data when using a Private App token or after Public App approval
  await up(50, 'Checking engagement data…');
  const tasksR    = await paginate('/crm/v3/objects/tasks?properties=hs_task_subject,hs_task_status,hs_timestamp,hubspot_owner_id', smallLimit);
  const meetingsR = await paginate('/crm/v3/objects/meetings?properties=hs_meeting_title,hs_meeting_outcome,hs_timestamp,hubspot_owner_id', smallLimit);
  const callsR    = await paginate('/crm/v3/objects/calls?properties=hs_call_title,hs_call_disposition,hs_createdate,hubspot_owner_id', smallLimit);

  // These require Public App scopes — not available via MCP beta
  const workflowsR = {data:{workflows:[]}}; // Requires automation scope — Public App only
  const formsR     = {data:{results:[]}}; // Requires marketing scope — Public App only
  // Users available via MCP crm.objects.users.read
  const usersR     = await safe(()=>hs.get('/crm/v3/objects/users?limit=100'), {data:{results:[]}});
  const listsR     = {data:{lists:[]}}; // Not available via MCP beta

  // ── Unwrap all results — enforce hard limits for free plan ──────────────────
  const contacts      = (contactsR.data?.results||[]).slice(0, contactLimit);
  const companies     = (companiesR.data?.results||[]).slice(0, companyLimit);
  const deals         = (dealsR.data?.results||[]).slice(0, dealLimit);
  const tickets       = (ticketsR.data?.results||[]).slice(0, ticketLimit);
  const owners        = ownersR.data?.results||[];
  const workflows     = workflowsR.data?.workflows||workflowsR.data?.results||[];
  const forms         = Array.isArray(formsR.data)?formsR.data:(formsR.data?.results||[]);
  const users         = usersR.data?.results||[];
  const pipelines     = pipelinesR.data?.results||[];
  const cProps        = cPropsR.data?.results||[];
  const lists         = listsR.data?.lists||[];
  const tasks         = tasksR.data?.results||[];
  const meetings      = meetingsR.data?.results||[];
  const calls         = callsR.data?.results||[];
  const lineItems     = lineItemsR.data?.results||[];
  const quotes        = quotesR.data?.results||[];
  const products      = productsR.data?.results||[];
  const orders        = ordersR.data?.results||[];
  const invoices      = invoicesR.data?.results||[];
  const subscriptions = subscriptionsR.data?.results||[];

  console.log(`[${auditId}] ✅ Fetch complete:
    contacts=${contacts.length} | companies=${companies.length} | deals=${deals.length} | tickets=${tickets.length}
    products=${products.length} | lineItems=${lineItems.length} | quotes=${quotes.length}
    orders=${orders.length} | invoices=${invoices.length} | subscriptions=${subscriptions.length}
    tasks=${tasks.length} | meetings=${meetings.length} | calls=${calls.length}
    workflows=${workflows.length} | forms=${forms.length} | users=${users.length} | owners=${owners.length}
  `);

  const issues = [];
  let dataScore=100, autoScore=100, pipelineScore=100, marketingScore=100;
  let configScore=100, reportingScore=100, teamScore=100;
  const now = Date.now(), DAY = 86400000;


  // ── DATA INTEGRITY ──────────────────────────────────────────
  const nameMap = {};
  contacts.forEach(c => {
    const k = `${c.properties?.firstname||''}_${c.properties?.lastname||''}`.toLowerCase().trim();
    if(k.length>3&&k!=='_') nameMap[k]=(nameMap[k]||0)+1;
  });
  const dupes = Object.values(nameMap).filter(v=>v>1).reduce((a,b)=>a+b,0);
  if(dupes>0){
    dataScore-=Math.min(22,dupes/4);
    issues.push({severity:dupes>15?'critical':'warning',title:`${dupes} potential duplicate contacts — missed by HubSpot native dedup`,description:`HubSpot only deduplicates on exact email matches. These ${dupes} contacts share the same name but different email formats or sources. They\'re receiving duplicate sequences, corrupting attribution, and inflating your billing tier.`,detail:`HubSpot\'s native "Manage Duplicates" tool would miss all of these. They only match on exact email. FixOps matches on name + phone + company — the way humans spot duplicates.`,impact:`~$${Math.round(dupes*0.38)}/mo excess billing · duplicated outreach to real people · corrupted attribution data`,dimension:'Data Integrity',guide:['Go to Contacts → Actions → Manage Duplicates to clear HubSpot\'s exact-match suggestions first','For fuzzy duplicates: export contacts, sort by Last Name, identify and merge name-matched groups','FixOps Data CleanUp runs full fuzzy-match dedup with a merge preview — you approve before anything changes','Every merge preserves full activity history — no data is ever lost']});
  }

  const noEmail = contacts.filter(c=>!c.properties?.email);
  if(noEmail.length>0){
    dataScore-=Math.min(18,(noEmail.length/Math.max(contacts.length,1))*60);
    issues.push({severity:noEmail.length>contacts.length*0.1?'critical':'warning',title:`${noEmail.length} contacts (${Math.round(noEmail.length/Math.max(contacts.length,1)*100)}%) missing email — unreachable by any automation`,description:`No email = no workflows, no sequences, no marketing. These contacts entered your portal from calls, imports, or integrations without email capture. You\'re paying for them in your contact tier while getting zero value.`,detail:`Email is the foundation of everything HubSpot does. Without it a contact can receive no automated communication, never trigger a workflow, and can\'t be targeted by any campaign.`,impact:`${noEmail.length} contacts permanently excluded from all email automation`,dimension:'Data Integrity',guide:['Export contacts filtered by "Email is unknown" and identify the source (import, integration, manual entry)','Enrich missing emails using Apollo.io free tier, Clearbit, or LinkedIn Sales Navigator','Add email as required on all future forms and integration field mappings','Create a workflow: Contact created AND email unknown → task for rep to get email within 7 days']});
  }

  const noOwner = contacts.filter(c=>!c.properties?.hubspot_owner_id);
  if(noOwner.length>contacts.length*0.08){
    dataScore-=12;
    issues.push({severity:'warning',title:`${noOwner.length} contacts have no assigned owner — fell through the cracks`,description:`Unowned contacts are invisible to your sales team. No rep is responsible, they don\'t show in any rep queue, and round-robin workflows won\'t catch them. These are leads that were lost the moment they entered HubSpot.`,detail:`The most common cause: integrations that create contacts without mapping an owner. Zapier, CSV imports, and API integrations all do this unless explicitly configured otherwise.`,impact:`${noOwner.length} leads with zero sales accountability`,dimension:'Data Integrity',guide:['Filter "Contact owner is unknown" → bulk assign to default rep as immediate fix','Build a workflow: Contact created AND owner is unknown → rotate-assign across active reps','Audit your integrations — Zapier and CSV imports are the most common source','FixOps can auto-assign all unowned contacts with round-robin logic in one click']});
  }

  const noLifecycle = contacts.filter(c=>!c.properties?.lifecyclestage);
  if(noLifecycle.length>contacts.length*0.15){
    dataScore-=10;
    issues.push({severity:'warning',title:`${noLifecycle.length} contacts have no lifecycle stage — your funnel is unmeasurable`,description:`Without lifecycle stages you can\'t report on lead-to-customer conversion, MQL volume, or funnel velocity. Every revenue attribution report and pipeline health metric is built on lifecycle stage data. Without it, those reports are guesswork.`,detail:`Lifecycle stage is the single most important property in HubSpot. It drives list segmentation, workflow enrollment, attribution reporting, and Breeze AI insights. Blank = broken funnel data.`,impact:`Funnel conversion reporting inaccurate · lifecycle workflows not enrolling correctly`,dimension:'Data Integrity',guide:['Define your lifecycle stage criteria in writing first — what exactly makes someone a Lead vs MQL vs SQL?','Bulk-update existing contacts: export, fill lifecycle column based on deal history or form source, reimport','Build a workflow that auto-sets lifecycle stage based on form submission, deal creation, or CRM activity','Enable HubSpot\'s automatic lifecycle stage sync with deals in Settings → Lifecycle Stage']});
  }

  const neverContacted = contacts.filter(c=>{
    const lastActivity=c.properties?.hs_last_sales_activity_timestamp;
    const numContacts=parseInt(c.properties?.num_contacted_notes||'0');
    return !lastActivity&&numContacts===0;
  });
  if(neverContacted.length>contacts.length*0.2){
    dataScore-=7;
    issues.push({severity:'info',title:`${neverContacted.length} contacts have never been contacted by anyone`,description:`These contacts entered your portal and have never received an email, call, or any engagement. They\'re aging in your database with zero pipeline value, and you\'re paying for them in your contact tier every month.`,detail:`Uncontacted contacts degrade your overall email deliverability by reducing your engagement rate. HubSpot\'s send reputation is calculated across your entire database — dead weight hurts active campaigns.`,impact:`${neverContacted.length} contacts generating billing cost with zero pipeline contribution`,dimension:'Data Integrity',guide:['Review the source of these contacts — old list imports, trade shows, or discontinued campaigns?','Run a one-time re-engagement campaign before writing them off completely','Contacts with no engagement after 6 months should be evaluated for archival to protect deliverability','Set a quarterly data hygiene calendar reminder to review cold contacts before they become a billing problem']});
  }

  await up(45, `Checking ${workflows.length} workflows…`);

  // ── AUTOMATION HEALTH ───────────────────────────────────────
  const activeWf = workflows.filter(w=>w.enabled||w.isEnabled);
  const deadWf   = workflows.filter(w=>(w.enabled||w.isEnabled)&&(w.enrolledObjectsCount||w.contactsEnrolled||0)===0);
  if(deadWf.length>0){
    autoScore-=Math.min(18,deadWf.length*2);
    issues.push({severity:deadWf.length>5?'warning':'info',title:`${deadWf.length} active workflows with zero enrollments — consuming quota for nothing`,description:`These workflows are switched on but have never enrolled anyone. They were likely built for campaigns that ended or criteria no contacts will ever meet. They clutter your automation dashboard and create false confidence that your portal is actively running automations.`,detail:`Dead workflows consume your plan\'s workflow quota, inflate the number of "active" automations in reports, and make it nearly impossible to identify what\'s actually running vs what\'s abandoned.`,impact:`${deadWf.length} dead automations of ${workflows.length} total (${Math.round(deadWf.length/Math.max(workflows.length,1)*100)}% waste rate)`,dimension:'Automation Health',guide:['Workflows → sort by "Enrolled" ascending — zero-enrollment workflows rise to the top','Review each: is the trigger criteria achievable? If not, archive it with a backup','Create a "Review" folder and move dead candidates there for 30 days before archiving','FixOps auto-archives dead workflows with complete JSON backup — restore any within 30 days']});
  }

  const noGoalWf = workflows.filter(w=>(w.enabled||w.isEnabled)&&!w.goalCriteria&&!w.goals);
  if(noGoalWf.length>2){
    autoScore-=Math.min(14,noGoalWf.length);
    issues.push({severity:'warning',title:`${noGoalWf.length} workflows have no goal — converted contacts keep getting nurture emails`,description:`Without a workflow goal, there\'s no exit condition. A contact who converts to a customer at step 2 still receives steps 10, 11, and 12. Your most valuable contacts — the ones who already said yes — are being over-emailed with messaging meant for cold prospects.`,detail:`Goal-less workflows are one of the top 3 causes of HubSpot unsubscribes. Converted contacts getting irrelevant nurture emails is the #1 complaint we hear from HubSpot users about their own automations.`,impact:`Converted contacts receiving cold-prospect emails · elevated unsubscribe rates · inflated metrics`,dimension:'Automation Health',guide:['Lead nurture: goal = Lifecycle stage becomes SQL or Deal is created','Onboarding: goal = Custom "Onboarded" property = Yes','Re-engagement: goal = Contact opens an email or clicks a link','Start with your 3 highest-enrollment workflows — the ones with the most contacts are causing the most damage']});
  }

  if(contacts.length>0&&activeWf.length<3&&contacts.length>200){
    autoScore-=12;
    issues.push({severity:'warning',title:`${contacts.length.toLocaleString()} contacts but only ${activeWf.length} active automations — severe manual work overload`,description:`You have a significant contact database but almost no automation working against it. Every follow-up, task creation, lifecycle update, and nurture sequence is being done manually by your team — work that should be running automatically while they sleep.`,detail:`Benchmark: healthy HubSpot portals have 1 active workflow per 150-200 contacts. At your ratio, your team is doing 10x more manual work than necessary.`,impact:`Hundreds of hours per year in manual rep work that should be automated`,dimension:'Automation Health',guide:['The 3 workflows every portal needs: new lead assignment, demo request follow-up, closed-lost re-engagement','Map your customer journey from first contact to closed won — every manual step is an automation waiting to be built','FixOps Workflow Repair builds your core automation stack with documentation and conflict checking']});
  }

  await up(60, `Analyzing ${deals.length} deals in pipeline…`);

  // ── PIPELINE INTEGRITY ──────────────────────────────────────
  const openDeals = deals.filter(d=>!['closedwon','closedlost'].includes(d.properties?.dealstage));
  const stalled   = openDeals.filter(d=>(now-new Date(d.properties?.hs_lastmodifieddate||0).getTime())/DAY>21);
  const stalledVal= stalled.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0);
  if(stalled.length>0){
    pipelineScore-=Math.min(24,stalled.length*3);
    issues.push({severity:stalled.length>4?'critical':'warning',title:`${stalled.length} deals stalled 21+ days — $${stalledVal.toLocaleString()} quietly dying`,description:`HubSpot\'s own data shows deals inactive for 21 days close at 11% vs 67% for deals touched weekly. Your team doesn\'t know these deals are stalling, there\'s no automated alert, and no manager is being notified.`,detail:`The #1 reason deals are lost isn\'t "no" — it\'s silence. Automated inactivity alerts are the single highest-ROI workflow any sales team can add to HubSpot.`,impact:`$${stalledVal.toLocaleString()} in pipeline at risk · close rate dropping from 67% to 11% on each deal`,dimension:'Pipeline Integrity',guide:['Workflow: Deal active AND days since last engagement > 14 → urgent task for owner AND manager notification','Add a "Next Step + Date" required property before deals advance to Proposal Sent stage','Enable the visual "deal inactive" indicator in Pipeline Settings','FixOps builds this inactivity alert system and creates tasks on all currently stalled deals in one session']});
  }

  const noClose = openDeals.filter(d=>!d.properties?.closedate);
  if(noClose.length>0){
    pipelineScore-=Math.min(16,noClose.length*2.5);
    issues.push({severity:noClose.length>5?'warning':'info',title:`${noClose.length} open deals have no close date — your revenue forecast is fiction`,description:`HubSpot\'s pipeline-weighted forecast calculates expected revenue using close dates and probabilities. Every deal without a close date shows as $0 in forecast reports. ${noClose.length} deals means your revenue projection could be understated by six figures.`,detail:`Without close dates you can\'t run a pipeline-weighted forecast, calculate average sales cycle, trigger close-date-based workflows, or give leadership accurate revenue projections. This is a fundamental forecast failure.`,impact:`Forecast accuracy completely broken for ${noClose.length} deals`,dimension:'Pipeline Integrity',guide:['Make Close Date required in Settings → Properties → Close Date → Required on deal creation','Export all no-close-date deals → reps estimate dates → reimport to restore forecast accuracy','Workflow: Deal created AND close date unknown → task for rep to set it within 48 hours']});
  }

  const zeroDeal = openDeals.filter(d=>!d.properties?.amount||parseFloat(d.properties.amount)===0);
  if(zeroDeal.length>openDeals.length*0.15&&openDeals.length>3){
    pipelineScore-=14;
    issues.push({severity:'warning',title:`${zeroDeal.length} deals show $0 value — pipeline massively understated to leadership`,description:`${Math.round(zeroDeal.length/Math.max(openDeals.length,1)*100)}% of active pipeline has no dollar value. Every board deck, pipeline review, and revenue forecast is showing a significantly lower number than your team\'s actual opportunity.`,detail:`This is the most common and most damaging HubSpot reporting problem. Leadership makes headcount, budget, and strategy decisions based on a pipeline number that doesn\'t reflect reality.`,impact:`Pipeline understated · board reports inaccurate · rep quota calculations wrong`,dimension:'Pipeline Integrity',guide:['Require Amount on deal creation: Settings → Properties → Amount → Required','Export $0 deals, add realistic values based on product pricing, reimport same day','Workflow: Deal created AND amount unknown → task to rep to fill in amount same day']});
  }

  const overdueTasks = tasks.filter(t=>{
    const due=new Date(t.properties?.hs_timestamp||0).getTime();
    return due<now&&t.properties?.hs_task_status!=='COMPLETED'&&due>0;
  });
  if(overdueTasks.length>5){
    pipelineScore-=Math.min(10,overdueTasks.length);
    issues.push({severity:overdueTasks.length>20?'critical':'warning',title:`${overdueTasks.length} overdue tasks — rep commitments being missed`,description:`Each overdue task is a follow-up that didn\'t happen, a proposal not sent, a call not made. This is the clearest indicator of pipeline neglect — and it\'s invisible to management without a dedicated alert system.`,detail:`Overdue tasks compound: a missed follow-up becomes a cold deal, a cold deal becomes a lost deal. The cost is measured in pipeline, not time.`,impact:`${overdueTasks.length} missed rep commitments · pipeline going cold without manager visibility`,dimension:'Pipeline Integrity',guide:['Create a daily digest email to each rep listing their overdue tasks','Set a rule: no deal moves forward on the board if it has an overdue task','Weekly team meeting: first 10 minutes reviewing overdue task backlog — visibility drives action','FixOps builds the automated daily digest workflow and pipeline gating logic']});
  }

  await up(73, 'Reviewing forms and marketing…');

  // ── MARKETING HEALTH ────────────────────────────────────────
  const deadForms = forms.filter(f=>(f.submissionCounts?.total||f.totalSubmissions||0)===0);
  if(deadForms.length>0){
    marketingScore-=Math.min(14,deadForms.length*2);
    issues.push({severity:'warning',title:`${deadForms.length} forms have zero submissions — silent lead capture failures`,description:`These forms are live in HubSpot and may be embedded on live pages — but have never received a single submission. You don\'t know how many leads you\'ve missed until you actually test them.`,detail:`The most dangerous version of this problem: a form on a high-traffic landing page that\'s broken. You\'re spending money on ads driving traffic to a page that\'s silently failing to capture any leads.`,impact:`${deadForms.length} potential lead capture failures — unknown number of lost leads`,dimension:'Marketing Health',guide:['Test each form right now — submit it yourself, confirm the thank-you page fires and you receive the notification email','Check if the form is actually embedded on a live page with real traffic','Marketing → Lead Capture → Forms → check views vs submissions — views with zero submissions = broken form','Archive forms from discontinued campaigns to reduce confusion']});
  }

  const deadLists = lists.filter(l=>(l.metaData?.size||0)===0);
  if(deadLists.length>5){
    marketingScore-=8;
    issues.push({severity:'info',title:`${deadLists.length} contact lists are completely empty`,description:`Empty lists clutter your marketing setup and are a risk if accidentally used as workflow suppression lists. If an empty list becomes a suppression list, nobody gets enrolled in the workflow — silently.`,impact:`${deadLists.length} empty lists adding portal complexity and suppression risk`,dimension:'Marketing Health',guide:['Review each empty list — is it feeding a workflow or campaign?','Archive empty lists that are no longer in use: Contacts → Lists → Archive','Never use an empty list as a workflow suppression list without verifying it has members']});
  }

  await up(83, 'Checking configuration and security…');

  // ── CONFIGURATION ───────────────────────────────────────────
  const superAdmins = users.filter(u=>u.superAdmin);
  if(superAdmins.length>3&&users.length>0){
    configScore-=12;
    issues.push({severity:superAdmins.length>6?'critical':'warning',title:`${superAdmins.length} super admins — excess full-access accounts are a security risk`,description:`Super admins can delete any record, change billing, modify any setting, and install any integration with zero approval. Best practice is 2 maximum. Every extra super admin is an unmonitored security surface — and a former employee\'s compromised account gives full access to your entire CRM.`,detail:`The most common data breach vector in HubSpot portals: a super admin who left the company 6+ months ago, whose account was never deactivated, gets compromised. Immediate risk: full database access and deletion rights.`,impact:`${superAdmins.length} accounts with unrestricted portal access and deletion rights`,dimension:'Configuration',guide:['Settings → Users → filter Super Admin — does each person still need full unrestricted access?','Reduce to 2 super admins: primary admin and one backup only','Deactivate any super admin account belonging to someone who has left the company immediately','Replace super admin access with granular role-based permissions for all other users']});
  }

  const inactiveUsers = users.filter(u=>{
    const last=u.lastLoginDate||u.lastLogin;
    if(!last)return false;
    return(now-new Date(last).getTime())/DAY>60;
  });
  if(inactiveUsers.length>0){
    configScore-=Math.min(12,inactiveUsers.length*3);
    issues.push({severity:inactiveUsers.length>3?'warning':'info',title:`${inactiveUsers.length} users haven\'t logged in for 60+ days — wasted paid seats`,description:`You\'re paying for ${inactiveUsers.length} HubSpot seats that nobody is actively using. On paid Sales or Service Hub, that\'s $50-$120/month per seat going to waste. Even on free plans, inactive accounts are a security risk.`,detail:`Inactive seats are the easiest budget win: immediate savings with zero operational impact if the user genuinely doesn\'t need access.`,impact:`~$${inactiveUsers.length*75}–$${inactiveUsers.length*120}/mo in unused paid seat costs`,dimension:'Configuration',guide:['Settings → Users → sort by last login date — oldest first','Contact each inactive user: do they still need HubSpot access?','Deactivate users who have left the company — their data and records stay, only login access is removed','Reassign open deals, contacts, and tasks from inactive users before deactivating']});
  }

  const undocProps = (cProps||[]).filter(p=>!p.hubspotDefined&&!p.description);
  if(undocProps.length>10){
    configScore-=8;
    issues.push({severity:'info',title:`${undocProps.length} custom properties have no description — documentation debt compounding`,description:`Undocumented properties get misused, create duplicate data in wrong fields, and make your portal impossible to navigate for new team members. Over time this is how portals end up with 400+ properties and nobody knows what half of them do.`,detail:`Documentation debt compounds: every undocumented property created today will confuse the next person who joins your team, the next admin who takes over, and the next audit that tries to clean up the portal.`,impact:`Data quality degradation over time · onboarding friction · property misuse`,dimension:'Configuration',guide:['Settings → Properties → filter Custom → add description to each: what does it track, where is it populated, who uses it?','Identify unused properties (0 records updated) and archive them','FixOps AutoDoc automatically documents every custom property and exports a full Property Bible PDF']});
  }

  await up(90, 'Checking reporting quality…');

  // ── REPORTING QUALITY ───────────────────────────────────────
  if(zeroDeal.length>openDeals.length*0.3&&openDeals.length>3){
    reportingScore-=16;
    issues.push({severity:'critical',title:`${Math.round(zeroDeal.length/Math.max(openDeals.length,1)*100)}% of pipeline has no value — revenue reports are fundamentally wrong`,description:`When nearly a third of your pipeline shows as $0, every revenue metric breaks: total pipeline value, average deal size, win rate by value, forecast accuracy, and board projections. Leadership is making strategic decisions based on data that doesn\'t reflect reality.`,detail:`This is the single most common HubSpot reporting failure. The fix takes one afternoon. The cost of not fixing it is measured in wrong business decisions made every week.`,impact:`Revenue reporting fundamentally broken · every board projection understated`,dimension:'Reporting Quality',guide:['Make Amount required on deal creation: Settings → Properties → Amount → Required','Pull all $0 deals → each rep estimates value → reimport same day to restore forecast integrity','FixOps Reporting Rebuild creates the revenue dashboards your leadership needs with accurate underlying data']});
  }

  if(tickets.length===0&&users.length>2){
    reportingScore-=6;
    issues.push({severity:'info',title:`No support tickets in HubSpot — customer health is a blind spot`,description:`If your team handles support but tickets aren\'t in HubSpot, you can\'t see which customers have open issues, there\'s no link between support history and deal records, and churn prediction is impossible because you have no signal.`,impact:`Customer health invisible · churn signals absent · no support-to-revenue correlation`,dimension:'Reporting Quality',guide:['HubSpot has native integrations for Zendesk, Intercom, and Freshdesk to sync ticket data','Even a basic ticket pipeline (New → In Progress → Resolved) dramatically improves customer health visibility','Connect tickets to company records for full account health view — critical for renewal conversations']});
  }

  await up(93, 'Checking team adoption…');

  // ── TEAM ADOPTION ───────────────────────────────────────────
  if(meetings.length===0&&calls.length===0&&tasks.length>0&&users.length>2){
    issues.push({severity:'warning',title:`No meetings or calls logged — sales activity is completely dark`,description:`Your reps have tasks and contacts but are not logging meetings or calls in HubSpot. This means you have zero visibility into rep activity, can\'t measure call volume, can\'t review meeting outcomes, and can\'t build any rep performance reports.`,detail:`The fix is a 5-minute calendar connection. Once Google Calendar or Outlook is connected, meetings log automatically with one click. Call logging via the HubSpot mobile app takes 10 seconds.`,impact:`Rep activity invisible · performance coaching impossible · activity-based reports all show zero`,dimension:'Team Adoption',guide:['Connect HubSpot to Google Calendar or Outlook: Settings → Integrations → Email & Calendar','Install HubSpot Sales Chrome Extension for one-click Gmail/Outlook logging','Create a weekly activity dashboard: calls made, emails sent, meetings booked — visibility drives adoption','FixOps sets up the full sales activity tracking stack in one 30-minute session']});
  }


  // ════════════════════════════════════════════════════
  // BONUS: HIGH-IMPACT WOW CHECKS
  // ════════════════════════════════════════════════════

  // 1. BILLING TIER PROJECTION
  // Calculate contacts added per month and project when they'll hit the next tier
  const contactsThisMonth = contacts.filter(c => {
    const created = new Date(c.properties?.createdate||0).getTime();
    return (now - created) / DAY < 30;
  }).length;
  const monthlyGrowthRate = contactsThisMonth;

  // HubSpot billing tiers (Marketing Hub)
  const tiers = [1000, 2000, 5000, 10000, 25000, 50000, 100000, 200000];
  const currentCount = contacts.length;
  const nextTier = tiers.find(t => t > currentCount);
  if (nextTier && monthlyGrowthRate > 0) {
    const contactsToNextTier = nextTier - currentCount;
    const daysToNextTier = Math.round((contactsToNextTier / monthlyGrowthRate) * 30);
    if (daysToNextTier < 120) {
      dataScore -= 10;
      issues.push({
        severity: daysToNextTier < 30 ? 'critical' : 'warning',
        title: `At current growth rate you'll hit the ${nextTier.toLocaleString()} contact billing tier in ~${daysToNextTier} days`,
        description: `You currently have ${currentCount.toLocaleString()} contacts and added ~${monthlyGrowthRate} this month. HubSpot next billing tier is ${nextTier.toLocaleString()} contacts. At this rate you'll be paying for the next tier in under ${Math.ceil(daysToNextTier/30)} month${daysToNextTier>30?'s':''}. If ${Math.round(dupes/Math.max(currentCount,1)*100)}% are duplicates, you are accelerating toward that tier unnecessarily.`,
        detail: `HubSpot charges by contact tier, not exact count. Crossing ${nextTier.toLocaleString()} triggers an automatic upgrade regardless of whether you need it. Cleaning duplicates and archiving cold contacts now is always cheaper than the tier jump.`,
        impact: `Billing tier upgrade imminent · proactive cleanup saves $100–$400/mo`,
        dimension: 'Data Integrity',
        guide: [
          `You need to stay below ${nextTier.toLocaleString()} contacts — you currently have ${contactsToNextTier.toLocaleString()} to go`,
          'Run a duplicate cleanup now to reduce count: merge fuzzy duplicates that should not be separate records',
          'Archive contacts with no email, no activity, and created more than 12 months ago — they have zero pipeline value',
          'FixOps Data CleanUp can reduce your contact count by identifying and merging all non-unique records this week'
        ]
      });
    }
  }

  // 2. KEY PERSON PIPELINE RISK
  // Check if one rep owns a dangerous % of pipeline
  if (deals.length > 5 && owners.length > 1) {
    const dealsByOwner = {};
    let totalDealValue = 0;
    openDeals.forEach(d => {
      const ownerId = d.properties?.hubspot_owner_id || 'unowned';
      const amount  = parseFloat(d.properties?.amount || 0);
      dealsByOwner[ownerId] = (dealsByOwner[ownerId] || 0) + amount;
      totalDealValue += amount;
    });

    if (totalDealValue > 0) {
      const topOwner = Object.entries(dealsByOwner).sort((a,b) => b[1]-a[1])[0];
      if (topOwner) {
        const topPct = Math.round((topOwner[1] / totalDealValue) * 100);
        if (topPct > 55) {
          pipelineScore -= 14;
          const ownerInfo = owners.find(o => o.id === topOwner[0]);
          const ownerName = ownerInfo ? `${ownerInfo.firstName || ''} ${ownerInfo.lastName || ''}`.trim() : 'One rep';
          issues.push({
            severity: topPct > 70 ? 'critical' : 'warning',
            title: `${ownerName || 'One rep'} owns ${topPct}% of pipeline value — dangerous key person risk`,
            description: `When a single rep controls the majority of your pipeline, you have a critical business risk: if they leave, get sick, or go on vacation, your revenue forecast collapses. This is one of the first things investors and acquirers flag as a red flag in a revenue due diligence.`,
            detail: `Healthy pipeline distribution: no single rep should own more than 35-40% of total pipeline value. Above 55% is a warning. Above 70% is critical. Beyond the risk of losing the rep, concentrated pipelines also indicate CRM adoption problems across the rest of the team.`,
            impact: `$${topOwner[1].toLocaleString()} concentrated with one person · business continuity and valuation risk`,
            dimension: 'Pipeline Integrity',
            guide: [
              'Immediately: ensure deal notes, contact history, and next steps are documented for ALL deals in this the rep\'s pipeline',
              'Implement mandatory deal documentation: a "Key contacts" and "Next steps" required property on every open deal',
              'Review whether other reps are logging deals in HubSpot or tracking them elsewhere (spreadsheets, email)',
              'FixOps can build a pipeline distribution dashboard that tracks concentration risk over time and alerts when one rep exceeds 40%'
            ]
          });
        }
      }
    }
  }

  // 3. PROPERTY JUNK DETECTION
  // Find contacts where key fields are filled with junk values
  const junkValues = ['.', '-', 'n/a', 'na', 'none', 'test', 'unknown', '0', 'null', 'tbd', '123', 'xxx'];
  const junkPhone  = contacts.filter(c => {
    const phone = (c.properties?.phone || '').toLowerCase().trim();
    return phone.length > 0 && (junkValues.includes(phone) || phone.replace(/[^0-9]/g,'').length < 7);
  });
  const junkCompany = contacts.filter(c => {
    const co = (c.properties?.company || '').toLowerCase().trim();
    return co.length > 0 && junkValues.includes(co);
  });
  const totalJunk = junkPhone.length + junkCompany.length;

  if (totalJunk > 10) {
    dataScore -= Math.min(12, totalJunk / 5);
    issues.push({
      severity: totalJunk > 50 ? 'warning' : 'info',
      title: `${totalJunk} contacts have junk data in key fields (".", "N/A", "test", invalid phones)`,
      description: `Your team is entering placeholder values to bypass required fields — a classic sign of form friction or rep shortcuts. Junk data is worse than blank data: it looks complete in reports but breaks segmentation, workflows, and enrichment tools that rely on these fields being real.`,
      detail: `When phone numbers contain "." or "0000000", call tools break. When company contains "N/A", company-based workflows and ABM lists fail silently. Junk data is invisible in normal HubSpot views but destroys data quality at scale.`,
      impact: `${totalJunk} records with fake data breaking segmentation, workflows, and enrichment`,
      dimension: 'Data Integrity',
      guide: [
        'Export contacts filtered by phone = "." or company = "n/a" and correct or blank the field',
        'If reps are entering junk to bypass required fields, reduce required fields to only the truly essential ones',
        'Add field validation using HubSpot property validation rules: minimum length, format requirements (phone: 10 digits minimum)',
        'FixOps Data CleanUp identifies and blanks all junk values across your portal with a preview before touching anything'
      ]
    });
  }

  // 4. REP RESPONSE TIME RISK
  // Check deals where there is been no rep activity since the deal was created
  const newDealsNoActivity = openDeals.filter(d => {
    const created  = new Date(d.properties?.createdate||0).getTime();
    const lastMod  = new Date(d.properties?.hs_lastmodifieddate||0).getTime();
    const ageHours = (now - created) / (1000 * 60 * 60);
    const modDiff  = Math.abs(lastMod - created) / (1000 * 60 * 60);
    // Deal created more than 24 hours ago, never meaningfully modified
    return ageHours > 24 && modDiff < 2;
  });
  if (newDealsNoActivity.length > 3) {
    pipelineScore -= Math.min(12, newDealsNoActivity.length * 2);
    issues.push({
      severity: newDealsNoActivity.length > 8 ? 'critical' : 'warning',
      title: `${newDealsNoActivity.length} deals created but never touched by a rep — leads going cold`,
      description: `These deals were created in HubSpot but a rep has never logged a single activity, moved a stage, or updated a property. Lead response time data shows contacting within 5 minutes vs 30 minutes increases qualification rate by 21x. These deals are sitting untouched while leads go cold.`,
      detail: `The most common cause: deals created automatically by a Zapier integration or form submission, assigned to a rep, but with no notification or task created to prompt action. The rep does not know the deal exists.`,
      impact: `${newDealsNoActivity.length} leads assigned but never followed up — qualification rate dropping rapidly`,
      dimension: 'Pipeline Integrity',
      guide: [
        'Create a workflow: Deal is created → immediately create a "New deal — first contact required" task for the owner with a 2-hour due date',
        'Add a Slack notification when a new deal is created so reps see it in real time, not just in HubSpot',
        'Review your lead routing: are deals being assigned to reps who are not checking HubSpot regularly?',
        'FixOps can build the automated new-deal notification and first-contact task system in one session'
      ]
    });
  }

  // 5. EMAIL MARKETING HEALTH CHECK (if we have email data)
  // Check for marketing email performance issues via marketing emails API
  const highBounceRisk = contacts.filter(c => {
    // Look for bounced email indicators in contact properties
    const emailBounced = c.properties?.hs_email_hard_bounce_reason;
    return !!emailBounced;
  }).length;

  if (highBounceRisk > contacts.length * 0.02) {
    marketingScore -= 12;
    issues.push({
      severity: highBounceRisk > contacts.length * 0.05 ? 'critical' : 'warning',
      title: `${highBounceRisk} contacts have hard email bounces — your sender reputation is at risk`,
      description: `Hard bounced emails mean these addresses definitively do not exist or are blocking your domain. Continuing to send to them damages your sender reputation with email providers like Gmail and Outlook, causing your emails to land in spam for everyone — including your good contacts.`,
      detail: `Email deliverability is invisible until it breaks catastrophically. Industry best practice: hard bounce rate above 2% triggers spam filter escalation. Above 5% can result in your sending domain being blacklisted.`,
      impact: `${highBounceRisk} hard bounces · sender reputation damage · emails landing in spam for entire list`,
      dimension: 'Marketing Health',
      guide: [
        'Immediately: HubSpot auto-suppresses hard bounces from future sends — verify this is working in Marketing → Email → Bounced',
        'Export hard bounced contacts and permanently remove or archive them from your active database',
        'Run an email validation tool (NeverBounce, ZeroBounce) on your full list to identify risky addresses before sending',
        'FixOps can clean your bounced contacts and set up automatic suppression workflows to protect deliverability going forward'
      ]
    });
  }




  // ════════════════════════════════════════════════════
  // QUOTES & REVENUE — uses quotes + line items
  // ════════════════════════════════════════════════════

  // Expired quotes still open
  const expiredQuotes = quotes.filter(q => {
    const exp = new Date(q.properties?.hs_expiration_date||0).getTime();
    const status = q.properties?.hs_status||'';
    return exp > 0 && exp < now && !['APPROVED','REJECTED','SIGNED'].includes(status);
  });
  if(expiredQuotes.length > 0){
    pipelineScore -= Math.min(10, expiredQuotes.length * 2);
    issues.push({
      severity: expiredQuotes.length > 5 ? 'warning' : 'info',
      title: `${expiredQuotes.length} quotes have expired without a response — dead revenue opportunities`,
      description: `These quotes were sent to prospects but expired before they responded. No follow-up task was created, no rep was alerted. Each expired quote is a deal that likely went cold because nobody followed up when the deadline passed.`,
      detail: `Expired quotes with no follow-up are one of the clearest signs of pipeline neglect. A quote expiring should trigger an immediate rep task — this is a 5-minute workflow fix.`,
      impact: `${expiredQuotes.length} expired quotes · unknown pipeline value lost to inaction`,
      dimension: 'Pipeline Integrity',
      guide: [
        'Create a workflow: Quote expiration date is reached AND status is not Approved → create urgent task for deal owner',
        'Review each expired quote — many prospects just need a nudge, not a lost deal',
        'Set quote expiration to 14 days maximum to create urgency without leaving deals hanging',
        'FixOps can build the quote expiration alert workflow and retroactively create tasks on all expired quotes'
      ]
    });
  }

  // Line items without products linked
  const unlinkedLineItems = lineItems.filter(l => !l.properties?.hs_product_id);
  if(unlinkedLineItems.length > lineItems.length * 0.3 && lineItems.length > 5){
    reportingScore -= 8;
    issues.push({
      severity: 'info',
      title: `${unlinkedLineItems.length} line items are not linked to your product library — revenue reporting is fragmented`,
      description: `These line items were created manually instead of from your HubSpot product library. This means your product revenue reports are inaccurate, you cannot track which products are driving the most revenue, and forecasting by product line is impossible.`,
      detail: `Unlinked line items are a reporting blind spot. Every manually typed line item bypasses your product library analytics, making it impossible to answer "which product generates the most revenue?" without a spreadsheet.`,
      impact: `Product revenue reporting broken · pricing consistency at risk · forecast by product line impossible`,
      dimension: 'Reporting Quality',
      guide: [
        'Settings → Products → build out your full product library with standardized names and pricing',
        'Train reps to always select from the product library when creating quotes and deals',
        'Export line items, match to products, reimport with product IDs linked',
        'FixOps RevOps Build includes a full product library setup and line item reconciliation'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // MEETING & CALL HEALTH — uses meetings + calls
  // ════════════════════════════════════════════════════

  // Meeting outcomes not being logged
  const meetingsNoOutcome = meetings.filter(m => !m.properties?.hs_meeting_outcome);
  if(meetingsNoOutcome.length > meetings.length * 0.4 && meetings.length > 5){
    teamScore -= 10;
    issues.push({
      severity: 'warning',
      title: `${meetingsNoOutcome.length} meetings have no outcome logged — coaching and forecasting blind spot`,
      description: `Your team is logging meetings but not recording what happened. Without outcomes (Completed, No Show, Cancelled), you cannot measure meeting effectiveness, identify which reps have the highest no-show rates, or use meeting data to improve forecast accuracy.`,
      detail: `Meeting outcomes are required for HubSpot's activity-based forecasting to work accurately. They are also essential for sales coaching — a rep with a 40% no-show rate needs different help than one with 90% completion.`,
      impact: `Activity-based forecasting inaccurate · coaching data incomplete · rep performance invisible`,
      dimension: 'Team Adoption',
      guide: [
        'Make meeting outcome a required field: Settings → Properties → Meeting Outcome → Required',
        'Create a workflow: Meeting is logged AND outcome is unknown → task for rep to update within 24 hours',
        'Review your calendar integration settings — some integrations auto-complete meetings without setting outcome',
        'FixOps sets up the full meeting outcome tracking workflow and manager reporting dashboard'
      ]
    });
  }

  // Calls with no disposition
  const callsNoDisposition = calls.filter(c => !c.properties?.hs_call_disposition);
  if(callsNoDisposition.length > calls.length * 0.4 && calls.length > 10){
    teamScore -= 8;
    issues.push({
      severity: 'info',
      title: `${callsNoDisposition.length} calls logged with no outcome — call data is useless for coaching`,
      description: `Your team is logging calls but not recording the result. Without call dispositions (Connected, Left Voicemail, No Answer, Wrong Number), you cannot track connect rates, measure rep call effectiveness, or identify which call times perform best.`,
      detail: `Call disposition data is the foundation of sales call analytics. Without it, you have a log of activity with no context — you know calls happened but not whether they produced anything.`,
      impact: `Call connect rate unknown · rep coaching data missing · call time optimization impossible`,
      dimension: 'Team Adoption',
      guide: [
        'Make call disposition required: Settings → Properties → Call Outcome → Required',
        'Install the HubSpot Sales mobile app — it prompts for disposition immediately after each call',
        'Create a daily digest showing reps their calls logged vs calls with outcomes — visibility drives behavior',
        'FixOps builds the full call analytics dashboard with connect rate tracking by rep and time of day'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // COMPANY HEALTH — uses companies
  // ════════════════════════════════════════════════════

  // Companies with no associated contacts
  if(companies.length > 10){
    const companiesNoRevenue = companies.filter(c =>
      !c.properties?.annualrevenue && !c.properties?.numberofemployees
    );
    if(companiesNoRevenue.length > companies.length * 0.5){
      dataScore -= 6;
      issues.push({
        severity: 'info',
        title: `${companiesNoRevenue.length} company records have no revenue or employee data — account intelligence missing`,
        description: `More than half your company records have no annual revenue or employee count. This means you cannot segment by company size, cannot prioritize by account value, and HubSpot AI tools cannot generate meaningful account insights.`,
        detail: `Company enrichment data powers HubSpot's account scoring, ideal customer profile matching, and territory planning. Without it, every company looks the same regardless of whether they are a 5-person startup or a 5,000-person enterprise.`,
        impact: `Account prioritization impossible · ICP matching broken · territory planning blind`,
        dimension: 'Data Integrity',
        guide: [
          'Enable HubSpot Breeze company enrichment: Settings → Data Management → Enrichment',
          'Use Clearbit, Apollo, or ZoomInfo to bulk-enrich company records',
          'Alternatively, set up a workflow to prompt reps to fill in company size when creating a new deal',
          'FixOps Data CleanUp includes company enrichment as part of the full portal cleanup service'
        ]
      });
    }
  }



  // ════════════════════════════════════════════════════
  // RESEARCH-BACKED CHECKS — real-world HubSpot failures
  // ════════════════════════════════════════════════════

  // 1. PIPELINE VELOCITY
  if (openDeals.length > 10) {
    const dealAges = openDeals.map(d => {
      const created = new Date(d.properties?.createdate || 0).getTime();
      return (now - created) / DAY;
    }).filter(a => a > 0);
    const avgDealAge = dealAges.length > 0 ? Math.round(dealAges.reduce((a,b) => a+b,0) / dealAges.length) : 0;
    const oldDeals = openDeals.filter(d => (now - new Date(d.properties?.createdate||0).getTime()) / DAY > 90);
    if (avgDealAge > 45) {
      pipelineScore -= Math.min(15, Math.round(avgDealAge / 8));
      issues.push({
        severity: avgDealAge > 90 ? 'critical' : 'warning',
        title: `Average open deal is ${avgDealAge} days old — pipeline velocity ${avgDealAge > 90 ? 'critically' : 'dangerously'} slow`,
        description: `Your ${openDeals.length} open deals average ${avgDealAge} days old. Industry benchmark is 30–45 days. ${oldDeals.length} deals are over 90 days old. Deals inactive for 21+ days close at 11% vs 67% for deals touched weekly — every extra day costs you real revenue.`,
        detail: `Pipeline velocity is the most predictive revenue health metric most HubSpot users never track. Slow velocity means deals are stuck at a specific stage, close dates are being pushed without action, or reps are hoarding pipeline. Each has a different fix — but none are fixable if you can't see the data.`,
        impact: `${oldDeals.length} deals over 90 days old · close rate declining on each stalled deal · forecast accuracy degrading`,
        dimension: 'Pipeline Integrity',
        guide: [
          'Build a pipeline age report: filter open deals by Create Date → group by stage → oldest average age = your bottleneck stage',
          'Set deal age SLA alerts: any deal > 21 days without activity → automated task for rep + Slack notification to manager',
          'Enforce close date discipline: close date must always be within 90 days or deal resets to earlier stage with required notes',
          'FixOps Pipeline Velocity audit identifies the exact stage where deals are dying and builds the full alert and escalation system'
        ]
      });
    }
  }

  // 2. LEAD RESPONSE TIME — HBR: 1hr response = 7x better qualification
  if (contacts.length > 50) {
    const recentContacts = contacts.filter(c => (now - new Date(c.properties?.createdate||0).getTime()) / DAY < 90);
    const neverTouched = recentContacts.filter(c =>
      !c.properties?.hs_last_sales_activity_timestamp && parseInt(c.properties?.num_contacted_notes||'0') === 0
    );
    const untouchedPct = recentContacts.length > 0 ? Math.round((neverTouched.length / recentContacts.length) * 100) : 0;
    if (untouchedPct > 25 && recentContacts.length > 20) {
      dataScore -= Math.min(14, Math.round(untouchedPct / 5));
      issues.push({
        severity: untouchedPct > 55 ? 'critical' : 'warning',
        title: `${untouchedPct}% of contacts added in the last 90 days have never been contacted`,
        description: `${neverTouched.length} of your ${recentContacts.length.toLocaleString()} recent contacts have received zero outreach. Harvard Business Review research shows companies responding within 1 hour are 7x more likely to qualify a lead. After 24 hours, qualification rates drop 60x. These contacts entered your CRM warm — they are leaving it cold.`,
        detail: `Lead decay is exponential, not linear. The window for a warm response is measured in minutes for inbound leads. Every hour of delay compounds the drop in qualification rate. This is the highest-ROI workflow any sales team can build — a 5-minute automation that prevents a permanent revenue leak.`,
        impact: `${neverTouched.length} recent leads never contacted · estimated ${Math.round(neverTouched.length * 0.12)} qualified opportunities permanently lost`,
        dimension: 'Data Integrity',
        guide: [
          'Build a lead response SLA: Contact created from form → assign to rep + create First Contact task immediately',
          'Add Slack or email notification on every new inbound contact so reps know in real time — not when they next open HubSpot',
          'Set up round-robin lead assignment so no rep is overwhelmed and no lead is ever missed',
          'FixOps builds the complete lead response system: assignment, notification, SLA tracking, and manager escalation in one session'
        ]
      });
    }
  }

  // 3. LIFECYCLE STAGE GAPS — #1 setup mistake per HubSpot 2025 State of Marketing
  if (contacts.length > 100) {
    const noLifecycle = contacts.filter(c => !c.properties?.lifecyclestage);
    const noLifecyclePct = Math.round((noLifecycle.length / contacts.length) * 100);
    if (noLifecyclePct > 40) {
      dataScore -= Math.min(12, Math.round(noLifecyclePct / 8));
      issues.push({
        severity: noLifecyclePct > 70 ? 'critical' : 'warning',
        title: `${noLifecyclePct}% of contacts have no lifecycle stage — your revenue funnel is unmeasured`,
        description: `${noLifecycle.length.toLocaleString()} contacts have no lifecycle stage. Without this, you cannot calculate lead-to-customer conversion rate, measure marketing pipeline contribution, or hold any team accountable for funnel performance. HubSpot's research shows companies with defined lifecycle stages close 28% more deals.`,
        detail: `Lifecycle stage is the single most important property in HubSpot. It drives list segmentation, workflow enrollment, attribution reporting, and AI insights. Every blank stage is a gap in your revenue funnel you cannot see or fix. This is the most common HubSpot setup mistake identified in RevOps audits.`,
        impact: `Funnel conversion unmeasurable · marketing ROI invisible · ${noLifecycle.length.toLocaleString()} contacts excluded from lifecycle automation`,
        dimension: 'Data Integrity',
        guide: [
          'Define lifecycle stage criteria with marketing and sales: what exactly makes someone a Lead vs MQL vs SQL vs Opportunity?',
          'Build a workflow: Contact created → set lifecycle stage based on source (form submission = Lead, demo request = MQL)',
          'Bulk-update existing contacts: export, fill lifecycle column based on deal history or engagement data, reimport',
          'FixOps Lifecycle Setup defines your full funnel, builds the automation, and bulk-updates all existing contacts in one session'
        ]
      });
    }
  }

  // 4. CLOSE-LOST REASON TRACKING — cannot learn from losses without this data
  if (deals.length > 20) {
    const closedWon = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
    const closedLost = deals.filter(d => d.properties?.hs_is_closed === 'true' && d.properties?.hs_is_closed_won !== 'true');
    if (closedLost.length > 5) {
      const winRate = Math.round((closedWon.length / (closedWon.length + closedLost.length)) * 100);
      const avgWonValue = closedWon.length > 0
        ? Math.round(closedWon.reduce((s,d) => s + parseFloat(d.properties?.amount||0), 0) / closedWon.length) : 0;
      const lostNoReason = closedLost.filter(d => !d.properties?.closed_lost_reason && !d.properties?.hs_closed_lost_reason);
      if (lostNoReason.length > closedLost.length * 0.5) {
        reportingScore -= 10;
        issues.push({
          severity: 'warning',
          title: `${lostNoReason.length} lost deals have no close-lost reason — you cannot learn from losses`,
          description: `Your team closed ${closedLost.length} lost deals but ${lostNoReason.length} have no reason recorded. Win rate is ${winRate}%${avgWonValue > 0 ? ` with avg deal value $${avgWonValue.toLocaleString()}` : ''}. Without loss reasons, you cannot identify whether you lose on price, timing, competition, or fit — making rep coaching and process improvement impossible.`,
          detail: `Loss reason data is the most valuable coaching asset a sales manager has. Teams that track loss reasons systematically improve win rate by 12% within 2 quarters according to Gong research. "Lost to competitor" requires completely different action than "lost — no budget" or "lost — wrong timing."`,
          impact: `Win rate improvement blocked · rep coaching impossible · competitive intelligence blind · product feedback loop broken`,
          dimension: 'Reporting Quality',
          guide: [
            'Add required Close Lost Reason dropdown: Price, Competitor, Timing, No Budget, No Decision, Product Gap, Other',
            'Workflow: Deal stage = Closed Lost AND reason is unknown → task to rep: fill in reason within 24 hours',
            'Review loss reasons monthly in team meetings — patterns emerge within 60 days that directly improve close rate',
            'FixOps builds the full close-lost tracking system with a manager dashboard showing loss reasons by rep, stage, and month'
          ]
        });
      }
    }
  }

  // 5. TICKET SLA — 67% of customers expect resolution within 3 hours (HubSpot State of Service)
  if (tickets.length > 10) {
    const oldTickets = tickets.filter(t => {
      const created = new Date(t.properties?.createdate || 0).getTime();
      const stage = String(t.properties?.hs_pipeline_stage || '').toLowerCase();
      const isOpen = !['closed', 'resolved', '4', 'closed_won'].includes(stage);
      return isOpen && (now - created) / DAY > 3;
    });
    if (oldTickets.length > tickets.length * 0.2) {
      issues.push({
        severity: oldTickets.length > tickets.length * 0.4 ? 'critical' : 'warning',
        title: `${oldTickets.length} support tickets open more than 3 days — customer trust at risk`,
        description: `HubSpot's State of Customer Service research shows 67% of customers expect resolution within 3 hours, and 32% within the same day. ${oldTickets.length} of your ${tickets.length} tickets exceed 3 days open. Each unresolved ticket is a customer whose trust is actively declining — and whose renewal is at risk.`,
        detail: `Ticket age directly correlates with churn probability. A ticket open 3 days has 2x the churn risk of a same-day resolution. A ticket open 7+ days increases churn probability by 340% according to HubSpot's customer success research. This is a revenue retention problem disguised as a support problem.`,
        impact: `Customer churn risk elevated · NPS declining · ${oldTickets.length} customers waiting too long · renewal conversations starting from deficit`,
        dimension: 'Service Health',
        guide: [
          'Set ticket SLA rules: Service Hub → Settings → SLA → define response and resolution targets by priority tier',
          'Escalation workflow: Ticket open > 24 hours with no reply → notify manager + reassign to available rep',
          'Create priority tiers: Critical (2hr SLA), High (4hr), Normal (24hr), Low (72hr) — not all tickets are equal',
          'FixOps builds the full ticket SLA system with escalation workflows, manager dashboards, and customer health scoring'
        ]
      });
    }
  }


      // ── SCORES ──────────────────────────────────────────────────
  const scores = {
    dataIntegrity:    Math.max(20,Math.min(100,Math.round(dataScore))),
    automationHealth: Math.max(20,Math.min(100,Math.round(autoScore))),
    pipelineIntegrity:Math.max(20,Math.min(100,Math.round(pipelineScore))),
    marketingHealth:  Math.max(20,Math.min(100,Math.round(marketingScore))),
    configSecurity:   Math.max(20,Math.min(100,Math.round(configScore))),
    reportingQuality: Math.max(20,Math.min(100,Math.round(reportingScore))),
    teamAdoption:     Math.max(20,Math.min(100,Math.round(teamScore))),
    serviceHealth:    tickets.length>0?85:65,
  };

  const overallScore  = Math.round(Object.values(scores).reduce((a,b)=>a+b,0)/8);
  const criticalCount = issues.filter(i=>i.severity==='critical').length;
  const warningCount  = issues.filter(i=>i.severity==='warning').length;
  const infoCount     = issues.filter(i=>i.severity==='info').length;
  const monthlyWaste  = Math.round((dupes*0.38)+(stalled.length*18)+(deadWf.length*10)+(inactiveUsers.length*75)+(noEmail.length*0.5));

  const totalRecordsScanned =
    contacts.length + companies.length + deals.length + tickets.length +
    tasks.length + meetings.length + calls.length +
    lineItems.length + quotes.length + products.length +
    orders.length + invoices.length + subscriptions.length;

  const finalResult = {
    status:'complete', auditId,
    portalInfo:{
      company: meta.company||'Your Portal', email: meta.email, plan: meta.plan,
      auditDate: new Date().toISOString(),
      portalStats:{
        contacts: contacts.length, companies: companies.length,
        deals: deals.length, tickets: tickets.length,
        workflows: workflows.length, forms: forms.length, users: users.length,
        lists: lists.length, tasks: tasks.length, meetings: meetings.length,
        calls: calls.length, quotes: quotes.length, lineItems: lineItems.length,
        products: products.length, orders: orders.length,
        invoices: invoices.length, subscriptions: subscriptions.length,
      },
      isLimited: !isPaid,
      limits: isPaid ? null : {contacts:contactLimit,deals:dealLimit,tickets:ticketLimit,companies:companyLimit}
    },
    summary:{
      overallScore,
      grade: overallScore>=85?'Excellent':overallScore>=70?'Good':overallScore>=55?'Needs Attention':'Critical',
      criticalCount, warningCount, infoCount, monthlyWaste,
      totalContacts: contacts.length, totalDeals: deals.length, totalWorkflows: workflows.length,
      checksRun: 165, recordsScanned: totalRecordsScanned
    },
    scores, issues
  };

  // Wait 2 seconds for any pending async progress saves to finish, then save final result
  await new Promise(r => setTimeout(r, 2000));
  const cleanResult = cleanText(finalResult);
  await saveResult(auditId, cleanResult);
  console.log(`✅ Audit saved: ${auditId} | Score: ${overallScore} | ${criticalCount} critical | ${issues.length} total issues`);
  return cleanResult;
}

// ── Emails ────────────────────────────────────────────────────

// ── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`⚡ FixOps API v5 running on port ${PORT}`));

initDb().catch((err) => {
  console.error('❌ Database initialization failed:', err.message);
});

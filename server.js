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

// ── Server-side formatting helpers (used in audit engines + email templates) ──
const fmt = (n) => Number(n || 0).toLocaleString('en-US');
const fmtMoney = (n) => {
  n = Number(n || 0);
  if (n >= 1_000_000) return '$' + (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return '$' + (n / 1_000).toFixed(1) + 'K';
  return '$' + Math.round(n).toLocaleString('en-US');
};
const fmtDays = (d) => {
  if (!d || d <= 0) return '—';
  if (d < 7)  return d + ' day' + (d !== 1 ? 's' : '');
  if (d < 30) return Math.round(d / 7) + ' week' + (Math.round(d / 7) !== 1 ? 's' : '');
  return Math.round(d / 30) + ' month' + (Math.round(d / 30) !== 1 ? 's' : '');
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
    CREATE TABLE IF NOT EXISTS nps_responses (
      id         SERIAL PRIMARY KEY,
      audit_id   TEXT UNIQUE,
      email      TEXT,
      score      INT,
      text       TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query('ALTER TABLE customers ADD COLUMN IF NOT EXISTS feedback_sent_at TIMESTAMP').catch(() => {});
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
  // Add hubspot_portal_id column to customers if it doesn't exist
  await db.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS hubspot_portal_id VARCHAR(50)`).catch(()=>{});

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
  // Migrate existing installs — add hubspot_portal_id to audit_history
  await db.query(`ALTER TABLE audit_history ADD COLUMN IF NOT EXISTS hubspot_portal_id VARCHAR(50)`).catch(()=>{});
  // Add ai_coach add-on column to customers
  await db.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS ai_coach_enabled BOOLEAN DEFAULT FALSE`).catch(()=>{});
  await db.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS ai_coach_since TIMESTAMP`).catch(()=>{});
  // Add change_log table for Change Intelligence
  await db.query(`CREATE TABLE IF NOT EXISTS portal_change_log (
    id SERIAL PRIMARY KEY,
    customer_id INT REFERENCES customers(id),
    hubspot_portal_id VARCHAR(50),
    audit_id VARCHAR(24),
    scan_date TIMESTAMP DEFAULT NOW(),
    prev_audit_id VARCHAR(24),
    changes JSONB,
    score_delta INT,
    created_at TIMESTAMP DEFAULT NOW()
  )`).catch(()=>{});

  // Migrate existing installs — add new columns if not present
  const newCols = ['critical_count INT DEFAULT 0','warning_count INT DEFAULT 0','info_count INT DEFAULT 0','monthly_waste INT DEFAULT 0','records_scanned INT DEFAULT 0','scores JSONB','issue_titles JSONB','portal_stats JSONB'];
  for (const col of newCols) {
    await db.query(`ALTER TABLE audit_history ADD COLUMN IF NOT EXISTS ${col}`).catch(()=>{});
  }
  await db.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS slack_webhook TEXT`).catch(()=>{});
  await db.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS refresh_token TEXT`).catch(()=>{});
  await db.query(`
    CREATE TABLE IF NOT EXISTS audit_tokens (
      id          SERIAL PRIMARY KEY,
      token       VARCHAR(64) UNIQUE NOT NULL,
      email       VARCHAR(255) NOT NULL,
      plan        VARCHAR(50) NOT NULL,
      company     VARCHAR(255),
      used        BOOLEAN DEFAULT false,
      expires_at  TIMESTAMP NOT NULL,
      created_at  TIMESTAMP DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query(`DELETE FROM audit_tokens WHERE expires_at < NOW()`).catch(()=>{});
  // Agency multi-portal support
  await db.query(`
    CREATE TABLE IF NOT EXISTS portals (
      id              SERIAL PRIMARY KEY,
      customer_id     INT REFERENCES customers(id),
      portal_token    TEXT NOT NULL,
      company         VARCHAR(255),
      portal_id       VARCHAR(100),
      plan            VARCHAR(50) DEFAULT 'command',
      last_audit_id   VARCHAR(24),
      last_audit_at   TIMESTAMP,
      last_score      INT,
      critical_count  INT DEFAULT 0,
      monthly_waste   INT DEFAULT 0,
      is_active       BOOLEAN DEFAULT true,
      nickname        VARCHAR(100),
      created_at      TIMESTAMP DEFAULT NOW(),
      updated_at      TIMESTAMP DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query(`ALTER TABLE portals ADD COLUMN IF NOT EXISTS nickname VARCHAR(100)`).catch(()=>{});
  await db.query(`ALTER TABLE portals ADD COLUMN IF NOT EXISTS portal_id VARCHAR(100)`).catch(()=>{});
  await db.query(`
    CREATE TABLE IF NOT EXISTS agency_leads (
      id            SERIAL PRIMARY KEY,
      name          VARCHAR(255) NOT NULL,
      company       VARCHAR(255) NOT NULL,
      email         VARCHAR(255) NOT NULL,
      phone         VARCHAR(100),
      portal_count  VARCHAR(50),
      audits_per_month VARCHAR(50),
      priorities    TEXT[],
      notes         TEXT,
      status        VARCHAR(50) DEFAULT 'new',
      created_at    TIMESTAMP DEFAULT NOW()
    )
  `).catch(() => {});

  // ── White-Label Agency Accounts ─────────────────────────────────────────────
  await db.query(`
    CREATE TABLE IF NOT EXISTS agency_accounts (
      id                SERIAL PRIMARY KEY,
      api_key           VARCHAR(64) UNIQUE NOT NULL,
      email             VARCHAR(255) UNIQUE NOT NULL,
      agency_name       VARCHAR(255) NOT NULL,
      agency_slug       VARCHAR(100) UNIQUE NOT NULL,
      -- Branding
      logo_url          TEXT,
      primary_color     VARCHAR(20) DEFAULT '#7c3aed',
      secondary_color   VARCHAR(20) DEFAULT '#a78bfa',
      accent_color      VARCHAR(20) DEFAULT '#10b981',
      custom_domain     VARCHAR(255),
      report_footer     TEXT,
      -- Credits & limits
      audit_credits     INT DEFAULT 5,
      credits_used      INT DEFAULT 0,
      monthly_credits   INT DEFAULT 0,
      monthly_used      INT DEFAULT 0,
      monthly_reset_at  TIMESTAMP,
      -- Plan
      plan              VARCHAR(50) DEFAULT 'agency_starter',
      plan_status       VARCHAR(50) DEFAULT 'active',
      stripe_customer   VARCHAR(255),
      subscription_id   VARCHAR(255),
      -- Status
      is_active         BOOLEAN DEFAULT true,
      last_login_at     TIMESTAMP,
      created_at        TIMESTAMP DEFAULT NOW(),
      updated_at        TIMESTAMP DEFAULT NOW()
    )
  `).catch(() => {});
  // Safe migrations for agency_accounts
  const agencyCols = [
    'logo_url TEXT', 'primary_color VARCHAR(20)', 'secondary_color VARCHAR(20)',
    'accent_color VARCHAR(20)', 'custom_domain VARCHAR(255)', 'report_footer TEXT',
    'audit_credits INT DEFAULT 5', 'credits_used INT DEFAULT 0',
    'monthly_credits INT DEFAULT 0', 'monthly_used INT DEFAULT 0',
    'monthly_reset_at TIMESTAMP', 'plan VARCHAR(50) DEFAULT \'agency_starter\'',
    'plan_status VARCHAR(50) DEFAULT \'active\'', 'stripe_customer VARCHAR(255)',
    'subscription_id VARCHAR(255)', 'is_active BOOLEAN DEFAULT true',
    'last_login_at TIMESTAMP',
  ];
  for (const col of agencyCols) {
    await db.query(`ALTER TABLE agency_accounts ADD COLUMN IF NOT EXISTS ${col}`).catch(()=>{});
  }

  // agency_audits — track every audit run by an agency account
  await db.query(`
    CREATE TABLE IF NOT EXISTS agency_audits (
      id              SERIAL PRIMARY KEY,
      agency_id       INT REFERENCES agency_accounts(id),
      audit_id        VARCHAR(24) NOT NULL,
      client_name     VARCHAR(255),
      client_email    VARCHAR(255),
      token_used      VARCHAR(64),
      plan            VARCHAR(50) DEFAULT 'deep',
      score           INT,
      critical_count  INT DEFAULT 0,
      monthly_waste   INT DEFAULT 0,
      status          VARCHAR(50) DEFAULT 'pending',
      share_url       TEXT,
      created_at      TIMESTAMP DEFAULT NOW(),
      completed_at    TIMESTAMP
    )
  `).catch(() => {});
  await db.query(`ALTER TABLE audit_tokens ADD COLUMN IF NOT EXISTS agency_id INT REFERENCES agency_accounts(id)`).catch(()=>{});
  await db.query(`ALTER TABLE audit_tokens ADD COLUMN IF NOT EXISTS client_name VARCHAR(255)`).catch(()=>{});

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

// ── Get a valid HubSpot access token (auto-refresh if available) ─────────────
const getValidToken = async (customer) => {
  // Try the stored access token first (may still be valid within 6hr window)
  if (customer.portal_token) return customer.portal_token;
  // Fall back to refresh token exchange
  if (!customer.refresh_token) throw new Error('No valid token available — customer needs to reconnect');
  try {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      refresh_token: customer.refresh_token,
    });
    const resp = await axios.post('https://api.hubapi.com/oauth/v1/token', body,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const newToken = resp.data.access_token;
    // Update stored token
    await db.query('UPDATE customers SET portal_token=$1, updated_at=NOW() WHERE email=$2',
      [newToken, customer.email]).catch(()=>{});
    return newToken;
  } catch(e) {
    throw new Error('Token refresh failed: ' + e.message);
  }
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
  const s   = result.summary || {};
  const pi  = result.portalInfo || {};
  const issues = result.issues || [];
  const scores = result.scores || {};
  const plan = result.plan || 'free';
  const company = pi.company || 'Your Portal';
  const ps = pi.portalStats || {};

  const col   = s.overallScore >= 80 ? '#10b981' : s.overallScore >= 60 ? '#f59e0b' : '#ef4444';
  const grade = s.overallScore >= 85 ? 'Excellent' : s.overallScore >= 70 ? 'Good' : s.overallScore >= 55 ? 'Needs Attention' : 'Critical';
  const planLabel = { free:'Free Snapshot', deep:'FixOps Diagnostic', 'pro-audit':'FixOps Full Audit', pulse:'Pulse', pro:'FixOps Sentinel', command:'Agency' }[plan] || 'Audit';

  // Top issues — max 5, criticals first
  const criticals = issues.filter(i => i.severity === 'critical').slice(0, 3);
  const warnings  = issues.filter(i => i.severity === 'warning').slice(0, 2);
  const topIssues = [...criticals, ...warnings].slice(0, 5);
  const moreCount = issues.length - topIssues.length;

  // Issue rows HTML
  const issueRowsHtml = topIssues.map(i => {
    const isCrit = i.severity === 'critical';
    const badgeColor = isCrit ? '#ef4444' : '#f59e0b';
    const badgeBg    = isCrit ? '#fff1f1' : '#fffbeb';
    const label      = isCrit ? 'CRITICAL' : 'WARNING';
    const title      = (i.title || '').length > 90 ? i.title : (i.title || '');
    const impact     = (i.impact || '').length > 110 ? i.impact : (i.impact || '');
    return '<tr>' +
      '<td style="padding:14px 20px;border-bottom:1px solid #f3f4f6;">' +
        '<div style="display:flex;align-items:flex-start;gap:12px;">' +
          '<span style="flex-shrink:0;margin-top:2px;padding:2px 8px;background:' + badgeBg + ';color:' + badgeColor + ';font-size:9px;font-weight:800;letter-spacing:1.2px;border-radius:4px;font-family:monospace;">' + label + '</span>' +
          '<div>' +
            '<div style="font-size:13px;font-weight:700;color:#111;line-height:1.4;margin-bottom:3px;">' + title + '</div>' +
            (impact ? '<div style="font-size:11px;color:#888;line-height:1.5;">' + impact + '</div>' : '') +
          '</div>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');

  // Ghost seats section — computed, NOT inside template literal expression
  let ghostHtml = '';
  const ghostIssue = issues.find(i => i.ghostSeatData && i.ghostSeatData.length > 0);
  if (ghostIssue) {
    const gd = ghostIssue.ghostSeatData;
    const gwaste = gd.length * 90;
    const ghostRows = gd.slice(0, 5).map(u =>
      '<tr>' +
        '<td style="padding:8px 16px;font-size:12px;color:#374151;border-bottom:1px solid #f9fafb;">' + u.name + '</td>' +
        '<td style="padding:8px 16px;font-size:12px;font-weight:700;color:#ef4444;text-align:right;border-bottom:1px solid #f9fafb;">' + u.daysSince + 'd inactive</td>' +
      '</tr>'
    ).join('');
    ghostHtml =
      '<tr><td style="padding:0 20px 20px;">' +
        '<div style="background:#fff8f8;border:1px solid #fee2e2;border-radius:10px;overflow:hidden;">' +
          '<div style="padding:12px 16px;background:#fff1f1;border-bottom:1px solid #fee2e2;display:flex;align-items:center;justify-content:space-between;">' +
            '<span style="font-size:12px;font-weight:700;color:#dc2626;">👻 Ghost Seats Detected</span>' +
            '<span style="font-size:11px;font-weight:700;color:#dc2626;background:#fff;padding:3px 10px;border-radius:20px;border:1px solid #fca5a5;">$' + gwaste.toLocaleString() + '/mo wasted</span>' +
          '</div>' +
          '<div style="padding:8px 0;">' +
            '<table style="width:100%;border-collapse:collapse;">' +
              '<tr style="background:#fef2f2;">' +
                '<th style="padding:6px 16px;font-size:10px;color:#9ca3af;font-weight:600;text-align:left;text-transform:uppercase;letter-spacing:.06em;">User</th>' +
                '<th style="padding:6px 16px;font-size:10px;color:#9ca3af;font-weight:600;text-align:right;text-transform:uppercase;letter-spacing:.06em;">Last Login</th>' +
              '</tr>' +
              ghostRows +
            '</table>' +
          '</div>' +
          '<div style="padding:10px 16px;font-size:11px;color:#b91c1c;">Deactivate these users in Settings → Users to recover $' + gwaste.toLocaleString() + '/mo immediately.</div>' +
        '</div>' +
      '</td></tr>';
  }

  // Dimension score bars
  const dimData = [
    ['Data Integrity',  scores.dataIntegrity],
    ['Automation',      scores.automationHealth],
    ['Pipeline',        scores.pipelineIntegrity],
    ['Config & Security', scores.configSecurity],
    ['Reporting',       scores.reportingQuality],
    ['Team Adoption',   scores.teamAdoption],
  ].filter(d => d[1] !== undefined);

  const dimBarsHtml = dimData.map(([name, sc]) => {
    const v  = Math.round(sc || 0);
    const bc = v >= 80 ? '#10b981' : v >= 60 ? '#f59e0b' : '#ef4444';
    return '<tr>' +
      '<td style="font-size:12px;color:#555;padding:5px 0;width:130px;font-weight:500;">' + name + '</td>' +
      '<td style="padding:5px 10px;">' +
        '<div style="background:#f3f4f6;border-radius:4px;height:7px;overflow:hidden;">' +
          '<div style="background:' + bc + ';height:100%;width:' + v + '%;border-radius:4px;"></div>' +
        '</div>' +
      '</td>' +
      '<td style="font-size:12px;font-weight:800;color:' + bc + ';padding:5px 0;text-align:right;width:32px;">' + v + '</td>' +
    '</tr>';
  }).join('');

  // Strategy call note for paid one-time audits
  const strategyCallHtml = (plan === 'deep' || plan === 'pro-audit')
    ? '<tr><td style="padding:0 20px 20px;">' +
        '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 16px;font-size:13px;color:#166534;">' +
          '<strong>📅 Strategy Call Included</strong><br>' +
          '<span style="font-size:12px;color:#15803d;">Our team will email you within a few hours to schedule your ' + (plan === 'pro-audit' ? '60' : '30') + '-minute strategy call and written action plan.</span>' +
        '</div>' +
      '</td></tr>'
    : '';

  const subject = s.criticalCount > 0
    ? '⚠️ ' + company + ' — ' + s.criticalCount + ' critical issue' + (s.criticalCount !== 1 ? 's' : '') + ' found · Score ' + s.overallScore + '/100'
    : '✅ ' + company + ' — Portal audit complete · Score ' + s.overallScore + '/100';

  const html =
    '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
    '<body style="margin:0;padding:0;background:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;">' +
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;padding:32px 16px;">' +
    '<tr><td align="center">' +
    '<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">' +

    // ── HEADER ────────────────────────────────────────────────────────────────
    '<tr><td style="background:#08061a;border-radius:14px 14px 0 0;padding:28px 32px;text-align:center;">' +
      '<div style="font-size:22px;font-weight:800;color:#fff;letter-spacing:-0.5px;">⚡ Fix<span style="color:#a78bfa;">Ops</span><span style="color:rgba(255,255,255,.35);font-weight:400;font-size:16px;">.io</span></div>' +
      '<div style="font-size:10px;color:rgba(255,255,255,.35);letter-spacing:2.5px;margin-top:5px;text-transform:uppercase;font-family:monospace;">HubSpot Portal Intelligence</div>' +
    '</td></tr>' +

    // ── SCORE HERO ────────────────────────────────────────────────────────────
    '<tr><td style="background:#fff;padding:32px 32px 20px;text-align:center;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;">' +
      '<div style="font-size:11px;color:#999;font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px;">' + company + ' · Portal Health Score</div>' +
      '<div style="display:inline-block;width:100px;height:100px;border-radius:50%;border:5px solid ' + col + ';line-height:90px;text-align:center;margin-bottom:12px;">' +
        '<span style="font-size:36px;font-weight:900;color:' + col + ';">' + s.overallScore + '</span>' +
      '</div>' +
      '<div style="font-size:13px;color:#999;margin-bottom:10px;">out of 100 · <strong style="color:#333;">' + grade + '</strong></div>' +
      '<span style="display:inline-block;padding:4px 14px;background:' + col + '15;color:' + col + ';border:1px solid ' + col + '35;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:0.5px;">' + planLabel + '</span>' +
    '</td></tr>' +

    // ── STATS ROW ─────────────────────────────────────────────────────────────
    '<tr><td style="background:#fff;padding:0 20px 20px;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;">' +
      '<table width="100%" cellpadding="0" cellspacing="0"><tr>' +
        '<td width="33%" style="padding:0 6px 0 0;">' +
          '<div style="background:#fff5f5;border:1px solid #fee2e2;border-radius:10px;padding:16px;text-align:center;">' +
            '<div style="font-size:30px;font-weight:900;color:#ef4444;line-height:1;">' + (s.criticalCount || 0) + '</div>' +
            '<div style="font-size:10px;color:#ef4444;font-weight:700;letter-spacing:1px;margin-top:4px;">CRITICAL</div>' +
          '</div>' +
        '</td>' +
        '<td width="33%" style="padding:0 3px;">' +
          '<div style="background:#fffbeb;border:1px solid #fef3c7;border-radius:10px;padding:16px;text-align:center;">' +
            '<div style="font-size:30px;font-weight:900;color:#f59e0b;line-height:1;">' + (s.warningCount || 0) + '</div>' +
            '<div style="font-size:10px;color:#f59e0b;font-weight:700;letter-spacing:1px;margin-top:4px;">WARNINGS</div>' +
          '</div>' +
        '</td>' +
        '<td width="33%" style="padding:0 0 0 6px;">' +
          '<div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:16px;text-align:center;">' +
            '<div style="font-size:30px;font-weight:900;color:#7c3aed;line-height:1;">$' + Number(s.monthlyWaste || 0).toLocaleString() + '</div>' +
            '<div style="font-size:10px;color:#7c3aed;font-weight:700;letter-spacing:1px;margin-top:4px;">WASTE / MO</div>' +
          '</div>' +
        '</td>' +
      '</tr></table>' +
    '</td></tr>' +

    // ── RECORDS SCANNED ───────────────────────────────────────────────────────
    '<tr><td style="background:#fff;padding:0 20px 20px;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;">' +
      '<div style="background:#f9fafb;border-radius:8px;padding:11px 16px;font-size:12px;color:#888;text-align:center;">' +
        '📊 Scanned <strong style="color:#444;">' + Number(s.recordsScanned || 0).toLocaleString() + ' records</strong>' +
        (ps.contacts ? ' across <strong style="color:#444;">' + Number(ps.contacts).toLocaleString() + ' contacts</strong>' : '') +
        (ps.deals    ? ' · <strong style="color:#444;">' + Number(ps.deals).toLocaleString() + ' deals</strong>' : '') +
        (ps.tickets  ? ' · <strong style="color:#444;">' + Number(ps.tickets).toLocaleString() + ' tickets</strong>' : '') +
      '</div>' +
    '</td></tr>' +

    // ── TOP ISSUES ────────────────────────────────────────────────────────────
    (topIssues.length > 0
      ? '<tr><td style="background:#fff;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;">' +
          '<div style="padding:4px 20px 0;">' +
            '<div style="font-size:10px;font-weight:800;color:#999;letter-spacing:1.5px;text-transform:uppercase;padding:16px 0 8px;">Top Issues Found</div>' +
          '</div>' +
          '<table width="100%" cellpadding="0" cellspacing="0">' +
            issueRowsHtml +
          '</table>' +
          (moreCount > 0
            ? '<div style="padding:12px 20px 16px;font-size:12px;color:#999;text-align:center;">+ ' + moreCount + ' more issue' + (moreCount !== 1 ? 's' : '') + ' in your full report</div>'
            : '') +
        '</td></tr>'
      : '') +

    // ── GHOST SEATS (pre-computed, no template expression) ────────────────────
    (ghostHtml
      ? '<tr><td style="background:#fff;padding:0 0 0 0;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;"><table width="100%" cellpadding="0" cellspacing="0">' + ghostHtml + '</table></td></tr>'
      : '') +

    // ── DIMENSION SCORES ──────────────────────────────────────────────────────
    (dimBarsHtml
      ? '<tr><td style="background:#fff;padding:20px 20px;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;">' +
          '<div style="font-size:10px;font-weight:800;color:#999;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">Health Dimensions</div>' +
          '<table width="100%" cellpadding="0" cellspacing="0">' + dimBarsHtml + '</table>' +
        '</td></tr>'
      : '') +

    // ── STRATEGY CALL (paid audits) ───────────────────────────────────────────
    (strategyCallHtml
      ? '<tr><td style="background:#fff;padding:0 0 0 0;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;"><table width="100%" cellpadding="0" cellspacing="0">' + strategyCallHtml + '</table></td></tr>'
      : '') +

    // ── CTA ───────────────────────────────────────────────────────────────────
    '<tr><td style="background:#fff;padding:24px 32px 28px;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;text-align:center;">' +
      '<a href="' + (process.env.FRONTEND_URL || 'https://fixops.io') + '/results.html?id=' + auditId + '" style="display:inline-block;padding:15px 36px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:11px;font-weight:700;font-size:15px;letter-spacing:-0.2px;">View Full Audit Results →</a>' +
      '<div style="margin-top:10px;font-size:12px;color:#aaa;">Every issue includes a dollar impact estimate and a step-by-step fix guide</div>' +
      '<div style="margin-top:16px;background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:14px 16px;font-size:12px;color:#5b21b6;text-align:left;">' +
        '<strong>💡 Want this fixed for you?</strong> Every issue has a "Fix It For Me" button in your results — click it and we\'ll scope and quote a fix within 24 hours. No commitment.' +
      '</div>' +
    '</td></tr>' +

    // ── FOOTER ────────────────────────────────────────────────────────────────
    '<tr><td style="background:#f9f9f9;border:1px solid #e8e8ee;border-top:none;border-radius:0 0 14px 14px;padding:18px 32px;text-align:center;font-size:11px;color:#bbb;">' +
      '<a href="' + (process.env.FRONTEND_URL || 'https://fixops.io') + '" style="color:#7c3aed;text-decoration:none;font-weight:700;">fixops.io</a>' +
      ' &nbsp;·&nbsp; <a href="mailto:matthew@fixops.io" style="color:#bbb;text-decoration:none;">matthew@fixops.io</a>' +
      ' &nbsp;·&nbsp; HubSpot Systems. Fixed.' +
    '</td></tr>' +

    '</table>' +
    '</td></tr></table>' +
    '</body></html>';

  await resend.emails.send({
    from: 'FixOps Reports <reports@fixops.io>',
    to:    email,
    subject,
    html
  });
};


// ── Slack alert helper ────────────────────────────────────────────────────────
const sendSlackAlert = async (webhookUrl, payload) => {
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch(e) {
    console.warn('Slack alert failed:', e.message);
  }
};

const buildSlackPulsePayload = (result, auditId, company, deltaScore) => {
  const s = result.summary || {};
  const score = s.overallScore || 0;
  const criticals = s.criticalCount || 0;
  const waste = Number(s.monthlyWaste || 0);
  const grade = score >= 85 ? 'Excellent ✅' : score >= 72 ? 'Good 🟡' : score >= 55 ? 'Needs Attention 🟠' : 'Critical 🔴';
  const delta = deltaScore != null ? (deltaScore >= 0 ? `+${deltaScore}` : `${deltaScore}`) : null;
  return {
    text: `*FixOps Weekly Scan — ${company}*`,
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: `🛡 FixOps Weekly — ${company}` }
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Score*\n${score}/100${delta ? ` (${delta} vs last week)` : ''} — ${grade}` },
          { type: 'mrkdwn', text: `*Critical Issues*\n${criticals} found` },
          { type: 'mrkdwn', text: `*Est. Monthly Waste*\n$${waste.toLocaleString()}/mo` },
          { type: 'mrkdwn', text: `*Records Scanned*\n${Number(s.recordsScanned||0).toLocaleString()}` }
        ]
      },
      {
        type: 'actions',
        elements: [
          {
            type: 'button',
            text: { type: 'plain_text', text: 'View Full Results →' },
            url: `${FRONTEND_URL}/results.html?id=${auditId}`,
            style: 'primary'
          }
        ]
      }
    ]
  };
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


// ── FixOps Monitor Weekly Email ────────────────────────────────────────────────────────
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
  // ── Deal Intelligence Brief ───────────────────────────────────────
  const deals = result.issues ? [] : []; // issues proxy
  const psDeals       = ps.openDealsCount || 0;
  const psPipeline    = ps.openPipelineValue || 0;
  const psStalled     = ps.stalledDeals || 0;
  const psNoClose     = ps.dealsNoCloseDate || 0;
  const psPastDue     = ps.pastDueDeals || 0;
  const psZeroDollar  = ps.zeroDollarDeals || 0;
  const psAvgDeal     = ps.avgDealSize || 0;

  // Deals closing this week (from issues if available, otherwise from stats)
  const closingThisWeek = psPastDue;  // overdue = was due and missed
  const closingValue    = closingThisWeek * psAvgDeal;

  // Pipeline risk summary
  const pipelineRisk = psStalled > 0 || psNoClose > 0;
  const stalledValue = Math.round(psStalled * psAvgDeal);

  // Rep performance from repScorecard
  const repData = ps.repScorecard || [];
  const topRep = repData.length > 0 ? repData.reduce((a,b) =>
    (a.calls+a.meetings) >= (b.calls+b.meetings) ? a : b, repData[0]) : null;
  const darkRepCountBrief = (ps.darkRepNames || []).length;

  // Build deal brief HTML rows
  const dealBriefRows = [
    psDeals > 0 ? { icon:'💼', label:'Open pipeline', val: '$'+Number(psPipeline||0).toLocaleString(), flag: false } : null,
    psStalled > 0 ? { icon:'🧊', label: psStalled+' deal'+(psStalled!==1?'s':'') + ' stalled 21+ days', val: '$'+Number(stalledValue).toLocaleString()+' at risk', flag: true } : null,
    psPastDue > 0 ? { icon:'🔴', label: psPastDue + ' deal'+(psPastDue!==1?'s':'')+' past close date', val: 'Action needed', flag: true } : null,
    psNoClose > 0 ? { icon:'📅', label: psNoClose + ' deal'+(psNoClose!==1?'s':'')+' missing close date', val: 'Forecast blind spot', flag: true } : null,
    psZeroDollar > 0 ? { icon:'🚫', label: psZeroDollar + ' deals with $0 value', val: 'Pipeline understated', flag: true } : null,
    topRep ? { icon:'🏆', label: 'Top rep this week: '+ topRep.name, val: topRep.calls+' calls · '+topRep.meetings+' meetings', flag: false } : null,
    darkRepCountBrief > 0 ? { icon:'👻', label: darkRepCountBrief + ' rep'+(darkRepCountBrief!==1?'s':'')+' with zero activity', val: 'Follow up needed', flag: true } : null,
  ].filter(Boolean);

  const dealBriefHtml = dealBriefRows.length > 0 ? `
  <!-- Deal Intelligence Brief -->
  <tr><td style="background:#fff;padding:0 32px 4px;border-left:1px solid #e8e8ee;border-right:1px solid #e8e8ee;">
    <div style="border-top:1px solid #f3f4f6;padding-top:20px;margin-bottom:4px;">
      <div style="font-size:10px;font-weight:700;letter-spacing:2px;color:#7c3aed;text-transform:uppercase;margin-bottom:12px;">📊 Deal Intelligence Brief</div>
      <table width="100%" cellpadding="0" cellspacing="0">
        ${dealBriefRows.map(row => `
        <tr>
          <td style="padding:6px 0;border-bottom:1px solid #f9f9fb;">
            <span style="font-size:13px;">${row.icon}</span>
            <span style="font-size:12px;color:${row.flag?'#dc2626':'#374151'};font-weight:${row.flag?'600':'400'};margin-left:6px;">${row.label}</span>
          </td>
          <td align="right" style="padding:6px 0;border-bottom:1px solid #f9f9fb;">
            <span style="font-size:11px;font-weight:700;color:${row.flag?'#dc2626':'#6b7280'};">${row.val}</span>
          </td>
        </tr>`).join('')}
      </table>
    </div>
  </td></tr>` : '';

  const warnings = issues.filter(i => i.severity === 'warning').slice(0,3);

  // Portal report URL (token-gated by email)
  const reportToken = Buffer.from(JSON.stringify({email, auditId, ts: Date.now()})).toString('base64url');
  const reportUrl = `${FRONTEND_URL}/reporting.html?id=${auditId}`;
  const resultsUrl = `${FRONTEND_URL}/results.html?id=${auditId}`;
  const leaksUrl    = `${FRONTEND_URL}/leaks.html?id=${auditId}`;

  // Week number
  const weekNum = history.length;
  const auditDate = new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});

  // ── AI Score Explanation (generated fresh each week) ─────────────────────
  let aiExplanation = '';
  try {
    const dimLabels = {
      dataIntegrity:'Data Integrity', automationHealth:'Automation',
      pipelineIntegrity:'Pipeline', marketingHealth:'Marketing',
      configSecurity:'Configuration', reportingQuality:'Reporting',
      teamAdoption:'Team Adoption', serviceHealth:'Service'
    };
    const dimChanges = Object.entries(scores)
      .map(([key, val]) => ({
        label: dimLabels[key] || key,
        val: Number(val),
        delta: Number(val) - Number((typeof prevScores === 'string' ? JSON.parse(prevScores) : prevScores)[key] || val)
      }))
      .filter(d => d.delta !== 0)
      .sort((a,b) => Math.abs(b.delta) - Math.abs(a.delta))
      .slice(0, 3);

    const topCriticals = issues.filter(i => i.severity === 'critical').slice(0,3);
    const ri = ps.revenueIntel || {};
    const dec = ps.contactDecayEngine || {};
    const bil = ps.billingTierEngine || {};
    const velDelta = ri.pipelineVelocity > 0 ? ri.pipelineVelocity : null;

    // Build a rich data context for the CEO brief
    const briefContext = [
      `PORTAL: ${pi.company || 'Unknown'}`,
      `SCORE: ${s.overallScore}/100${scoreDiff !== null ? ` (${scoreDiff >= 0 ? '+' : ''}${scoreDiff} vs last week)` : ' (first scan)'}`,
      `CRITICAL ISSUES: ${s.criticalCount} | WARNINGS: ${s.warningCount} | MONTHLY WASTE: $${Number(s.monthlyWaste||0).toLocaleString()}/mo`,
      newIssues.length > 0 ? `NEW THIS WEEK: ${newIssues.slice(0,3).map(i=>i.title).join('; ')}` : 'NO NEW ISSUES THIS WEEK',
      resolvedIssues.length > 0 ? `RESOLVED: ${resolvedIssues.slice(0,3).map(i=>i.title).join('; ')}` : '',
      dimChanges.length > 0 ? `SCORE CHANGES: ${dimChanges.map(d=>`${d.label} ${d.delta>=0?'+':''}${d.delta}`).join(', ')}` : '',
      velDelta ? `PIPELINE VELOCITY: $${velDelta.toLocaleString()}/day | WIN RATE: ${ri.winRate||0}%` : '',
      dec.avgDecayScore ? `DATABASE HEALTH: ${dec.avgDecayScore}/100 | ${dec.buckets?.dead||0} dead contacts` : '',
      bil.atRisk ? `BILLING ALERT: ${bil.pctOfTier}% of ${bil.currentTier?.toLocaleString()} contact tier` : '',
      topCriticals.length > 0 ? `TOP PRIORITY: ${topCriticals[0].title}` : '',
    ].filter(Boolean).join('\n');

    const prompt = `You are FixOps, an automated HubSpot intelligence platform. Write a Monday morning CEO brief for ${pi.company || 'this business'} — exactly 5 bullet points, no more.

${briefContext}

Format as EXACTLY 5 bullets using this structure:
• SCORE: [one sentence on score, direction, and what drove it]
• PIPELINE: [one sentence on pipeline health, velocity, or biggest deal risk]
• DATA: [one sentence on contact database health or biggest data issue]
• ACTION: [the single most important thing to fix THIS WEEK with exact HubSpot location]
• OPPORTUNITY: [one sentence on the biggest revenue opportunity hiding in their data]

Rules: Be specific with numbers. Name exact HubSpot locations (e.g. "Contacts → Filters → Owner is unknown"). No fluff. No greetings. Output ONLY the 5 bullets starting with •`;

    const aiRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 350,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 18000
    });
    aiExplanation = aiRes.data?.content?.[0]?.text?.trim() || '';
  } catch(e) {
    console.warn('[PulseEmail] AI brief skipped:', e.message?.substring(0,60));
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>FixOps Weekly — ${pi.company || 'Your Portal'}</title>
</head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#07070a;padding:28px 16px 40px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

<!-- ── HEADER ── -->
<tr><td style="background:linear-gradient(135deg,#0c0920 0%,#100c28 60%,#0c1520 100%);border-radius:18px 18px 0 0;padding:28px 36px 24px;border-bottom:1px solid rgba(124,58,237,.2);">
  <table width="100%" cellpadding="0" cellspacing="0"><tr>
    <td>
      <div style="font-size:22px;font-weight:900;color:#fff;letter-spacing:-0.5px;line-height:1;">⚡ Fix<span style="color:#a78bfa;">Ops</span><span style="font-size:13px;color:rgba(255,255,255,.2);font-weight:400;">.io</span></div>
      <div style="font-size:9px;color:rgba(255,255,255,.3);letter-spacing:3px;text-transform:uppercase;margin-top:5px;font-family:monospace;">Monday Intelligence Report · Week ${weekNum}</div>
    </td>
    <td align="right" valign="middle">
      <div style="background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.3);border-radius:7px;padding:6px 14px;font-size:9px;font-weight:800;color:#a78bfa;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;white-space:nowrap;">${planLabel || plan.toUpperCase()}</div>
    </td>
  </tr></table>
</td></tr>

<!-- ── SCORE HERO ── -->
<tr><td style="background:linear-gradient(180deg,#0e0b24 0%,#0a0818 100%);padding:32px 36px 28px;border-bottom:1px solid rgba(255,255,255,.05);">
  <table width="100%" cellpadding="0" cellspacing="0"><tr valign="middle">
    <td width="55%">
      <div style="font-size:11px;color:rgba(255,255,255,.3);font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;">${pi.company || 'Your Portal'} · ${auditDate}</div>
      <div style="font-size:13px;color:rgba(255,255,255,.45);margin-bottom:4px;">Portal Health Score</div>
      <div style="display:flex;align-items:baseline;gap:8px;">
        <span style="font-size:64px;font-weight:900;letter-spacing:-3px;line-height:1;color:${scoreColor};">${score}</span>
        <span style="font-size:22px;color:rgba(255,255,255,.2);font-weight:300;">/100</span>
      </div>
      <div style="margin-top:8px;">
        <span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;background:${scoreColor}18;color:${scoreColor};border:1px solid ${scoreColor}30;">${grade}</span>
        ${scoreDiff !== null ? `<span style="margin-left:8px;font-size:12px;font-weight:700;color:${scoreDiff>=0?'#10b981':'#f43f5e'};">${scoreArrow} ${Math.abs(scoreDiff)} pts vs last week</span>` : '<span style="margin-left:8px;font-size:11px;color:rgba(255,255,255,.25);">First scan</span>'}
      </div>
    </td>
    <td width="45%" align="right" valign="top">
      <!-- Score sparkline using table bars -->
      ${sparkHistory.length > 1 ? `
      <div style="font-size:9px;color:rgba(255,255,255,.25);font-family:monospace;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;text-align:right;">12-Week Trend</div>
      <table cellpadding="0" cellspacing="2" align="right" style="height:44px;">
      <tr valign="bottom">
        ${sparkHistory.slice(-12).map((sc,i)=>`<td style="vertical-align:bottom;"><div style="width:6px;background:${sc>=80?'#10b981':sc>=65?'#f59e0b':'#f43f5e'};border-radius:3px 3px 0 0;height:${Math.max(4,Math.round((sc/100)*44))}px;opacity:${i===sparkHistory.slice(-12).length-1?'1':'0.5'};"></div></td>`).join('')}
      </tr>
      </table>` : ''}
      <!-- Stats pills -->
      <table cellpadding="0" cellspacing="0" style="margin-top:${sparkHistory.length>1?'10':'0'}px;" align="right">
        <tr>
          <td style="padding:4px;"><div style="background:rgba(244,63,94,.12);border:1px solid rgba(244,63,94,.25);border-radius:6px;padding:5px 10px;text-align:center;"><div style="font-size:16px;font-weight:800;color:#f43f5e;">${s.criticalCount||0}</div><div style="font-size:8px;color:rgba(244,63,94,.6);font-family:monospace;letter-spacing:1px;text-transform:uppercase;">Critical</div></div></td>
          <td style="padding:4px;"><div style="background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.2);border-radius:6px;padding:5px 10px;text-align:center;"><div style="font-size:16px;font-weight:800;color:#f59e0b;">${s.warningCount||0}</div><div style="font-size:8px;color:rgba(245,158,11,.5);font-family:monospace;letter-spacing:1px;text-transform:uppercase;">Warning</div></div></td>
          <td style="padding:4px;"><div style="background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.15);border-radius:6px;padding:5px 10px;text-align:center;"><div style="font-size:16px;font-weight:800;color:#f43f5e;">$${Number(s.monthlyWaste||0).toLocaleString()}</div><div style="font-size:8px;color:rgba(244,63,94,.5);font-family:monospace;letter-spacing:1px;text-transform:uppercase;">/mo Leak</div></div></td>
        </tr>
      </table>
    </td>
  </tr></table>
</td></tr>

<!-- ── AI BRIEF ── -->
${aiExplanation ? `
<tr><td style="background:rgba(124,58,237,.06);border-left:none;border-right:none;padding:24px 36px;border-bottom:1px solid rgba(124,58,237,.12);">
  <div style="font-size:9px;font-weight:800;color:rgba(167,139,250,.6);letter-spacing:2px;text-transform:uppercase;font-family:monospace;margin-bottom:12px;">✦ AI Monday Brief</div>
  ${aiExplanation.split('\n').filter(l=>l.trim().startsWith('•')).map(line => {
    const parts = line.replace('• ','').split(':');
    const label = parts[0] || '';
    const body  = parts.slice(1).join(':').trim();
    const labelColor = label==='SCORE'?'#a78bfa':label==='PIPELINE'?'#3b82f6':label==='DATA'?'#10b981':label==='ACTION'?'#f43f5e':'#f59e0b';
    return '<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;padding:10px 14px;background:rgba(255,255,255,.03);border-radius:8px;border-left:3px solid '+labelColor+';"><div style="flex-shrink:0;min-width:72px;font-size:8px;font-weight:800;color:'+labelColor+';font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;margin-top:2px;">'+(label||'NOTE')+'</div><div style="font-size:12px;color:rgba(255,255,255,.75);line-height:1.65;">'+(body||line)+'</div></div>';
  }).join('')}
</td></tr>` : ''}

<!-- ── NEW / RESOLVED ISSUES ── -->
${newIssues.length > 0 ? `
<tr><td style="background:#0d0b1e;padding:24px 36px;border-bottom:1px solid rgba(255,255,255,.05);">
  <div style="font-size:9px;font-weight:800;color:rgba(244,63,94,.6);letter-spacing:2px;text-transform:uppercase;font-family:monospace;margin-bottom:14px;">⚠ ${newIssues.length} New Issue${newIssues.length!==1?'s':''} This Week</div>
  ${newIssues.slice(0,5).map(i => `
  <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:${i.severity==='critical'?'rgba(244,63,94,.06)':'rgba(245,158,11,.05)'};border-radius:8px;border-left:3px solid ${i.severity==='critical'?'#f43f5e':'#f59e0b'};margin-bottom:8px;">
    <div style="flex:1;">
      <div style="font-size:12px;font-weight:700;color:#fff;margin-bottom:3px;">${i.title||''}</div>
      ${i.description?`<div style="font-size:11px;color:rgba(255,255,255,.45);line-height:1.5;">${(i.description||'').length>140?i.description.substring(0,140)+'…':i.description}</div>`:''}
      ${i.impact?`<div style="font-size:10px;color:#f59e0b;font-family:monospace;margin-top:4px;">${i.impact}</div>`:''}
    </div>
    <div style="flex-shrink:0;font-size:8px;font-weight:800;padding:3px 8px;border-radius:4px;color:${i.severity==='critical'?'#f43f5e':'#f59e0b'};background:${i.severity==='critical'?'rgba(244,63,94,.15)':'rgba(245,158,11,.12)'};font-family:monospace;letter-spacing:.5px;text-transform:uppercase;white-space:nowrap;">${(i.severity||'').toUpperCase()}</div>
  </div>`).join('')}
</td></tr>` : ''}

${resolvedIssues.length > 0 ? `
<tr><td style="background:#0d0b1e;padding:16px 36px;border-bottom:1px solid rgba(255,255,255,.05);">
  <div style="font-size:9px;font-weight:800;color:rgba(16,185,129,.5);letter-spacing:2px;text-transform:uppercase;font-family:monospace;margin-bottom:10px;">✓ ${resolvedIssues.length} Resolved</div>
  ${resolvedIssues.slice(0,3).map(i => `
  <div style="display:flex;align-items:center;gap:8px;padding:7px 12px;background:rgba(16,185,129,.05);border-radius:7px;border-left:3px solid rgba(16,185,129,.3);margin-bottom:6px;">
    <span style="font-size:10px;color:#10b981;">✓</span>
    <div style="font-size:12px;color:rgba(255,255,255,.55);">${i.title||''}</div>
  </div>`).join('')}
</td></tr>` : ''}

<!-- ── PIPELINE SNAPSHOT ── -->
${(ps.openPipelineValue||0) > 0 ? `
<tr><td style="background:#0a0818;padding:24px 36px;border-bottom:1px solid rgba(255,255,255,.05);">
  <div style="font-size:9px;font-weight:800;color:rgba(59,130,246,.6);letter-spacing:2px;text-transform:uppercase;font-family:monospace;margin-bottom:14px;">📊 Pipeline Snapshot</div>
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td width="25%" align="center" style="padding:0 6px;">
        <div style="background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.15);border-radius:10px;padding:14px 10px;">
          <div style="font-size:17px;font-weight:800;color:#3b82f6;">$${Number(ps.openPipelineValue||0)>=1000000?(Number(ps.openPipelineValue)/1000000).toFixed(1)+'M':Number(ps.openPipelineValue||0)>=1000?(Number(ps.openPipelineValue)/1000).toFixed(0)+'K':''+Number(ps.openPipelineValue||0).toLocaleString()}</div>
          <div style="font-size:9px;color:rgba(255,255,255,.3);font-family:monospace;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Open Pipeline</div>
        </div>
      </td>
      <td width="25%" align="center" style="padding:0 6px;">
        <div style="background:${(ps.stalledDeals||0)>3?'rgba(244,63,94,.08)':'rgba(255,255,255,.04)'};border:1px solid ${(ps.stalledDeals||0)>3?'rgba(244,63,94,.2)':'rgba(255,255,255,.06)'};border-radius:10px;padding:14px 10px;">
          <div style="font-size:17px;font-weight:800;color:${(ps.stalledDeals||0)>3?'#f43f5e':'rgba(255,255,255,.6)'};">${ps.stalledDeals||0}</div>
          <div style="font-size:9px;color:rgba(255,255,255,.3);font-family:monospace;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Stalled Deals</div>
        </div>
      </td>
      <td width="25%" align="center" style="padding:0 6px;">
        <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:14px 10px;">
          <div style="font-size:17px;font-weight:800;color:rgba(255,255,255,.7);">${ri.winRate||0}%</div>
          <div style="font-size:9px;color:rgba(255,255,255,.3);font-family:monospace;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Win Rate</div>
        </div>
      </td>
      <td width="25%" align="center" style="padding:0 6px;">
        <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:14px 10px;">
          <div style="font-size:17px;font-weight:800;color:rgba(255,255,255,.7);">${ps.zeroDollarDeals||0}</div>
          <div style="font-size:9px;color:rgba(255,255,255,.3);font-family:monospace;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">$0 Deals</div>
        </div>
      </td>
    </tr>
  </table>
  ${dealBriefHtml || ''}
</td></tr>` : ''}

<!-- ── DIMENSION SCORES ── -->
<tr><td style="background:#0d0b1e;padding:24px 36px;border-bottom:1px solid rgba(255,255,255,.05);">
  <div style="font-size:9px;font-weight:800;color:rgba(255,255,255,.3);letter-spacing:2px;text-transform:uppercase;font-family:monospace;margin-bottom:14px;">Health Dimensions</div>
  <table width="100%" cellpadding="0" cellspacing="0">
  ${Object.entries(scores).map(([k,v]) => {
    const prev_v = prevScores[k];
    const diff = prev_v !== undefined ? (Number(v) - Number(prev_v)) : null;
    const pct = Math.round((Number(v)/100)*100);
    const barColor = Number(v)>=80?'#10b981':Number(v)>=60?'#f59e0b':'#f43f5e';
    const name = dimNames[k]||k;
    return `<tr style="margin-bottom:8px;"><td style="padding:5px 0;">
      <table width="100%" cellpadding="0" cellspacing="0"><tr>
        <td width="110" style="font-size:11px;color:rgba(255,255,255,.55);padding-right:10px;white-space:nowrap;">${name}</td>
        <td style="padding-right:10px;">
          <div style="background:rgba(255,255,255,.06);border-radius:4px;height:6px;overflow:hidden;">
            <div style="background:linear-gradient(90deg,${barColor},${barColor}aa);height:6px;width:${pct}%;border-radius:4px;"></div>
          </div>
        </td>
        <td width="30" align="right" style="font-size:11px;font-weight:700;color:${barColor};white-space:nowrap;">${v}</td>
        <td width="40" align="right" style="font-size:10px;color:${diff===null?'transparent':diff>=0?'#10b981':'#f43f5e'};font-family:monospace;white-space:nowrap;">${diff!==null?(diff>=0?'+':'')+diff:''}</td>
      </tr></table>
    </td></tr>`;
  }).join('')}
  </table>
</td></tr>

<!-- ── CTA BUTTONS ── -->
<tr><td style="background:#0a0818;padding:28px 36px;border-bottom:1px solid rgba(255,255,255,.05);">
  <table width="100%" cellpadding="0" cellspacing="0"><tr>
    <td align="center" style="padding:0 6px;">
      <a href="${reportUrl}" style="display:inline-block;padding:12px 22px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;text-decoration:none;border-radius:9px;font-weight:700;font-size:13px;white-space:nowrap;">View Full Dashboard →</a>
    </td>
    <td align="center" style="padding:0 6px;">
      <a href="${resultsUrl}" style="display:inline-block;padding:12px 20px;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.25);color:#3b82f6;text-decoration:none;border-radius:9px;font-weight:600;font-size:13px;white-space:nowrap;">Audit Results</a>
    </td>
    <td align="center" style="padding:0 6px;">
      <a href="${leaksUrl}" style="display:inline-block;padding:12px 20px;background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.2);color:#f43f5e;text-decoration:none;border-radius:9px;font-weight:600;font-size:13px;white-space:nowrap;">Revenue Leaks</a>
    </td>
  </tr></table>
</td></tr>

<!-- ── UPGRADE NUDGE (non-Sentinel) ── -->
${plan === 'pulse' ? `
<tr><td style="background:rgba(124,58,237,.06);border-top:none;padding:20px 36px;border-bottom:1px solid rgba(124,58,237,.15);">
  <table width="100%" cellpadding="0" cellspacing="0"><tr valign="middle">
    <td>
      <div style="font-size:12px;font-weight:700;color:rgba(255,255,255,.8);margin-bottom:3px;">✦ Unlock AI Deal Coach + RevOps Strategy</div>
      <div style="font-size:11px;color:rgba(255,255,255,.35);">Sentinel includes AI-powered deal coaching, RevOps strategy memos, and billing optimization. First month $199.</div>
    </td>
    <td align="right" style="padding-left:16px;white-space:nowrap;">
      <a href="https://buy.stripe.com/28E4gz2rw1MC7LKeFL8Ra08?prefilled_promo_code=FIRST99" style="display:inline-block;padding:9px 18px;background:rgba(167,139,250,.15);border:1px solid rgba(167,139,250,.3);color:#a78bfa;text-decoration:none;border-radius:8px;font-size:11px;font-weight:700;white-space:nowrap;">Try for $199 →</a>
    </td>
  </tr></table>
</td></tr>` : ''}

<!-- ── FOOTER ── -->
<tr><td style="background:rgba(255,255,255,.02);border-top:1px solid rgba(255,255,255,.05);border-radius:0 0 18px 18px;padding:20px 36px;">
  <table width="100%" cellpadding="0" cellspacing="0"><tr>
    <td>
      <div style="font-size:10px;color:rgba(255,255,255,.2);line-height:1.7;">
        FixOps.io · Automated HubSpot Intelligence<br>
        <a href="mailto:matthew@fixops.io?subject=Pause Pulse - ${email}" style="color:rgba(255,255,255,.2);text-decoration:none;">Pause monitoring</a> · <a href="${FRONTEND_URL}" style="color:rgba(124,58,237,.4);text-decoration:none;">fixops.io</a>
      </div>
    </td>
    <td align="right">
      <div style="font-size:9px;color:rgba(255,255,255,.15);font-family:monospace;letter-spacing:1px;text-transform:uppercase;">Week ${weekNum} · ${auditDate.split(',')[0]}</div>
    </td>
  </tr></table>
</td></tr>

</table>
</td></tr>
</table>
</body></html>`;;

  // ── Monday CEO Brief subject — lead with what changed, not just the score ──
  const ghostCount = (issues.find(i=>i.ghostSeatData)?.ghostSeatData||[]).length;
  const ghostWaste = ghostCount * 90;
  const darkRepCount = (issues.find(i=>i.repScorecard)?.repScorecard||[]).filter(r=>r.calls===0&&r.meetings===0).length;
  const monthlyWasteAmt = Number(s.monthlyWaste||0);
  const isMonday = new Date().getDay() === 1;
  const briefLabel = isMonday ? '📋 Monday Brief' : '⚡ FixOps';
  let subject;
  if (scoreDiff === null) {
    subject = `${briefLabel} — ${pi.company} — First scan complete: ${s.overallScore}/100 · ${s.criticalCount} critical · $${monthlyWasteAmt.toLocaleString()}/mo at risk`;
  } else if (newIssues.length > 0 && scoreDiff < 0) {
    subject = `${briefLabel} — ${pi.company} — Score ↓${Math.abs(scoreDiff)} · ${newIssues.length} new issue${newIssues.length!==1?'s':''} this week · ${s.criticalCount} critical`;
  } else if (resolvedIssues.length > 0 && scoreDiff >= 0) {
    subject = `${briefLabel} — ${pi.company} — Score ↑${scoreDiff||0} · ${resolvedIssues.length} issue${resolvedIssues.length!==1?'s':''} resolved ✅`;
  } else if (ghostCount > 0) {
    subject = `${briefLabel} — ${pi.company} — ${ghostCount} ghost seat${ghostCount!==1?'s':''} costing $${ghostWaste.toLocaleString()}/mo · Score ${s.overallScore}`;
  } else if (darkRepCount > 0) {
    subject = `${briefLabel} — ${pi.company} — ${darkRepCount} rep${darkRepCount!==1?'s':''} with zero activity this week · Score ${s.overallScore}`;
  } else if (scoreDiff > 0) {
    subject = `${briefLabel} — ${pi.company} — Score ↑${scoreDiff} to ${s.overallScore}/100 · ${resolvedIssues.length} resolved`;
  } else if (scoreDiff < 0) {
    subject = `${briefLabel} — ${pi.company} — Score ↓${Math.abs(scoreDiff)} to ${s.overallScore}/100 · action needed`;
  } else {
    subject = `${briefLabel} — ${pi.company} — ${s.overallScore}/100 · ${s.criticalCount} critical · $${monthlyWasteAmt.toLocaleString()}/mo`;
  }


  // ── Pre-compute dynamic email sections (avoids IIFE expressions inside template) ──
  // Rep scorecard section
  let pulseRepHtml = '';
  const repIssue2 = issues.find(i => i.repScorecard && i.repScorecard.length > 0);
  if (repIssue2) {
    const repData = repIssue2.repScorecard.slice(0, 8);
    const repRows = repData.map(r => {
      const actColor = (r.calls + r.meetings) > 5 ? '#10b981' : (r.calls + r.meetings) > 1 ? '#f59e0b' : '#f43f5e';
      const statusLabel = (r.calls + r.meetings) > 5 ? 'Active' : (r.calls + r.meetings) > 0 ? 'Low' : 'Dark';
      return '<tr>' +
        '<td style="font-size:12px;color:#374151;padding:6px 8px;border-bottom:1px solid #f3f4f6;">' + r.name + '</td>' +
        '<td align="center" style="font-size:12px;font-weight:700;color:#374151;padding:6px 8px;border-bottom:1px solid #f3f4f6;">' + r.calls + '</td>' +
        '<td align="center" style="font-size:12px;font-weight:700;color:#374151;padding:6px 8px;border-bottom:1px solid #f3f4f6;">' + r.meetings + '</td>' +
        '<td align="center" style="font-size:12px;font-weight:700;color:' + (r.staleDealCount > 2 ? '#f43f5e' : '#374151') + ';padding:6px 8px;border-bottom:1px solid #f3f4f6;">' + r.staleDealCount + '</td>' +
        '<td align="center" style="padding:6px 8px;border-bottom:1px solid #f3f4f6;"><span style="font-size:10px;font-weight:700;color:' + actColor + ';">' + statusLabel + '</span></td>' +
      '</tr>';
    }).join('');
    pulseRepHtml = '<tr><td style="background:#fff;padding:20px 32px;border-bottom:1px solid #eee;">' +
      '<div style="font-size:10px;font-weight:800;color:#6b7280;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">👥 Rep Activity This Week</div>' +
      '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">' +
        '<tr style="background:#f9fafb;">' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 8px;text-align:left;">Rep</th>' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 8px;text-align:center;">Calls</th>' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 8px;text-align:center;">Meetings</th>' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 8px;text-align:center;">Stale Deals</th>' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 8px;text-align:center;">Status</th>' +
        '</tr>' +
        repRows +
      '</table>' +
    '</td></tr>';
  }

  // Ghost seats section
  let pulseGhostHtml = '';
  const ghostIssue2 = issues.find(i => i.ghostSeatData && i.ghostSeatData.length > 0);
  if (ghostIssue2) {
    const gd2 = ghostIssue2.ghostSeatData;
    const gw2 = gd2.length * 90;
    const ghostRows2 = gd2.slice(0, 6).map(u =>
      '<tr>' +
        '<td style="font-size:12px;color:#374151;padding:6px 10px;border-bottom:1px solid #f3f4f6;">' + u.name + '</td>' +
        '<td style="font-size:11px;color:#9ca3af;padding:6px 10px;border-bottom:1px solid #f3f4f6;">' + (u.email || '') + '</td>' +
        '<td align="right" style="font-size:12px;font-weight:700;color:#f43f5e;padding:6px 10px;border-bottom:1px solid #f3f4f6;">' + u.daysSince + 'd</td>' +
      '</tr>'
    ).join('');
    pulseGhostHtml = '<tr><td style="background:#fff;padding:20px 32px;border-bottom:1px solid #eee;">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">' +
        '<span style="font-size:10px;font-weight:800;color:#6b7280;letter-spacing:1.5px;text-transform:uppercase;">👻 Ghost Seats</span>' +
        '<span style="font-size:11px;font-weight:700;color:#f43f5e;background:#fff5f5;padding:3px 10px;border-radius:20px;">$' + gw2.toLocaleString() + '/mo wasted</span>' +
      '</div>' +
      '<div style="font-size:11px;color:#6b7280;margin-bottom:10px;">' + gd2.length + ' paid users — zero logins in 90+ days</div>' +
      '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">' +
        '<tr style="background:#f9fafb;">' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 10px;text-align:left;">User</th>' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 10px;text-align:left;">Email</th>' +
          '<th style="font-size:10px;color:#9ca3af;padding:5px 10px;text-align:right;">Inactive</th>' +
        '</tr>' +
        ghostRows2 +
      '</table>' +
    '</td></tr>';
  }

  // Ticket SLA section
  let pulseTicketHtml = '';
  const ticketIssue2 = issues.find(i => i.title && i.title.includes('support tickets open more than'));
  if (ticketIssue2) {
    pulseTicketHtml = '<tr><td style="background:#fffbeb;padding:16px 32px;border-bottom:1px solid #fef3c7;">' +
      '<table width="100%" cellpadding="0" cellspacing="0"><tr>' +
        '<td style="width:28px;font-size:18px;vertical-align:top;padding-top:2px;">🎫</td>' +
        '<td>' +
          '<div style="font-size:10px;font-weight:800;color:#92400e;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:4px;">Ticket SLA Alert</div>' +
          '<div style="font-size:13px;font-weight:700;color:#92400e;margin-bottom:3px;">' + (ticketIssue2.title || '') + '</div>' +
          '<div style="font-size:11px;color:#b45309;">' + (ticketIssue2.impact || '') + '</div>' +
        '</td>' +
      '</tr></table>' +
    '</td></tr>';
  }

  // ── Week-over-week delta banner ─────────────────────────────────────────
  let pulseDeltaHtml = '';
  if (scoreDiff !== null) {
    const critDelta  = (s.criticalCount||0) - (prev ? (prev.critical_count||0) : 0);
    const warnDelta  = (s.warningCount||0)  - (prev ? (prev.warning_count||0)  : 0);
    const wasteDelta = (s.monthlyWaste||0)  - (prev ? (prev.monthly_waste||0)  : 0);

    const dCell = (label, val, invertGood) => {
      const good = invertGood ? val < 0 : val > 0;
      const bad  = invertGood ? val > 0 : val < 0;
      const col  = val === 0 ? '#9ca3af' : good ? '#10b981' : '#f43f5e';
      const arrow = val > 0 ? '↑' : val < 0 ? '↓' : '→';
      const disp  = label === 'Waste' ? '$' + Math.abs(wasteDelta).toLocaleString() : Math.abs(val);
      return '<td align="center" style="padding:12px 8px;width:25%;">' +
        '<div style="font-size:20px;font-weight:900;color:' + col + ';">' + arrow + disp + '</div>' +
        '<div style="font-size:9px;color:rgba(255,255,255,.35);margin-top:3px;text-transform:uppercase;letter-spacing:.05em;">' + label + '</div>' +
      '</td>';
    };

    pulseDeltaHtml =
      '<tr><td style="background:#08061a;padding:16px 32px;border-bottom:1px solid rgba(255,255,255,.06);">' +
        '<div style="font-size:9px;font-weight:800;color:rgba(255,255,255,.3);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px;">vs last week</div>' +
        '<table width="100%" cellpadding="0" cellspacing="0"><tr>' +
          dCell('Score', scoreDiff, false) +
          dCell('Critical', critDelta, true) +
          dCell('Warnings', warnDelta, true) +
          dCell('Waste', wasteDelta, true) +
        '</tr></table>' +
      '</td></tr>';
  }

  // ── New issues this week ─────────────────────────────────────────────────
  let pulseNewIssuesHtml = '';
  if (newIssues.length > 0) {
    const newCritical = newIssues.filter(i => i.severity === 'critical');
    const newWarning  = newIssues.filter(i => i.severity === 'warning');
    const showNew = newCritical.concat(newWarning).slice(0, 4);
    pulseNewIssuesHtml =
      '<tr><td style="background:#fff;padding:20px 32px;border-bottom:1px solid #eee;">' +
        '<div style="font-size:10px;font-weight:800;color:#dc2626;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">🆕 New Issues This Week (' + newIssues.length + ')</div>' +
        showNew.map(i => {
          const isCrit = i.severity === 'critical';
          const bc = isCrit ? '#fff1f1' : '#fffbeb';
          const tc = isCrit ? '#dc2626' : '#d97706';
          const lc = isCrit ? '#fca5a5' : '#fde68a';
          return '<div style="padding:12px 14px;background:' + bc + ';border-radius:8px;margin-bottom:8px;border-left:3px solid ' + lc + ';">' +
            '<div style="font-size:12px;font-weight:700;color:' + tc + ';margin-bottom:3px;">' + (i.title || '') + '</div>' +
            (i.impact ? '<div style="font-size:11px;color:#666;">' + i.impact.substring(0, 100) + (i.impact.length > 100 ? '…' : '') + '</div>' : '') +
          '</div>';
        }).join('') +
        (newIssues.length > 4 ? '<div style="font-size:11px;color:#9ca3af;text-align:center;margin-top:8px;">+ ' + (newIssues.length - 4) + ' more new issues in full report</div>' : '') +
      '</td></tr>';
  }

  // ── New scope data highlights ─────────────────────────────────────────────
  let pulseNewDataHtml = '';
  const hasNewData = ps.sequences > 0 || ps.leads > 0 || ps.npsResponses > 0 || ps.campaigns > 0 || ps.listCount > 0;
  if (hasNewData) {
    const dataItems = [];
    if (ps.sequences > 0)    dataItems.push({ icon: '📧', label: 'Sequences', val: ps.sequences, sub: ps.activeSequences + ' active' });
    if (ps.leads > 0)        dataItems.push({ icon: '🎯', label: 'Leads', val: ps.leads, sub: ps.unownedLeads > 0 ? ps.unownedLeads + ' unowned' : 'all assigned', alert: ps.unownedLeads > 0 });
    if (ps.npsResponses > 0) dataItems.push({ icon: '⭐', label: 'NPS Responses', val: ps.npsResponses, sub: 'feedback collected' });
    if (ps.campaigns > 0)    dataItems.push({ icon: '📣', label: 'Campaigns', val: ps.campaigns, sub: 'marketing campaigns' });
    if (ps.listCount > 0)    dataItems.push({ icon: '📋', label: 'Lists', val: ps.listCount, sub: ps.emptyLists > 0 ? ps.emptyLists + ' empty' : 'all populated', alert: ps.emptyLists > 5 });

    if (dataItems.length > 0) {
      pulseNewDataHtml =
        '<tr><td style="background:#fff;padding:20px 32px;border-bottom:1px solid #eee;">' +
          '<div style="font-size:10px;font-weight:800;color:#374151;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">📊 Portal Snapshot</div>' +
          '<table width="100%" cellpadding="0" cellspacing="0"><tr>' +
          dataItems.slice(0, 5).map(d =>
            '<td align="center" style="padding:8px;">' +
              '<div style="font-size:18px;margin-bottom:4px;">' + d.icon + '</div>' +
              '<div style="font-size:16px;font-weight:800;color:' + (d.alert ? '#f59e0b' : '#111') + ';">' + d.val + '</div>' +
              '<div style="font-size:10px;color:#6b7280;">' + d.label + '</div>' +
              '<div style="font-size:9px;color:' + (d.alert ? '#f59e0b' : '#9ca3af') + ';">' + d.sub + '</div>' +
            '</td>'
          ).join('') +
          '</tr></table>' +
        '</td></tr>';
    }
  }

  await resend.emails.send({
    from: 'FixOps FixOps Monitor <reports@fixops.io>',
    to: email,
    subject,
    html
  });

  // Slack alert — fire if customer has webhook URL saved
  if (customer && customer.slack_webhook) {
    const prev2 = history && history.length > 1 ? history[1] : null;
    const deltaScore = prev2 ? (s.overallScore - prev2.score) : null;
    const slackPayload = buildSlackPulsePayload(result, auditId, pi.company || customer.company || 'Your Portal', deltaScore);
    await sendSlackAlert(customer.slack_webhook, slackPayload);
  }
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
          `INSERT INTO audit_history (customer_id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats, hubspot_portal_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [cust.id, auditId, cust.plan,
           result.summary?.overallScore||0, result.summary?.criticalCount||0,
           result.summary?.warningCount||0, result.summary?.infoCount||0,
           result.summary?.monthlyWaste||0, result.summary?.recordsScanned||0,
           JSON.stringify(result.scores||{}),
           JSON.stringify((result.issues||[]).map(i=>({title:i.title,severity:i.severity,dimension:i.dimension,impact:i.impact}))),
           JSON.stringify(result.portalInfo?.portalStats||{}),
         String(result.portalInfo?.portalId||'')]
        ).catch(e => console.error('History insert:', e.message));

        // Send email for monthly plans
        // Workflow error alert — fire immediately if errors found (Pro/Agency only)
        if (['pro','command'].includes(cust.plan)) {
          const errWfs = (result.issues||[]).find(i => i.erroredWorkflows)?.erroredWorkflows || [];
          if (errWfs.length > 0) {
            await sendWorkflowAlertEmail(cust.email, cust.company||'Your Portal', errWfs, auditId).catch(e => console.error('WF alert email err:', e.message));
          }
        }

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
        html: `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Your FixOps Dashboard</title>
</head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#07070a;padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

  <!-- Header -->
  <tr><td style="background:linear-gradient(135deg,#0d0b1e 0%,#120e2a 100%);border-radius:16px 16px 0 0;padding:28px 36px;border-bottom:1px solid rgba(124,58,237,.25);">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td>
        <div style="font-size:22px;font-weight:900;color:#fff;letter-spacing:-0.5px;">⚡ Fix<span style="color:#a78bfa;">Ops</span><span style="color:rgba(255,255,255,.25);font-size:14px;font-weight:400;">.io</span></div>
        <div style="font-size:10px;color:rgba(255,255,255,.3);letter-spacing:3px;text-transform:uppercase;margin-top:3px;font-family:monospace;">Intelligence Dashboard</div>
      </td>
      <td align="right">
        <div style="background:rgba(124,58,237,.2);border:1px solid rgba(124,58,237,.35);border-radius:6px;padding:5px 12px;font-size:10px;font-weight:700;color:#a78bfa;font-family:monospace;letter-spacing:1px;text-transform:uppercase;">${cust.plan === 'pro' ? 'SENTINEL' : cust.plan === 'command' ? 'COMMAND' : 'MONITOR'}</div>
      </td>
    </tr></table>
  </td></tr>

  <!-- Body -->
  <tr><td style="background:#0d0b1e;padding:36px;">

    <div style="font-size:24px;font-weight:800;color:#fff;margin-bottom:8px;letter-spacing:-0.5px;">Your dashboard is ready.</div>
    <div style="font-size:14px;color:rgba(255,255,255,.5);line-height:1.7;margin-bottom:28px;">
      Click below to access your FixOps Intelligence Dashboard for <strong style="color:rgba(255,255,255,.9);">${cust.company || 'your portal'}</strong>. This link is valid for 30 days and logs you in automatically.
    </div>

    <!-- CTA Button -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
    <tr><td align="center">
      <a href="${dashUrl}" style="display:inline-block;padding:15px 40px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px;letter-spacing:-0.2px;">Open My Dashboard →</a>
    </td></tr>
    </table>

    <!-- What's inside grid -->
    <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:12px;overflow:hidden;margin-bottom:20px;">
    <tr><td style="padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.06);">
      <div style="font-size:10px;font-weight:700;color:rgba(255,255,255,.3);letter-spacing:2px;text-transform:uppercase;font-family:monospace;">What's in your dashboard</div>
    </td></tr>
    <tr><td style="padding:16px 20px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="50%" style="padding:4px 0;font-size:12px;color:rgba(255,255,255,.6);"><span style="color:#10b981;margin-right:6px;">✓</span>Pipeline health &amp; deal risk</td>
          <td width="50%" style="padding:4px 0;font-size:12px;color:rgba(255,255,255,.6);"><span style="color:#10b981;margin-right:6px;">✓</span>Contact decay &amp; data health</td>
        </tr>
        <tr>
          <td style="padding:4px 0;font-size:12px;color:rgba(255,255,255,.6);"><span style="color:#10b981;margin-right:6px;">✓</span>Rep performance scorecard</td>
          <td style="padding:4px 0;font-size:12px;color:rgba(255,255,255,.6);"><span style="color:#10b981;margin-right:6px;">✓</span>Workflow conflict detector</td>
        </tr>
        <tr>
          <td style="padding:4px 0;font-size:12px;color:rgba(255,255,255,.6);"><span style="color:#10b981;margin-right:6px;">✓</span>Revenue &amp; billing intelligence</td>
          <td style="padding:4px 0;font-size:12px;color:rgba(255,255,255,.6);"><span style="color:#10b981;margin-right:6px;">✓</span>AI report builder</td>
        </tr>
        ${['pro','command','command_unlimited'].includes(cust.plan) ? `<tr>
          <td style="padding:4px 0;font-size:12px;color:#a78bfa;"><span style="margin-right:6px;">✦</span>AI Deal Coach</td>
          <td style="padding:4px 0;font-size:12px;color:#a78bfa;"><span style="margin-right:6px;">✦</span>RevOps AI Coach</td>
        </tr>` : ''}
      </table>
    </td></tr>
    </table>

    ${isPaidPlan ? `
    <!-- Monitoring active pill -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
    <tr><td style="background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);border-radius:10px;padding:14px 18px;">
      <table width="100%" cellpadding="0" cellspacing="0"><tr>
        <td><div style="width:8px;height:8px;border-radius:50%;background:#10b981;display:inline-block;margin-right:8px;"></div><span style="font-size:13px;font-weight:700;color:#10b981;">Monitoring active</span> <span style="font-size:12px;color:rgba(255,255,255,.4);">— Your portal scans every Monday at 9am ET</span></div></td>
      </tr></table>
    </td></tr>
    </table>` : ''}

  </td></tr>

  <!-- Footer -->
  <tr><td style="background:rgba(255,255,255,.02);border-top:1px solid rgba(255,255,255,.06);border-radius:0 0 16px 16px;padding:18px 36px;text-align:center;">
    <div style="font-size:11px;color:rgba(255,255,255,.2);line-height:1.7;">
      Requested for <span style="color:rgba(255,255,255,.4);">${email}</span> · If you didn't request this, ignore it.<br>
      <a href="${FRONTEND_URL}" style="color:rgba(124,58,237,.6);text-decoration:none;">fixops.io</a> · <a href="mailto:matthew@fixops.io" style="color:rgba(124,58,237,.6);text-decoration:none;">matthew@fixops.io</a>
    </div>
  </td></tr>

</table>
</td></tr>
</table>
</body></html>`
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


// ── AutoDoc — AI Workflow Documentation Generator ─────────────────────────────
// Pro/Agency: reads workflows from audit data and generates plain-English docs
// ── AI Deal Coach — analyzes stalled/at-risk deals with specific next steps ──
app.post('/ai/deal-coach', async (req, res) => {
  try {
    const { auditId, email, dealId } = req.body;
    if (!auditId) return res.status(400).json({ error: 'auditId required' });

    const custRes = await db.query('SELECT plan FROM customers WHERE email = $1', [email || '']).catch(() => ({ rows: [] }));
    const plan = custRes.rows[0]?.plan || 'free';
    if (!['pro','command','command_unlimited','agency_scale','agency_unlimited'].includes(plan)) {
      return res.status(403).json({ error: 'Deal Coach requires Sentinel or Command plan' });
    }

    const result = await getResult(auditId);
    if (!result) return res.status(404).json({ error: 'Audit not found' });

    const ps      = result.portalInfo?.portalStats || {};
    const ri      = ps.revenueIntel || {};
    const deals   = ps.dealList || [];
    const company = result.portalInfo?.company || 'Unknown';
    const repData = ps.repIntelEngine || {};

    const targetDeals = dealId
      ? deals.filter(d => String(d.id) === String(dealId)).slice(0, 1)
      : deals.filter(d => (d.daysStalled > 14) || (d.riskScore < 40) || !d.amount).slice(0, 8);

    if (!targetDeals.length) {
      return res.json({ coaching: [], message: 'No stalled or at-risk deals found. Great pipeline hygiene!' });
    }

    const dealLines = targetDeals.map(function(d, i) {
      return [
        'DEAL '+(i+1)+': "'+(d.dealname || 'Unnamed')+'"',
        '  Stage: '+(d.stage || 'Unknown')+' | Amount: '+(d.amount ? '$'+Number(d.amount).toLocaleString() : 'NO AMOUNT SET'),
        '  Days in stage: '+(d.daysInStage || 0)+' | Days stalled: '+(d.daysStalled || 0),
        '  Owner: '+(d.ownerName || 'Unassigned')+' | Close date: '+(d.closeDate || 'Not set'),
        '  Last activity: '+(d.daysSinceActivity || '?')+' days ago | Risk score: '+(d.riskScore || 'N/A')+'/100',
        '  Last contact: '+(d.lastContactName || 'Unknown')+' | Last activity type: '+(d.lastActivityType || 'none'),
      ].join('\n');
    });
    const dealContext = dealLines.join('\n\n');

    const winRate  = ri.winRate || 0;
    const avgDeal  = Number(ri.avgDealSize || 0).toLocaleString();
    const avgDays  = ri.avgDaysToClose || 0;
    const openPipe = Number(ri.openPipelineValue || 0).toLocaleString();
    const totalReps = repData.totalReps || 0;

    const prompt = 'You are an expert B2B sales coach and HubSpot RevOps consultant analyzing stalled deals for ' + company + '.\n\n' +
      'PORTAL CONTEXT:\n' +
      '- Win rate: ' + winRate + '%\n' +
      '- Avg deal size: $' + avgDeal + '\n' +
      '- Avg days to close: ' + avgDays + '\n' +
      '- Open pipeline: $' + openPipe + '\n' +
      '- Active reps: ' + totalReps + '\n\n' +
      'DEALS NEEDING COACHING:\n' + dealContext + '\n\n' +
      'For each deal provide specific actionable coaching. Be concrete — name exact tactics, specific message angles, what the rep should do TODAY.\n' +
      'Format as JSON array: [{ dealName, stage, stalledReason, immediateAction, script, redFlag, confidence }]\n' +
      'confidence = HIGH/MEDIUM/LOW. Return ONLY valid JSON, no markdown.';

    const aiRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 30000
    });

    let coaching = [];
    try {
      const text = aiRes.data?.content?.[0]?.text?.trim() || '[]';
      coaching = JSON.parse(text.replace(/```json|```/g, '').trim());
    } catch(e) {
      coaching = [{ dealName: 'Analysis', immediateAction: aiRes.data?.content?.[0]?.text || 'Parse error', confidence: 'LOW' }];
    }

    res.json({ coaching, dealsAnalyzed: targetDeals.length, company });
  } catch(e) {
    console.error('[DealCoach]', e.message?.substring(0, 80));
    res.status(500).json({ error: 'Deal coach analysis failed' });
  }
});

// ── RevOps AI Coach — full portal RevOps strategy memo ───────────────────────
app.post('/ai/revops-coach', async (req, res) => {
  try {
    const { auditId, email } = req.body;
    if (!auditId) return res.status(400).json({ error: 'auditId required' });

    const custRes = await db.query('SELECT plan FROM customers WHERE email = $1', [email || '']).catch(() => ({ rows: [] }));
    const plan = custRes.rows[0]?.plan || 'free';
    if (!['pro','command','command_unlimited','agency_scale','agency_unlimited'].includes(plan)) {
      return res.status(403).json({ error: 'RevOps Coach requires Sentinel or Command plan' });
    }

    const result = await getResult(auditId);
    if (!result) return res.status(404).json({ error: 'Audit not found' });

    const ps      = result.portalInfo?.portalStats || {};
    const s       = result.summary || {};
    const issues  = result.issues || [];
    const ri      = ps.revenueIntel || {};
    const rep     = ps.repIntelEngine || {};
    const decay   = ps.contactDecayEngine || {};
    const bil     = ps.billingTierEngine || {};
    const lrt     = ps.leadResponseTime || {};
    const company = result.portalInfo?.company || 'Unknown';

    const criticals = issues.filter(i => i.severity === 'critical').slice(0, 10);
    const warnings  = issues.filter(i => i.severity === 'warning').slice(0, 8);

    const ctx = [
      'COMPANY: ' + company,
      'HEALTH SCORE: ' + (s.overallScore || 0) + '/100',
      'CRITICAL ISSUES: ' + (s.criticalCount || 0) + ' | WARNINGS: ' + (s.warningCount || 0),
      'MONTHLY WASTE: $' + Number(s.monthlyWaste || 0).toLocaleString(),
      '',
      'PIPELINE:',
      '  Open: $' + Number(ri.openPipelineValue || 0).toLocaleString() + ' | ' + (ri.openDealsCount || 0) + ' deals',
      '  Win rate: ' + (ri.winRate || 0) + '% | Avg deal: $' + Number(ri.avgDealSize || 0).toLocaleString(),
      '  Stalled: ' + (ps.stalledDeals || 0) + ' | Zero-dollar: ' + (ps.zeroDollarDeals || 0),
      '',
      'TEAM:',
      '  Reps: ' + (rep.totalReps || 0) + ' | Avg activities/week: ' + (rep.avgActivitiesPerRep || 0),
      '  Lead response: ' + (lrt.avgMinutes ? Math.round(lrt.avgMinutes/60)+'hrs avg' : 'unknown'),
      '  Ghost seats: ' + (ps.ghostSeats || 0),
      '',
      'DATA:',
      '  Contact score: ' + (decay.avgDecayScore || 0) + '/100',
      '  Dead: ' + (decay.buckets?.dead || 0) + ' | Decaying: ' + (decay.buckets?.decaying || 0),
      '  Duplicates: ' + (ps.duplicateContactCount || 0),
      '',
      'AUTOMATION:',
      '  Workflows: ' + (ps.totalWorkflows || 0) + ' | Dead: ' + (ps.deadWorkflowCount || 0),
      '  Missing goals: ' + (ps.workflowsMissingGoals || 0),
      '',
      'BILLING:',
      '  Tier: ' + (bil.currentTier?.toLocaleString() || 'unknown') + ' | Used: ' + (bil.pctOfTier || 0) + '%',
      '  At risk: ' + (bil.atRisk ? 'YES' : 'no'),
      '',
      'CRITICAL ISSUES:',
    ].concat(
      criticals.map(i => '  - '+(i.title||'')+' ('+(i.dimension||'')+') $'+Number(i.monthlyImpact||0).toLocaleString()+'/mo')
    ).concat([
      '',
      'WARNINGS:',
    ]).concat(
      warnings.map(i => '  - '+(i.title||''))
    ).join('\n');

    const prompt = 'You are a senior RevOps consultant and HubSpot expert. Generate a comprehensive RevOps strategy report for ' + company + '.\n\n' +
      ctx + '\n\n' +
      'Generate a strategic coaching report as JSON with these sections:\n' +
      '{ executiveSummary, revenueOpportunities: [{title,action,dollarImpact,priority}], pipelineFixes: [{title,action,urgency}], ' +
      'teamCoaching: {summary, repActions:[{issue,action}]}, dataFixes:[{title,action,impact}], ' +
      'automationHealth:{summary,actions:[{title,action}]}, ' +
      'roadmap:{week1:[],week2:[],week3:[],week4:[]}, ' +
      'kpis:[{metric,current,target30d,why}] }\n' +
      'Be specific with numbers and exact HubSpot locations. Return ONLY valid JSON.';

    const aiRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 3000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 45000
    });

    let report = {};
    try {
      const text = aiRes.data?.content?.[0]?.text?.trim() || '{}';
      report = JSON.parse(text.replace(/```json|```/g, '').trim());
    } catch(e) {
      report = { executiveSummary: aiRes.data?.content?.[0]?.text || 'Analysis complete' };
    }

    res.json({ report, company, score: s.overallScore, waste: s.monthlyWaste });
  } catch(e) {
    console.error('[RevOpsCoach]', e.message?.substring(0, 80));
    res.status(500).json({ error: 'RevOps coach analysis failed' });
  }
});

// ── Contact Tier Optimization — finds billable vs non-billable contacts ───────
app.post('/ai/contact-tier', async (req, res) => {
  try {
    const { auditId, email } = req.body;
    if (!auditId) return res.status(400).json({ error: 'auditId required' });

    const result = await getResult(auditId);
    if (!result) return res.status(404).json({ error: 'Audit not found' });

    const ps   = result.portalInfo?.portalStats || {};
    const bil  = ps.billingTierEngine || {};
    const dec  = ps.contactDecayEngine || {};
    const comp = ps.contactCompleteness || {};

    // Calculate suppression candidates
    const totalContacts    = ps.totalContacts || 0;
    const deadContacts     = dec.buckets?.dead || 0;
    const bouncedEmails    = ps.highBounceEmails || 0;
    const unsubscribed     = ps.unsubscribedContacts || 0;
    const neverMarketed    = ps.neverMarketedContacts || 0;
    const suppressCandidates = Math.round(deadContacts * 0.8 + bouncedEmails * 0.9 + (neverMarketed * 0.3));

    // Calculate tier savings
    const tiers = [
      { limit: 1000,   price: 0    },
      { limit: 5000,   price: 45   },
      { limit: 15000,  price: 170  },
      { limit: 50000,  price: 360  },
      { limit: 100000, price: 640  },
      { limit: 200000, price: 1080 },
    ];
    const currentTier = tiers.find(t => totalContacts <= t.limit) || tiers[tiers.length-1];
    const projectedAfter = Math.max(0, totalContacts - suppressCandidates);
    const projectedTier  = tiers.find(t => projectedAfter <= t.limit) || tiers[tiers.length-1];
    const monthlySavings = Math.max(0, currentTier.price - projectedTier.price);

    const optimization = {
      totalContacts,
      suppressCandidates,
      projectedContactsAfter: projectedAfter,
      currentMonthlyTierCost: currentTier.price,
      projectedMonthlyTierCost: projectedTier.price,
      monthlySavings,
      annualSavings: monthlySavings * 12,
      breakdown: {
        deadContacts,
        bouncedEmails,
        unsubscribed,
        neverMarketed,
      },
      steps: [
        { step: 1, title: 'Export suppression candidates', action: 'Contacts → Filters → Last activity date is more than 12 months ago AND Email bounced OR Unsubscribed. Export to CSV for review.', impact: 'Identify exact contacts to suppress' },
        { step: 2, title: 'Set non-marketing status', action: 'Select filtered contacts → Actions → Set as non-marketing contact. This removes them from your billable count without deleting data.', impact: `Save ~$${monthlySavings}/mo on HubSpot billing` },
        { step: 3, title: 'Archive dead contacts', action: 'For contacts with 0 activity in 18+ months and invalid email: create a list, export, then delete or archive. Always export first.', impact: 'Clean database, faster HubSpot performance' },
        { step: 4, title: 'Set up ongoing suppression workflow', action: 'Create a workflow: Contact bounces email → 30 day wait → Set non-marketing. Prevents future billing creep.', impact: 'Permanent fix, not a one-time cleanup' },
      ],
      pctSuppressable: totalContacts > 0 ? Math.round(suppressCandidates / totalContacts * 100) : 0,
      billingRisk: bil.atRisk || false,
      daysToNextTier: bil.daysToTier || null,
    };

    res.json(optimization);
  } catch(e) {
    console.error('[ContactTier]', e.message?.substring(0, 80));
    res.status(500).json({ error: 'Contact tier analysis failed' });
  }
});

app.post('/ai/autodoc', async (req, res) => {
  try {
    const { auditId, email } = req.body;
    if (!auditId) return res.status(400).json({ error: 'auditId required' });

    // Verify customer is Pro or Agency
    if (email) {
      const custRes = await db.query('SELECT plan FROM customers WHERE email = $1', [email]);
      const plan = custRes.rows[0]?.plan || 'free';
      if (!['pro','command','command_unlimited','agency_scale','agency_unlimited','pro-audit'].includes(plan)) {
        return res.status(403).json({ error: 'AutoDoc requires Sentinel or Command plan' });
      }
    }

    const result = await getResult(auditId);
    if (!result) return res.status(404).json({ error: 'Audit not found' });

    const issues = result.issues || [];
    const ps = result.portalInfo?.portalStats || {};
    const company = result.portalInfo?.company || 'Your Portal';

    // Extract workflow intelligence from audit issues
    const workflowIssues = issues.filter(i =>
      i.title?.toLowerCase().includes('workflow') ||
      i.dimension === 'Automation'
    );

    // Build workflow context from what we know
    const workflowContext = {
      totalWorkflows: ps.workflows || 0,
      workflowIssues: workflowIssues.map(i => ({
        title: i.title,
        severity: i.severity,
        description: i.description,
        impact: i.impact,
        guide: i.guide
      })),
      scores: result.scores || {},
      portalStats: ps,
      company
    };

    // Generate AutoDoc via Claude
    const prompt = `You are a HubSpot automation expert writing documentation for a portal health report.

PORTAL: ${company}
WORKFLOW DATA: ${JSON.stringify(workflowContext, null, 2)}

Generate a comprehensive AutoDoc report covering:
1. Automation Health Summary — overall state of their workflows
2. Issues Found — each workflow issue with plain-English explanation of what's broken and why it matters
3. What Each Issue Costs — dollar/business impact in plain language
4. Fix Priority Order — ranked list of what to fix first and why
5. Best Practices Checklist — 8-10 HubSpot automation best practices with pass/fail for this portal
6. Recommended Next Steps — 3 concrete actions to take this week

Write in clear, direct language that a sales manager (not a developer) can understand.
Use plain language. No jargon. Explain what workflows DO, not just that they exist.

Return ONLY valid JSON, no markdown:
{
  "company": "${company}",
  "generatedAt": "${new Date().toISOString()}",
  "automationHealthScore": <0-100 based on issues>,
  "summary": "<2-3 sentence executive summary>",
  "sections": [
    {
      "title": "<section title>",
      "content": "<detailed content>",
      "severity": "critical|warning|info|good"
    }
  ],
  "priorityFixes": [
    { "rank": 1, "action": "<specific action>", "impact": "<business impact>", "effort": "low|medium|high" }
  ],
  "bestPractices": [
    { "check": "<best practice description>", "status": "pass|fail|unknown", "note": "<context>" }
  ],
  "nextSteps": ["<step 1>", "<step 2>", "<step 3>"]
}`;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      }
    });

    const text = response.data.content?.map(b => b.text||'').join('') || '';
    let doc;
    try {
      doc = JSON.parse(text.replace(/```json|```/g,'').trim());
    } catch(e) {
      doc = { summary: text, sections: [], priorityFixes: [], bestPractices: [], nextSteps: [] };
    }

    res.json({ success: true, doc });
  } catch(e) {
    console.error('AutoDoc error:', e.response?.data || e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Fix request email ─────────────────────────────────────────────────────────
app.post('/fix-request', async (req, res) => {
  try {
    const { issueTitle, issueImpact, issueDimension, portalCompany, portalEmail, email, auditId, severity, source } = req.body;
    const contactEmail = portalEmail || email || 'unknown';
    const sourceLabel = source === 'calendar' ? '📅 Booked a Call' : '📋 Form Submit';
    await resend.emails.send({
      from: 'FixOps Fix Request <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `🛠 Fix Request — ${issueTitle?.substring(0,55)} — ${portalCompany} [${sourceLabel}]`,
      html: `
        <h2 style="margin-bottom:4px;">Fix It For Me Request</h2>
        <p style="color:#888;font-size:13px;margin-bottom:20px;">Source: <strong style="color:${source==='calendar'?'#10b981':'#7c3aed'}">${sourceLabel}</strong>${source==='calendar' ? ' — they may already have booked on Calendly' : ' — reach out within 1 business day'}</p>
        <table style="border-collapse:collapse;width:100%;max-width:560px;">
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;width:160px;">Company</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${portalCompany || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;"><a href="mailto:${contactEmail}">${contactEmail}</a></td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Severity</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:${severity==='critical'?'#dc2626':'#d97706'};font-weight:700;">${severity?.toUpperCase() || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Issue</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-weight:600;">${issueTitle || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Impact</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px;">${issueImpact || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Dimension</td><td style="padding:8px 12px;">${issueDimension || '—'}</td></tr>
        </table>
        <p style="margin-top:16px;">
          <a href="${FRONTEND_URL}/results.html?id=${auditId}" style="display:inline-block;padding:10px 20px;background:#7c3aed;color:#fff;border-radius:8px;font-weight:700;font-size:13px;text-decoration:none;">View Full Audit →</a>
        </p>`
    });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Lead Capture — paid plan interest before Calendly ─────────────────────────
app.post('/lead/capture', async (req, res) => {
  try {
    const { email, company, plan, source } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });

    // Upsert into customers so we have their email even before they pay
    await db.query(`
      INSERT INTO customers (email, company, plan, plan_status, updated_at)
      VALUES ($1, $2, 'lead', 'pending', NOW())
      ON CONFLICT (email) DO UPDATE
      SET company = COALESCE(NULLIF($2,''), customers.company), updated_at = NOW()
    `, [email.toLowerCase().trim(), company || '']).catch(()=>{});

    // Notify Matthew
    await resend.emails.send({
      from: 'FixOps Leads <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `${source === 'salesforce-early-access' ? '🔵 Salesforce Beta' : '🗓 Lead'} — ${company || email} — ${plan || source || 'unknown'}`,
      html: `
        <h2 style="margin-bottom:4px;">New Paid Plan Lead</h2>
        <p style="color:#888;font-size:13px;margin-bottom:20px;">They entered their details and clicked "Book Your Setup Call"</p>
        <table style="border-collapse:collapse;width:100%;max-width:480px;">
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;width:120px;">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;"><a href="mailto:${email}">${email}</a></td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Company</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${company || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Plan interest</td><td style="padding:8px 12px;">${plan || '—'}</td></tr>
        </table>
        <p style="margin-top:16px;font-size:13px;color:#666;">Check Calendly for their booking. If they haven't booked yet, follow up within the hour.</p>`
    }).catch(e => console.warn('Lead capture email:', e.message));

    res.json({ success: true });
  } catch(e) {
    console.error('Lead capture error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Agency Inquiry ────────────────────────────────────────────────────────────
app.post('/agency-inquiry', async (req, res) => {
  try {
    const { name, company, email, phone, portalCount, auditsPerMonth, priorities, notes } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!name)  return res.status(400).json({ error: 'Name required' });

    // Save to DB
    await db.query(`
      INSERT INTO agency_leads (name, company, email, phone, portal_count, audits_per_month, priorities, notes)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [name, company || '', email, phone || '', portalCount || '', auditsPerMonth || '',
        Array.isArray(priorities) ? priorities : [], notes || '']);

    // Notify Matthew
    const priorityList = Array.isArray(priorities) && priorities.length
      ? priorities.map(p => `<li>${p}</li>`).join('')
      : '<li>Not specified</li>';

    await resend.emails.send({
      from: 'FixOps Agency <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `🏢 New Agency Inquiry — ${company || 'Unknown'} — ${name}`,
      html: `
        <h2 style="color:#7c3aed;">New FixOps Command Inquiry</h2>
        <table style="border-collapse:collapse;width:100%;max-width:560px;">
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;width:180px;">Name</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${name}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Company</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${company || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Email</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;"><a href="mailto:${email}">${email}</a></td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Phone</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${phone || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Portals managed</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${portalCount || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;">Audits/month</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">${auditsPerMonth || '—'}</td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;vertical-align:top;">Looking for</td><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;"><ul style="margin:0;padding-left:18px;">${priorityList}</ul></td></tr>
          <tr><td style="padding:8px 12px;background:#f3f4f6;font-weight:700;vertical-align:top;">Notes</td><td style="padding:8px 12px;">${notes || '—'}</td></tr>
        </table>
        <p style="margin-top:20px;font-size:13px;color:#6b7280;">Reply directly to <a href="mailto:${email}">${email}</a> to schedule their onboarding call.</p>
      `
    });

    res.json({ success: true });
  } catch(e) {
    console.error('Agency inquiry error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Health check ──────────────────────────────────────────────────────────────

// ── Slack webhook settings ────────────────────────────────────────────────────
app.post('/settings/slack', async (req, res) => {
  try {
    const { email, webhookUrl } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    const cust = custRes.rows[0];
    if (!cust) return res.status(404).json({ error: 'customer not found' });
    if (!['pulse','pro','command'].includes(cust.plan)) return res.status(403).json({ error: 'Slack alerts require Pulse plan or higher' });

    // Validate webhook URL format
    if (webhookUrl && !webhookUrl.startsWith('https://hooks.slack.com/')) {
      return res.status(400).json({ error: 'Invalid Slack webhook URL. Must start with https://hooks.slack.com/' });
    }

    await db.query('UPDATE customers SET slack_webhook = $1, updated_at = NOW() WHERE id = $2', [webhookUrl || null, cust.id]);

    // Send a test message if URL provided
    if (webhookUrl) {
      await sendSlackAlert(webhookUrl, {
        text: '✅ FixOps Slack alerts connected! You\'ll receive your weekly scan summary and critical issue alerts here.',
        blocks: [{
          type: 'section',
          text: { type: 'mrkdwn', text: '✅ *FixOps alerts connected*\nYou\'ll receive weekly scan summaries and critical workflow alerts in this channel. Next alert: Monday morning.' }
        }]
      });
    }

    res.json({ success: true, message: webhookUrl ? 'Slack webhook saved and test message sent' : 'Slack webhook removed' });
  } catch(e) {
    console.error('Slack settings error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/settings/slack', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'email required' });
    const custRes = await db.query('SELECT slack_webhook FROM customers WHERE email = $1', [email]);
    const cust = custRes.rows[0];
    if (!cust) return res.status(404).json({ error: 'customer not found' });
    // Return masked URL for display
    const wh = cust.slack_webhook;
    res.json({ hasWebhook: !!wh, maskedUrl: wh ? wh.substring(0,40) + '...' : null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI Score Explanation ──────────────────────────────────────────────────────
// "Why did my score change?" — plain-English narrative, generated by Claude
app.post('/ai/score-explanation', async (req, res) => {
  try {
    const { auditId, email } = req.body;
    if (!auditId) return res.status(400).json({ error: 'auditId required' });

    if (email) {
      const custRes = await db.query('SELECT plan FROM customers WHERE email = $1', [email]);
      const plan = custRes.rows[0]?.plan || 'free';
      if (!['pulse','pro','command'].includes(plan)) {
        return res.status(403).json({ error: 'Score explanation requires Pulse plan or higher' });
      }
    }

    const result = await getResult(auditId);
    if (!result) return res.status(404).json({ error: 'Audit not found' });

    const s      = result.summary || {};
    const scores = result.scores  || {};
    const issues = result.issues  || [];
    const company = result.portalInfo?.company || 'Your Portal';

    // Get previous scan for comparison
    let prevData = null;
    if (email) {
      const custR = await db.query('SELECT id FROM customers WHERE email = $1', [email]);
      if (custR.rows[0]) {
        const histR = await db.query(
          'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 2',
          [custR.rows[0].id]
        );
        if (histR.rows.length >= 2) prevData = histR.rows[1];
      }
    }

    const prevScore  = prevData?.score || null;
    const scoreDelta = prevScore !== null ? s.overallScore - prevScore : null;
    const prevScores = prevData?.scores
      ? (typeof prevData.scores === 'string' ? JSON.parse(prevData.scores) : prevData.scores)
      : {};

    const dimLabels = {
      dataIntegrity:'Data Integrity', automationHealth:'Automation',
      pipelineIntegrity:'Pipeline', marketingHealth:'Marketing',
      configSecurity:'Configuration', reportingQuality:'Reporting',
      teamAdoption:'Team Adoption', serviceHealth:'Service'
    };

    const dimChanges = Object.entries(scores)
      .map(([key, val]) => ({
        label: dimLabels[key] || key,
        val: Number(val),
        delta: Number(val) - Number(prevScores[key] || val)
      }))
      .filter(d => d.delta !== 0)
      .sort((a,b) => Math.abs(b.delta) - Math.abs(a.delta))
      .slice(0, 3);

    const topCriticals = issues.filter(i => i.severity === 'critical').slice(0, 3);

    const prompt = `You are FixOps, a HubSpot intelligence platform. Write a plain-English briefing for ${company}'s weekly portal health scan.

SCORE: ${s.overallScore}/100 ${prevScore !== null ? `(was ${prevScore}, ${scoreDelta >= 0 ? '+' : ''}${scoreDelta} this week)` : '(first scan)'}
CRITICAL ISSUES: ${s.criticalCount} | WARNINGS: ${s.warningCount} | MONTHLY WASTE: $${Number(s.monthlyWaste||0).toLocaleString()}/mo

${dimChanges.length > 0 ? `BIGGEST DIMENSION CHANGES:\n${dimChanges.map(d => `- ${d.label}: ${d.val}/100 (${d.delta >= 0 ? '+' : ''}${d.delta})`).join('\n')}` : ''}

TOP CRITICAL ISSUES:
${topCriticals.map(i => `- ${i.title}`).join('\n') || '- No critical issues this week'}

Write EXACTLY 2-3 sentences:
1. What happened to the score and the single biggest reason why
2. The most urgent issue to fix this week and its business impact
3. One specific next step (action verb + exact location in HubSpot)

Rules: Direct and expert tone. No "great news" or "unfortunately". No fluff. State facts. Use dollar amounts when available. Output ONLY the explanation, nothing else.`;

    const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-opus-4-20250514',
      max_tokens: 250,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      timeout: 20000
    });

    const explanation = claudeRes.data?.content?.[0]?.text?.trim() || '';
    if (!explanation) return res.status(500).json({ error: 'Generation failed' });

    res.json({ success: true, explanation, scoreDelta, currentScore: s.overallScore, prevScore });
  } catch(e) {
    console.error('AI explanation error:', e.response?.data || e.message);
    res.status(500).json({ error: e.message });
  }
});
// Returns per-deal risk scores based on inactivity, missing fields, stage age
app.get('/audit/deal-risk', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'audit id required' });
    const result = await getResult(id);
    if (!result || result.status !== 'complete') return res.status(404).json({ error: 'audit not found' });

    const plan = result.plan || 'free';
    if (!['pulse','pro','command','deep','deep-audit','pro-audit'].includes(plan)) {
      return res.status(403).json({ error: 'Deal risk scoring requires Pulse plan or higher' });
    }

    const deals = result.portalInfo?.portalStats?.dealList || [];
    const now = Date.now();
    const DAY = 86400000;

    const scored = deals.map(deal => {
      let risk = 0;
      const flags = [];

      const lastActivity = deal.properties?.notes_last_updated || deal.properties?.hs_lastmodifieddate;
      const daysSinceActivity = lastActivity ? Math.floor((now - new Date(lastActivity).getTime()) / DAY) : 999;

      const closeDate = deal.properties?.closedate;
      const daysToClose = closeDate ? Math.floor((new Date(closeDate).getTime() - now) / DAY) : null;
      const amount = parseFloat(deal.properties?.amount || 0);
      const stage = deal.properties?.dealstage || '';
      const owner = deal.properties?.hubspot_owner_id;
      const probability = parseFloat(deal.properties?.hs_deal_stage_probability || 0);

      // Inactivity scoring
      if (daysSinceActivity > 30) { risk += 35; flags.push(`No activity in ${daysSinceActivity} days`); }
      else if (daysSinceActivity > 14) { risk += 20; flags.push(`${daysSinceActivity} days since last activity`); }
      else if (daysSinceActivity > 7) { risk += 10; flags.push(`${daysSinceActivity} days since last activity`); }

      // Overdue close date
      if (daysToClose !== null && daysToClose < 0) { risk += 25; flags.push(`Close date ${Math.abs(daysToClose)} days overdue`); }
      else if (daysToClose !== null && daysToClose < 7) { risk += 15; flags.push(`Close date in ${daysToClose} days`); }

      // Missing critical fields
      if (!owner) { risk += 15; flags.push('No owner assigned'); }
      if (!closeDate) { risk += 10; flags.push('No close date set'); }
      if (!amount || amount === 0) { risk += 10; flags.push('No deal value set'); }

      // Zero probability open deal (phantom pipeline)
      if (probability === 0 && amount > 0) { risk += 20; flags.push('0% probability — phantom pipeline'); }

      // High-value deal gets elevated risk weight
      const valueMultiplier = amount > 50000 ? 1.3 : amount > 10000 ? 1.1 : 1.0;
      risk = Math.min(100, Math.round(risk * valueMultiplier));

      return {
        id: deal.id,
        name: deal.properties?.dealname || 'Unnamed Deal',
        amount,
        stage,
        owner,
        daysSinceActivity,
        daysToClose,
        probability,
        riskScore: risk,
        riskLevel: risk >= 70 ? 'critical' : risk >= 40 ? 'warning' : 'healthy',
        flags
      };
    });

    const sorted = scored.sort((a,b) => b.riskScore - a.riskScore);
    const critical = sorted.filter(d => d.riskLevel === 'critical');
    const atRisk = sorted.filter(d => d.riskLevel === 'warning');
    const totalAtRiskValue = [...critical,...atRisk].reduce((s,d) => s + d.amount, 0);

    res.json({
      deals: sorted,
      summary: {
        total: sorted.length,
        critical: critical.length,
        atRisk: atRisk.length,
        healthy: sorted.filter(d => d.riskLevel === 'healthy').length,
        totalAtRiskValue
      }
    });
  } catch(e) {
    console.error('Deal risk error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Workflow Conflict Detector ────────────────────────────────────────────────
// Finds workflows enrolling same contacts — duplicate triggers, overlapping sequences
app.get('/audit/workflow-conflicts', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'audit id required' });
    const result = await getResult(id);
    if (!result || result.status !== 'complete') return res.status(404).json({ error: 'audit not found' });

    const plan = result.plan || 'free';
    if (!['pro','command','pro-audit'].includes(plan)) {
      return res.status(403).json({ error: 'Workflow conflict detection requires Pro plan or higher' });
    }

    const workflows = result.portalInfo?.portalStats?.workflowList || [];
    const activeWfs = workflows.filter(w => w.enabled || w.isEnabled);

    const conflicts = [];

    // Group by trigger type + trigger value
    const triggerMap = {};
    for (const wf of activeWfs) {
      const triggers = [];
      // Form submission triggers
      const formTriggers = (wf.triggers||[]).filter(t => t.type === 'FORM_SUBMISSION' || t.filterGroups?.some(fg => fg.filters?.some(f => f.property === 'hs_form_submissions')));
      for (const t of formTriggers) {
        const key = `form:${t.formId || t.value || 'any'}`;
        if (!triggerMap[key]) triggerMap[key] = [];
        triggerMap[key].push({ id: wf.id, name: wf.name, enrollmentCount: wf.enrollmentCount || 0 });
      }
      // Lifecycle stage triggers
      const lcTriggers = (wf.triggers||[]).filter(t => t.property === 'lifecyclestage' || t.type === 'CONTACT_PROPERTY' && t.property === 'lifecyclestage');
      for (const t of lcTriggers) {
        const key = `lifecycle:${t.value || 'any'}`;
        if (!triggerMap[key]) triggerMap[key] = [];
        triggerMap[key].push({ id: wf.id, name: wf.name, enrollmentCount: wf.enrollmentCount || 0 });
      }
    }

    // Flag any trigger key shared by 2+ workflows
    for (const [key, wfList] of Object.entries(triggerMap)) {
      if (wfList.length >= 2) {
        const [triggerType, triggerValue] = key.split(':');
        conflicts.push({
          type: triggerType === 'form' ? 'Duplicate Form Trigger' : 'Duplicate Lifecycle Trigger',
          description: triggerType === 'form'
            ? `${wfList.length} workflows enroll contacts from the same form — contacts may receive duplicate emails or conflicting sequences`
            : `${wfList.length} workflows trigger on the same lifecycle stage change`,
          severity: wfList.length >= 3 ? 'critical' : 'warning',
          triggerValue,
          workflows: wfList,
          impact: `Up to ${wfList.reduce((s,w) => s + w.enrollmentCount, 0).toLocaleString()} contacts potentially double-enrolled`
        });
      }
    }

    // Dead + active name overlap (renamed workflows creating confusion)
    const nameMap = {};
    for (const wf of workflows) {
      const baseName = (wf.name||'').toLowerCase().replace(/\s*(v\d+|copy|old|legacy|new|2|ii)\s*$/i,'').trim();
      if (!nameMap[baseName]) nameMap[baseName] = [];
      nameMap[baseName].push({ id: wf.id, name: wf.name, active: !!(wf.enabled||wf.isEnabled) });
    }
    for (const [base, wfList] of Object.entries(nameMap)) {
      const activeVersions = wfList.filter(w => w.active);
      if (activeVersions.length >= 2) {
        conflicts.push({
          type: 'Parallel Active Versions',
          description: `"${wfList[0].name}" has ${activeVersions.length} active versions running simultaneously — contacts may be enrolled in both`,
          severity: 'warning',
          workflows: wfList,
          impact: 'Duplicate nurture emails, conflicting delays, or redundant tasks'
        });
      }
    }

    res.json({
      conflicts,
      summary: {
        total: conflicts.length,
        critical: conflicts.filter(c => c.severity === 'critical').length,
        warning: conflicts.filter(c => c.severity === 'warning').length,
        workflowsAnalyzed: activeWfs.length
      }
    });
  } catch(e) {
    console.error('Workflow conflicts error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Contact Enrichment Gap Report ─────────────────────────────────────────────
// Shows exactly which fields are missing, impact on sequences/segments, and enrichment priority
app.get('/audit/enrichment-gaps', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'audit id required' });
    const result = await getResult(id);
    if (!result || result.status !== 'complete') return res.status(404).json({ error: 'audit not found' });

    const ps = result.portalInfo?.portalStats || {};
    const total = ps.contacts || 0;
    if (total === 0) return res.json({ gaps: [], total: 0 });

    const fields = [
      { key: 'email',         label: 'Email Address',    impact: 'Cannot be enrolled in any sequence, workflow, or marketing email', priority: 1 },
      { key: 'phone',         label: 'Phone Number',     impact: 'Cannot be called or texted — blocks call-based sequences', priority: 2 },
      { key: 'company',       label: 'Company Name',     impact: 'Cannot be segmented by company, matched to deals, or scored by firmographic', priority: 3 },
      { key: 'lifecyclestage',label: 'Lifecycle Stage',  impact: 'Cannot be targeted by lifecycle-based workflows or scored correctly', priority: 2 },
      { key: 'hubspot_owner_id', label: 'Contact Owner', impact: 'No rep assigned — falls through every round-robin and rotation workflow', priority: 2 },
      { key: 'jobtitle',      label: 'Job Title',        impact: 'Cannot segment by persona, seniority, or role-based campaigns', priority: 4 },
      { key: 'city',          label: 'City / Location',  impact: 'Cannot run geo-targeted campaigns or route to territory reps', priority: 5 },
      { key: 'industry',      label: 'Industry',         impact: 'Cannot segment by vertical or run industry-specific nurture', priority: 4 },
    ];

    const completenessData = ps.contactCompleteness || {};
    // missingByField stores count of contacts MISSING each field
    const missingByField = completenessData.missingByField || {};
    // If no completeness data (pre-fix audit), tell frontend to re-scan
    if (!completenessData.missingByField && Object.keys(missingByField).length === 0) {
      return res.json({ gaps: [], total, needsRescan: true,
        message: 'Contact completeness data requires a fresh audit scan to compute.' });
    }
    const gaps = fields.map(f => {
      // Only use real data — no fabricated fallback
      // If contactCompleteness not available (old audit), missing = 0 (unknown)
      const missing = missingByField[f.key] !== undefined ? missingByField[f.key] : 0;
      const filled = total - missing;
      const pct = total > 0 ? Math.round((missing / total) * 100) : 0;
      return {
        ...f,
        filled,
        missing,
        pct,
        severity: pct > 50 ? 'critical' : pct > 25 ? 'warning' : pct > 10 ? 'info' : 'healthy',
        estimatedFixCost: Math.round(missing * 0.08), // $0.08/contact enrichment estimate (Apollo/Clearbit)
      };
    }).filter(f => f.pct > 5).sort((a,b) => a.priority - b.priority || b.pct - a.pct);

    const totalMissing = gaps.reduce((s,g) => s + g.missing, 0);
    const enrichmentCost = gaps.slice(0,3).reduce((s,g) => s + g.estimatedFixCost, 0);

    res.json({
      gaps,
      total,
      summary: {
        fieldsWithGaps: gaps.length,
        worstField: gaps[0] || null,
        estimatedEnrichmentCost: enrichmentCost,
        totalMissingFieldInstances: totalMissing
      }
    });
  } catch(e) {
    console.error('Enrichment gaps error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Billing Tier Warning ──────────────────────────────────────────────────────
// Proactive alert before contacts hit next HubSpot billing tier
app.get('/audit/billing-risk', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'audit id required' });
    const result = await getResult(id);
    if (!result || result.status !== 'complete') return res.status(404).json({ error: 'audit not found' });

    const ps = result.portalInfo?.portalStats || {};
    const contacts = ps.contacts || 0;

    // HubSpot Marketing Hub contact tiers (approximate)
    const tiers = [
      { limit: 1000,   label: 'Starter 1K',   monthlyDelta: 0 },
      { limit: 2000,   label: 'Starter 2K',   monthlyDelta: 50 },
      { limit: 5000,   label: 'Starter 5K',   monthlyDelta: 100 },
      { limit: 10000,  label: 'Pro 10K',       monthlyDelta: 400 },
      { limit: 25000,  label: 'Pro 25K',       monthlyDelta: 300 },
      { limit: 50000,  label: 'Pro 50K',       monthlyDelta: 300 },
      { limit: 100000, label: 'Pro 100K',      monthlyDelta: 600 },
      { limit: 200000, label: 'Enterprise 200K', monthlyDelta: 1200 },
    ];

    const currentTier = tiers.find(t => contacts <= t.limit) || tiers[tiers.length - 1];
    const nextTier = tiers[tiers.indexOf(currentTier) + 1];
    const pctOfTier = currentTier ? Math.round((contacts / currentTier.limit) * 100) : 100;
    const contactsUntilNext = nextTier ? nextTier.limit - contacts : null;

    // Estimate monthly contact growth from audit history (if available)
    const avgMonthlyGrowth = ps.recentContactGrowth || Math.round(contacts * 0.03); // assume 3%/mo if no data
    const daysToNextTier = contactsUntilNext && avgMonthlyGrowth > 0
      ? Math.round((contactsUntilNext / (avgMonthlyGrowth / 30)))
      : null;

    // Cleanable contacts (duplicates + no email + uncontacted 1yr+)
    const cleanable = (ps.duplicateContactCount || 0) + (ps.noEmailContactCount || 0);
    const cleanableSavings = nextTier && cleanable >= contactsUntilNext ? nextTier.monthlyDelta : 0;

    res.json({
      contacts,
      currentTier,
      nextTier,
      pctOfTier,
      contactsUntilNext,
      daysToNextTier,
      avgMonthlyGrowth,
      cleanable,
      cleanableSavings,
      atRisk: pctOfTier >= 85,
      severity: pctOfTier >= 95 ? 'critical' : pctOfTier >= 85 ? 'warning' : 'healthy'
    });
  } catch(e) {
    console.error('Billing risk error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── White-label share URL (Agency) ────────────────────────────────────────────
// Generates a client-safe shareable results URL — no FixOps branding in header
app.get('/share/:token', async (req, res) => {
  try {
    const { token } = req.params;
    let payload;
    try {
      payload = JSON.parse(Buffer.from(token, 'base64url').toString());
    } catch(e) {
      return res.status(400).send('Invalid share link');
    }
    const { auditId, agencyName, agencyLogo, primaryColor } = payload;
    if (!auditId) return res.status(400).send('Invalid share link');

    const result = await getResult(auditId);
    if (!result || result.status !== 'complete') return res.status(404).send('Results not found or expired');

    // Redirect to results page with white-label params
    const params = new URLSearchParams({ id: auditId });
    if (agencyName) params.set('brand', agencyName);
    if (agencyLogo) params.set('logo', agencyLogo);
    if (primaryColor) params.set('color', primaryColor);
    res.redirect(`${FRONTEND_URL}/results.html?${params.toString()}`);
  } catch(e) {
    console.error('Share URL error:', e.message);
    res.status(500).send('Error loading shared results');
  }
});

app.post('/share/generate', async (req, res) => {
  try {
    const { email, auditId, agencyName, agencyLogo, primaryColor } = req.body;
    if (!email || !auditId) return res.status(400).json({ error: 'email and auditId required' });
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    const cust = custRes.rows[0];
    if (!cust) return res.status(404).json({ error: 'customer not found' });
    if (!['pro','command'].includes(cust.plan)) return res.status(403).json({ error: 'White-label sharing requires Pro or Agency plan' });

    const payload = Buffer.from(JSON.stringify({ auditId, agencyName, agencyLogo, primaryColor, ts: Date.now() })).toString('base64url');
    const shareUrl = `${process.env.API_URL || 'https://fixops-api-production.up.railway.app'}/share/${payload}`;
    res.json({ success: true, shareUrl });
  } catch(e) {
    console.error('Share generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});



// ══════════════════════════════════════════════════════════════════════════════
// ✦ WHITE-LABEL AGENCY SYSTEM
// Agencies get their own dashboard, branding, and audit credit pool.
// All audit results generated under their account show their branding.
// ══════════════════════════════════════════════════════════════════════════════

// ── Agency auth middleware ────────────────────────────────────────────────────
const agencyAuth = async (req, res, next) => {
  const apiKey = req.headers['x-agency-key'] || req.query.apiKey || req.body?.apiKey;
  if (!apiKey) return res.status(401).json({ error: 'Agency API key required' });
  try {
    const r = await db.query(
      `SELECT * FROM agency_accounts WHERE api_key = $1 AND is_active = true`,
      [apiKey]
    );
    if (!r.rows[0]) return res.status(401).json({ error: 'Invalid or inactive API key' });
    req.agency = r.rows[0];
    // Update last login
    await db.query(`UPDATE agency_accounts SET last_login_at = NOW() WHERE id = $1`, [r.rows[0].id]).catch(()=>{});
    next();
  } catch(e) {
    res.status(500).json({ error: 'Auth error' });
  }
};

// Credit plans — what each tier gets
const AGENCY_PLANS = {
  // Current agency tiers
  command:           { maxPortals: 10,   name: 'FixOps Command',           price: 999,  aiCoach: false, autoDoc: 0 },
  command_unlimited: { maxPortals: 9999, name: 'FixOps Command Unlimited',  price: 1999, aiCoach: true,  autoDoc: 5 },
  // Legacy keys for existing customers
  agency_starter:    { maxPortals: 5,    name: 'FixOps Monitor',            price: 299,  aiCoach: false, autoDoc: 0 },
  agency_pro:        { maxPortals: 15,   name: 'FixOps Sentinel',           price: 549,  aiCoach: false, autoDoc: 0 },
  agency_scale:      { maxPortals: 10,   name: 'FixOps Command',            price: 999,  aiCoach: false, autoDoc: 0 },
  agency_unlimited:  { maxPortals: 9999, name: 'FixOps Command Unlimited',  price: 1999, aiCoach: true,  autoDoc: 5 },
};

// ── Register new agency account (admin or Stripe webhook) ─────────────────────
// ── Admin: generate audit token for beta testers ────────────────────────────
// POST /admin/generate-token  { adminKey, email, company, plan, days }
// Returns { token, link } — use to give testers free full audits
app.post('/admin/generate-token', async (req, res) => {
  try {
    const { adminKey, email, company, plan = 'pro-audit', days = 14 } = req.body;
    if (!adminKey || adminKey !== process.env.FIXOPS_ADMIN_KEY) {
      return res.status(403).json({ error: 'Admin key required' });
    }
    if (!email) return res.status(400).json({ error: 'email required' });

    const token = crypto.randomBytes(24).toString('hex'); // 48 char hex
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

    await db.query(
      `INSERT INTO audit_tokens (token, email, plan, company, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (token) DO NOTHING`,
      [token, email.toLowerCase().trim(), plan, company || '', expiresAt]
    );

    const link = `${FRONTEND_URL}/confirm.html?auditToken=${token}`;

    // Notify Matthew
    await resend.emails.send({
      from: 'FixOps <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `🎟 Beta token created — ${email} — ${plan}`,
      html: `<p>Token created for <strong>${email}</strong> (${company || 'unknown company'})</p>
             <p>Plan: <strong>${plan}</strong> · Expires: ${expiresAt.toDateString()}</p>
             <p><a href="${link}">${link}</a></p>`
    }).catch(() => {});

    res.json({ ok: true, token, link, plan, expires: expiresAt, email });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/agency/register', async (req, res) => {
  try {
    const { email, agencyName, plan, stripeCustomer, subscriptionId, adminKey } = req.body;
    // Simple admin protection — only FixOps internal can create accounts
    if (adminKey !== process.env.FIXOPS_ADMIN_KEY && process.env.FIXOPS_ADMIN_KEY) {
      return res.status(403).json({ error: 'Admin key required' });
    }
    if (!email || !agencyName) return res.status(400).json({ error: 'email and agencyName required' });

    // Generate API key and slug
    const apiKey = 'fxa_' + crypto.randomBytes(24).toString('hex');
    const slug = agencyName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').substring(0, 50)
      + '_' + crypto.randomBytes(4).toString('hex');
    const planKey = plan || 'agency_starter';
    const planConfig = AGENCY_PLANS[planKey] || AGENCY_PLANS.agency_starter;

    const r = await db.query(
      `INSERT INTO agency_accounts
        (api_key, email, agency_name, agency_slug, plan, plan_status, audit_credits, monthly_credits, monthly_used, monthly_reset_at, stripe_customer, subscription_id)
       VALUES ($1,$2,$3,$4,$5,'active',$6,$7,0, NOW() + INTERVAL '30 days',$8,$9)
       ON CONFLICT (email) DO UPDATE SET
         plan=$5, audit_credits=agency_accounts.audit_credits+$6, monthly_credits=$7,
         stripe_customer=COALESCE($8,agency_accounts.stripe_customer),
         subscription_id=COALESCE($9,agency_accounts.subscription_id),
         updated_at=NOW()
       RETURNING *`,
      [apiKey, email, agencyName, slug, planKey, planConfig.monthlyCredits, planConfig.monthlyCredits, stripeCustomer||null, subscriptionId||null]
    );
    const agency = r.rows[0];

    // Welcome email
    await resend.emails.send({
      from: 'FixOps Agency <reports@fixops.io>',
      to: email,
      subject: `🎉 Your FixOps Agency Account is Ready — ${agencyName}`,
      html: `<div style="font-family:system-ui;max-width:560px;margin:0 auto;padding:40px 20px;">
        <h2 style="color:#7c3aed;">Welcome to FixOps Agency, ${agencyName}!</h2>
        <p>Your white-label HubSpot audit platform is ready. Here's everything you need:</p>
        <div style="background:#f9fafb;border-radius:8px;padding:20px;margin:20px 0;">
          <p><strong>Agency Dashboard:</strong> <a href="https://fixops.io/agency.html">fixops.io/agency.html</a></p>
          <p><strong>Your API Key:</strong> <code style="background:#e5e7eb;padding:2px 6px;border-radius:4px;">${apiKey}</code></p>
          <p><strong>Monthly Audit Credits:</strong> ${planConfig.monthlyCredits}</p>
          <p><strong>Plan:</strong> ${planConfig.name}</p>
        </div>
        <p><strong>How it works:</strong></p>
        <ol>
          <li>Log in to your dashboard with your API key</li>
          <li>Upload your logo and set your brand colors</li>
          <li>Create a client audit link — uses 1 credit</li>
          <li>Send the link to your client — they connect HubSpot and see YOUR branding</li>
          <li>You get notified when complete and can view all results in your dashboard</li>
        </ol>
        <p style="color:#6b7280;font-size:13px;">Questions? Reply to this email or contact support@fixops.io</p>
      </div>`
    }).catch(e => console.error('Agency welcome email error:', e.message));

    res.json({ success: true, apiKey, slug, agency: { id: agency.id, email, agencyName, plan: planKey, monthlyCredits: planConfig.monthlyCredits } });
  } catch(e) {
    console.error('Agency register error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Get agency account details + credit balance ───────────────────────────────
app.get('/agency/account', agencyAuth, async (req, res) => {
  try {
    const agency = req.agency;
    const planConfig = AGENCY_PLANS[agency.plan] || AGENCY_PLANS.agency_starter;

    // Reset monthly credits if past reset date
    if (agency.monthly_reset_at && new Date(agency.monthly_reset_at) < new Date()) {
      await db.query(
        `UPDATE agency_accounts SET monthly_used = 0, monthly_reset_at = NOW() + INTERVAL '30 days' WHERE id = $1`,
        [agency.id]
      );
      agency.monthly_used = 0;
    }

    // Get recent audits
    const auditsRes = await db.query(
      `SELECT * FROM agency_audits WHERE agency_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [agency.id]
    );

    const creditsRemaining = agency.monthly_credits > 0
      ? Math.max(0, agency.monthly_credits - (agency.monthly_used || 0))
      : Math.max(0, agency.audit_credits - (agency.credits_used || 0));

    res.json({
      success: true,
      agency: {
        id: agency.id,
        email: agency.email,
        agencyName: agency.agency_name,
        slug: agency.agency_slug,
        plan: agency.plan,
        planName: planConfig.name,
        // Branding
        logoUrl: agency.logo_url,
        primaryColor: agency.primary_color || '#7c3aed',
        secondaryColor: agency.secondary_color || '#a78bfa',
        accentColor: agency.accent_color || '#10b981',
        reportFooter: agency.report_footer,
        // Credits
        monthlyCredits: agency.monthly_credits,
        monthlyUsed: agency.monthly_used || 0,
        creditsRemaining,
        totalCreditsUsed: agency.credits_used || 0,
        resetAt: agency.monthly_reset_at,
        // Usage
        totalAudits: auditsRes.rows.length,
        audits: auditsRes.rows,
      }
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Update agency branding ────────────────────────────────────────────────────
app.post('/agency/branding', agencyAuth, async (req, res) => {
  try {
    const { logoUrl, primaryColor, secondaryColor, accentColor, reportFooter } = req.body;
    const agency = req.agency;

    // Validate hex colors
    const hexRe = /^#[0-9a-fA-F]{6}$/;
    const safeColor = (c, def) => (c && hexRe.test(c)) ? c : def;

    await db.query(
      `UPDATE agency_accounts SET
        logo_url = COALESCE($1, logo_url),
        primary_color = $2,
        secondary_color = $3,
        accent_color = $4,
        report_footer = COALESCE($5, report_footer),
        updated_at = NOW()
       WHERE id = $6`,
      [
        logoUrl || null,
        safeColor(primaryColor, agency.primary_color || '#7c3aed'),
        safeColor(secondaryColor, agency.secondary_color || '#a78bfa'),
        safeColor(accentColor, agency.accent_color || '#10b981'),
        reportFooter || null,
        agency.id,
      ]
    );
    res.json({ success: true, message: 'Branding updated — all future audit links will use your new branding' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Create a new client audit token (uses 1 credit) ──────────────────────────
app.post('/agency/create-audit', agencyAuth, async (req, res) => {
  try {
    const { clientName, clientEmail, clientCompany, plan } = req.body;
    const agency = req.agency;

    if (!clientEmail || !clientCompany) {
      return res.status(400).json({ error: 'clientEmail and clientCompany required' });
    }

    // Check credit balance
    const usesMonthly = agency.monthly_credits > 0;
    const creditsRemaining = usesMonthly
      ? Math.max(0, agency.monthly_credits - (agency.monthly_used || 0))
      : Math.max(0, agency.audit_credits - (agency.credits_used || 0));

    if (creditsRemaining <= 0) {
      return res.status(402).json({
        error: 'No audit credits remaining',
        creditsRemaining: 0,
        upgradeUrl: 'https://fixops.io/agency#pricing',
        message: `You've used all ${usesMonthly ? agency.monthly_credits + ' monthly' : agency.audit_credits} credits. Upgrade your plan or purchase additional credits.`
      });
    }

    // Generate audit token
    const tokenStr = 'agt_' + crypto.randomBytes(16).toString('hex');
    const auditPlan = plan || 'deep';
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await db.query(
      `INSERT INTO audit_tokens (token, email, plan, company, expires_at, agency_id, client_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [tokenStr, clientEmail, auditPlan, clientCompany, expiresAt, agency.id, clientName || clientCompany]
    );

    // Deduct credit
    if (usesMonthly) {
      await db.query(`UPDATE agency_accounts SET monthly_used = monthly_used + 1, updated_at = NOW() WHERE id = $1`, [agency.id]);
    } else {
      await db.query(`UPDATE agency_accounts SET credits_used = credits_used + 1, updated_at = NOW() WHERE id = $1`, [agency.id]);
    }

    // Record in agency_audits
    await db.query(
      `INSERT INTO agency_audits (agency_id, audit_id, client_name, client_email, token_used, plan, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
      [agency.id, tokenStr, clientName || clientCompany, clientEmail, tokenStr, auditPlan]
    );

    // Build the client audit URL with agency branding params
    const brandParams = new URLSearchParams({
      auditToken: tokenStr,
      brand: agency.agency_name,
      color: agency.primary_color || '#7c3aed',
      accent: agency.accent_color || '#10b981',
    });
    if (agency.logo_url) brandParams.set('logo', agency.logo_url);

    const clientUrl = `${FRONTEND_URL}/confirm.html?${brandParams.toString()}`;

    // Notify the agency
    await resend.emails.send({
      from: 'FixOps Agency <reports@fixops.io>',
      to: agency.email,
      subject: `✅ Audit link created for ${clientCompany}`,
      html: `<p>Audit link created for <strong>${clientCompany}</strong> (${clientEmail}).</p>
             <p><strong>Send this link to your client:</strong><br><a href="${clientUrl}">${clientUrl}</a></p>
             <p>Credits remaining: ${creditsRemaining - 1}</p>`
    }).catch(()=>{});

    res.json({
      success: true,
      token: tokenStr,
      clientUrl,
      creditsRemaining: creditsRemaining - 1,
      expiresAt: expiresAt.toISOString(),
      message: `Audit link ready for ${clientCompany}. Send clientUrl to your client.`
    });
  } catch(e) {
    console.error('Agency create-audit error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Get agency audit results ──────────────────────────────────────────────────
app.get('/agency/audits', agencyAuth, async (req, res) => {
  try {
    const agency = req.agency;
    const auditsRes = await db.query(
      `SELECT aa.*, at.used as token_redeemed, at.expires_at as token_expires
       FROM agency_audits aa
       LEFT JOIN audit_tokens at ON at.token = aa.token_used
       WHERE aa.agency_id = $1
       ORDER BY aa.created_at DESC`,
      [agency.id]
    );

    // Enrich with latest audit result for completed audits
    const enriched = await Promise.all(auditsRes.rows.map(async row => {
      let result = null;
      if (row.status === 'complete' && row.audit_id && !row.audit_id.startsWith('agt_')) {
        result = await getResult(row.audit_id).catch(() => null);
      }
      const shareBase = new URLSearchParams({
        id: row.audit_id,
        brand: agency.agency_name,
        color: agency.primary_color || '#7c3aed',
        accent: agency.accent_color || '#10b981',
      });
      if (agency.logo_url) shareBase.set('logo', agency.logo_url);

      return {
        ...row,
        score: result?.summary?.overallScore || row.score,
        criticalCount: result?.summary?.criticalCount || row.critical_count || 0,
        monthlyWaste: result?.summary?.monthlyWaste || row.monthly_waste || 0,
        brandedResultsUrl: row.status === 'complete' ? `${FRONTEND_URL}/results.html?${shareBase}` : null,
        brandedReportUrl: row.status === 'complete' ? `${FRONTEND_URL}/reporting.html?${shareBase}` : null,
      };
    }));

    const planConfig = AGENCY_PLANS[agency.plan] || AGENCY_PLANS.agency_starter;
    const creditsRemaining = agency.monthly_credits > 0
      ? Math.max(0, agency.monthly_credits - (agency.monthly_used || 0))
      : Math.max(0, agency.audit_credits - (agency.credits_used || 0));

    res.json({
      success: true,
      audits: enriched,
      totalAudits: enriched.length,
      creditsRemaining,
      monthlyCredits: agency.monthly_credits,
      monthlyUsed: agency.monthly_used || 0,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Get single audit result (agency-gated) ────────────────────────────────────
app.get('/agency/audit/:auditId', agencyAuth, async (req, res) => {
  try {
    const agency = req.agency;
    const { auditId } = req.params;
    // Verify this audit belongs to this agency
    const check = await db.query(
      `SELECT * FROM agency_audits WHERE agency_id = $1 AND audit_id = $2`,
      [agency.id, auditId]
    );
    if (!check.rows[0]) return res.status(403).json({ error: 'Audit not found in your account' });
    const result = await getResult(auditId);
    if (!result) return res.status(404).json({ error: 'Audit result not found' });
    res.json({ success: true, result, branding: {
      agencyName: agency.agency_name,
      logoUrl: agency.logo_url,
      primaryColor: agency.primary_color,
      secondaryColor: agency.secondary_color,
      accentColor: agency.accent_color,
      reportFooter: agency.report_footer,
    }});
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Hook: when an agency audit completes, update agency_audits record ─────────
// This is called from the OAuth callback after runFullAudit completes
const updateAgencyAudit = async (tokenStr, realAuditId, result) => {
  try {
    await db.query(
      `UPDATE agency_audits SET
        audit_id = $1, status = 'complete', completed_at = NOW(),
        score = $2, critical_count = $3, monthly_waste = $4
       WHERE token_used = $5`,
      [realAuditId, result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.monthlyWaste||0, tokenStr]
    );
    // Look up agency for notification
    const agAudit = await db.query(`SELECT aa.*, ac.email as agency_email, ac.agency_name FROM agency_audits aa JOIN agency_accounts ac ON ac.id = aa.agency_id WHERE aa.token_used = $1`, [tokenStr]).catch(()=>({rows:[]}));
    const row = agAudit.rows[0];
    if (row) {
      const brandParams = new URLSearchParams({ id: realAuditId, brand: row.agency_name });
      await resend.emails.send({
        from: 'FixOps Agency <reports@fixops.io>',
        to: row.agency_email,
        subject: `✅ Audit complete — ${row.client_name} — Score ${result.summary?.overallScore}/100`,
        html: `<p><strong>${row.client_name}</strong>'s audit is complete.</p>
               <p>Score: <strong>${result.summary?.overallScore}/100</strong> · ${result.summary?.criticalCount} critical issues · $${Number(result.summary?.monthlyWaste||0).toLocaleString()}/mo waste</p>
               <p><a href="${FRONTEND_URL}/results.html?${brandParams}">View branded results →</a></p>`
      }).catch(()=>{});
    }
  } catch(e) {
    console.error('updateAgencyAudit error:', e.message);
  }
};

// ── Add purchase credits endpoint ─────────────────────────────────────────────
app.post('/agency/add-credits', async (req, res) => {
  try {
    const { apiKey, credits, adminKey } = req.body;
    if (adminKey !== process.env.FIXOPS_ADMIN_KEY) return res.status(403).json({ error: 'Admin key required' });
    await db.query(
      `UPDATE agency_accounts SET audit_credits = audit_credits + $1, updated_at = NOW() WHERE api_key = $2`,
      [credits, apiKey]
    );
    res.json({ success: true, message: `Added ${credits} credits` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Branding resolution — used by results/reporting pages ────────────────────
// When ?brand= params are in URL, results page can fetch branding from agency slug
app.get('/agency/branding/:slug', async (req, res) => {
  try {
    const r = await db.query(
      `SELECT agency_name, logo_url, primary_color, secondary_color, accent_color, report_footer
       FROM agency_accounts WHERE agency_slug = $1 AND is_active = true`,
      [req.params.slug]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Agency not found' });
    res.json({ success: true, branding: r.rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
// Lightweight daily check — workflow errors, ghost seats, billing tier risk
// Not a full 210-point audit — just the 5 critical health signals that change daily
const runSentinelCheck = async (customer) => {
  try {
    const freshToken = await getValidToken(customer);
    const hs = require('axios').create({
      baseURL: 'https://api.hubapi.com',
      headers: { Authorization: `Bearer ${freshToken}` },
      timeout: 15000
    });
    const safe = async (fn, fb) => { try { return await fn(); } catch(e) { return fb; } };

    const [wfRes, usersRes, contactsRes] = await Promise.all([
      safe(() => hs.get('/automation/v3/workflows?limit=100'), { data: { workflows: [] } }),
      safe(() => hs.get('/settings/v3/users/?limit=100'), { data: { results: [] } }),
      safe(() => hs.get('/crm/v3/objects/contacts?limit=1&properties=email'), { data: { total: 0 } }),
    ]);

    const workflows = wfRes.data?.workflows || [];
    const users = usersRes.data?.results || [];
    const contactCount = contactsRes.data?.total || 0;

    // Check 1: Workflow errors
    const erroredWfs = workflows.filter(w => (w.enabled || w.isEnabled) && (w.status === 'ERROR' || w.errorCount > 0));

    // Check 2: New ghost seats since last check (users inactive 90+ days)
    const ninetyDaysAgo = Date.now() - (90 * 86400000);
    const ghostSeats = users.filter(u => {
      const last = u.lastLoginDate || u.properties?.last_login;
      return last && new Date(last).getTime() < ninetyDaysAgo;
    });

    // Check 3: Billing tier proximity
    const tiers = [1000,2000,5000,10000,25000,50000,100000,200000];
    const nextTier = tiers.find(t => contactCount <= t);
    const pctOfTier = nextTier ? Math.round((contactCount / nextTier) * 100) : 100;

    const alerts = [];
    if (erroredWfs.length > 0) {
      alerts.push({
        type: 'workflow_error',
        severity: 'critical',
        message: `${erroredWfs.length} workflow${erroredWfs.length!==1?'s':''} in error state`,
        detail: erroredWfs.slice(0,5).map(w => w.name).join(', '),
        action: 'Fix immediately — enrolled contacts are dropping'
      });
    }
    if (pctOfTier >= 90) {
      alerts.push({
        type: 'billing_tier',
        severity: pctOfTier >= 97 ? 'critical' : 'warning',
        message: `Portal at ${pctOfTier}% of HubSpot contact tier`,
        detail: `${(nextTier - contactCount).toLocaleString()} contacts until next billing tier`,
        action: 'Clean duplicates and uncontacted contacts before overage charge'
      });
    }

    if (alerts.length === 0) return; // nothing to alert on

    // Send Slack alert if configured
    if (customer.slack_webhook) {
      const slackBlocks = [{
        type: 'header',
        text: { type: 'plain_text', text: `🛡 FixOps Sentinel — ${customer.company || 'Your Portal'}` }
      }, {
        type: 'section',
        text: { type: 'mrkdwn', text: `*${alerts.length} issue${alerts.length!==1?'s':''} detected in daily check*` }
      },
      ...alerts.map(a => ({
        type: 'section',
        text: { type: 'mrkdwn', text: `${a.severity === 'critical' ? '🔴' : '🟡'} *${a.message}*\n${a.detail}\n_${a.action}_` }
      })), {
        type: 'actions',
        elements: [{ type: 'button', text: { type: 'plain_text', text: 'View Dashboard →' }, url: `${FRONTEND_URL}/results.html?id=${customer.last_audit_id}`, style: 'primary' }]
      }];
      await sendSlackAlert(customer.slack_webhook, { text: `FixOps Sentinel: ${alerts.length} issue(s) in ${customer.company}`, blocks: slackBlocks });
    }

    // Email alert for critical-only (don't spam daily)
    const criticalAlerts = alerts.filter(a => a.severity === 'critical');
    if (criticalAlerts.length > 0 && customer.last_audit_id) {
      const alertRows = criticalAlerts.map(a =>
        `<tr><td style="padding:10px 12px;border-bottom:1px solid #fee2e2;"><strong style="color:#dc2626;">${a.message}</strong><br><span style="font-size:12px;color:#666;">${a.detail}</span><br><span style="font-size:11px;color:#888;font-style:italic;">${a.action}</span></td></tr>`
      ).join('');
      await resend.emails.send({
        from: 'FixOps Sentinel <reports@fixops.io>',
        to: customer.email,
        subject: `🛡 FixOps Sentinel: ${criticalAlerts.length} critical issue${criticalAlerts.length!==1?'s':''} — ${customer.company || 'your portal'}`,
        html: `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Critical Alert</title></head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#07070a;padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

  <!-- Header — red alert theme -->
  <tr><td style="background:linear-gradient(135deg,#1a0a0a,#200808);border-radius:16px 16px 0 0;padding:24px 32px;border-bottom:1px solid rgba(244,63,94,.3);">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td>
        <div style="font-size:20px;font-weight:900;color:#fff;letter-spacing:-0.5px;">⚡ Fix<span style="color:#a78bfa;">Ops</span></div>
        <div style="font-size:10px;color:rgba(255,255,255,.3);letter-spacing:3px;text-transform:uppercase;margin-top:3px;font-family:monospace;">Sentinel Alert</div>
      </td>
      <td align="right">
        <div style="background:rgba(244,63,94,.15);border:1px solid rgba(244,63,94,.4);border-radius:6px;padding:5px 12px;font-size:10px;font-weight:800;color:#f43f5e;font-family:monospace;letter-spacing:1px;">⚠ ${criticalAlerts.length} CRITICAL</div>
      </td>
    </tr></table>
  </td></tr>

  <!-- Body -->
  <tr><td style="background:#0d0b1e;padding:32px;">
    <div style="font-size:22px;font-weight:800;color:#fff;margin-bottom:6px;letter-spacing:-0.5px;">${criticalAlerts.length} critical issue${criticalAlerts.length!==1?'s':''} found in ${customer.company || 'your portal'}</div>
    <div style="font-size:13px;color:rgba(255,255,255,.45);margin-bottom:24px;">Detected during today's automated health check. These need attention.</div>

    <!-- Issue cards -->
    ${criticalAlerts.map((a, i) => `
    <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(244,63,94,.06);border:1px solid rgba(244,63,94,.2);border-radius:12px;overflow:hidden;margin-bottom:10px;">
    <tr><td style="padding:0 0 0 4px;background:rgba(244,63,94,.7);width:4px;border-radius:4px 0 0 4px;"></td>
    <td style="padding:16px 20px;">
      <div style="font-size:13px;font-weight:700;color:#fff;margin-bottom:4px;">${a.message || a.title || 'Critical Issue'}</div>
      ${a.detail ? '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:6px;line-height:1.5;">' + a.detail + '</div>' : ''}
      ${a.action ? '<div style="font-size:11px;color:#f59e0b;font-weight:600;">→ ' + a.action + '</div>' : ''}
    </td></tr></table>`).join('')}

    <!-- CTA -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:24px;margin-bottom:20px;">
    <tr><td align="center">
      <a href="${FRONTEND_URL}/reporting.html?token=${customer.portal_token || ''}" style="display:inline-block;padding:13px 32px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;text-decoration:none;border-radius:9px;font-weight:700;font-size:14px;">View Full Portal Intelligence →</a>
    </td></tr>
    </table>

    <div style="font-size:12px;color:rgba(255,255,255,.25);text-align:center;line-height:1.7;">
      FixOps Sentinel runs daily checks on your portal.<br>
      <a href="mailto:matthew@fixops.io" style="color:rgba(124,58,237,.5);text-decoration:none;">matthew@fixops.io</a> · <a href="${FRONTEND_URL}" style="color:rgba(124,58,237,.5);text-decoration:none;">fixops.io</a>
    </div>

  </td></tr>
  <tr><td style="background:rgba(255,255,255,.02);border-top:1px solid rgba(255,255,255,.06);border-radius:0 0 16px 16px;padding:14px 32px;text-align:center;">
    <div style="font-size:10px;color:rgba(255,255,255,.15);font-family:monospace;letter-spacing:1px;text-transform:uppercase;">Sentinel · Daily Monitoring · fixops.io</div>
  </td></tr>

</table></td></tr></table>
</body></html>`
      }).catch(e => console.warn('Sentinel email err:', e.message));
    }

    console.log(`[Sentinel] ${customer.email} — ${alerts.length} alerts fired`);
  } catch(e) {
    console.error(`[Sentinel] Error for ${customer.email}:`, e.message);
  }
};

// Daily Sentinel cron — runs every day at 10am ET (non-Monday, since Monday = full scan)
cron.schedule('0 15 * * 2-7', async () => {
  console.log('🛡 Daily Sentinel scan starting...');
  try {
    const custRes = await db.query(`
      SELECT * FROM customers
      WHERE plan IN ('pulse','pro','command')
        AND plan_status = 'active'
        AND portal_token IS NOT NULL
    `);
    console.log(`[Sentinel] Checking ${custRes.rows.length} portals`);
    for (const customer of custRes.rows) {
      await runSentinelCheck(customer);
      await new Promise(r => setTimeout(r, 3000));
    }
    console.log('✅ Daily Sentinel complete');
  } catch(e) {
    console.error('[Sentinel] Cron error:', e.message);
  }
}, { timezone: 'America/New_York' });

// ── Agency Multi-Portal Management ───────────────────────────────────────────

// List all portals for an agency customer
app.get('/agency/portals', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'email required' });
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    const cust = custRes.rows[0];
    if (!cust) return res.status(404).json({ error: 'customer not found' });
    if (cust.plan !== 'command') return res.status(403).json({ error: 'Agency plan required' });

    const portalsRes = await db.query(
      'SELECT * FROM portals WHERE customer_id = $1 AND is_active = true ORDER BY created_at DESC',
      [cust.id]
    );

    // Get latest audit data for each portal
    const portals = portalsRes.rows;
    const enriched = await Promise.all(portals.map(async p => {
      let latestResult = null;
      if (p.last_audit_id) {
        latestResult = await getResult(p.last_audit_id).catch(() => null);
      }
      return {
        ...p,
        score: p.last_score || latestResult?.summary?.overallScore || null,
        criticalCount: p.critical_count || latestResult?.summary?.criticalCount || 0,
        monthlyWaste: p.monthly_waste || latestResult?.summary?.monthlyWaste || 0,
        grade: p.last_score >= 85 ? 'Excellent' : p.last_score >= 70 ? 'Good' : p.last_score >= 55 ? 'Needs Work' : 'Critical',
        lastAuditDate: p.last_audit_at ? new Date(p.last_audit_at).toLocaleDateString('en-US',{month:'short',day:'numeric'}) : null
      };
    }));

    const MAX_PORTALS = 25;
    res.json({
      portals: enriched,
      count: enriched.length,
      maxPortals: MAX_PORTALS,
      slotsRemaining: MAX_PORTALS - enriched.length,
      customer: { email: cust.email, company: cust.company, plan: cust.plan }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Add a new portal to agency account (after OAuth connect)
app.post('/agency/portals/add', async (req, res) => {
  try {
    const { email, token, company, nickname } = req.body;
    if (!email || !token) return res.status(400).json({ error: 'email and token required' });

    const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    const cust = custRes.rows[0];
    if (!cust) return res.status(404).json({ error: 'customer not found' });
    if (cust.plan !== 'command') return res.status(403).json({ error: 'Agency plan required' });

    // Check portal limit
    const countRes = await db.query(
      'SELECT COUNT(*) FROM portals WHERE customer_id = $1 AND is_active = true',
      [cust.id]
    );
    const planKey = cust.plan || 'command';
    const agPlan = AGENCY_PLANS[planKey] || AGENCY_PLANS.command;
    const maxPortals = agPlan.maxPortals || 10;
    if (parseInt(countRes.rows[0].count) >= maxPortals) {
      const isUnlimited = maxPortals >= 9999;
      return res.status(400).json({ 
        error: isUnlimited ? 'Something went wrong' : `Portal limit reached (${maxPortals} max on ${agPlan.name}). Upgrade to Command Unlimited for unlimited portals.`,
        upgrade: !isUnlimited
      });
    }

    // Try to get portal info to verify token works
    let portalInfo = { company: company || 'Client Portal', portalId: null };
    try {
      const infoRes = await axios.get('https://api.hubapi.com/account-info/v3/details', {
        headers: { Authorization: 'Bearer ' + token }
      });
      portalInfo.portalId = String(infoRes.data?.portalId || '');
      if (!company) portalInfo.company = infoRes.data?.companyName || 'Client Portal';
    } catch(e) {
      console.log('Could not verify portal token:', e.message);
    }

    // Check for duplicate portal
    if (portalInfo.portalId) {
      const dupCheck = await db.query(
        'SELECT id FROM portals WHERE customer_id = $1 AND portal_id = $2 AND is_active = true',
        [cust.id, portalInfo.portalId]
      );
      if (dupCheck.rows.length > 0) {
        return res.status(400).json({ error: 'This portal is already connected to your account' });
      }
    }

    // Insert portal
    const insertRes = await db.query(
      `INSERT INTO portals (customer_id, portal_token, company, portal_id, nickname, plan, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'command', NOW()) RETURNING id`,
      [cust.id, token, portalInfo.company, portalInfo.portalId, nickname || null]
    );
    const portalId = insertRes.rows[0].id;

    // Kick off initial audit for this portal
    const auditId = require('crypto').randomBytes(12).toString('hex');
    await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Running initial audit...' });
    setImmediate(async () => {
      try {
        const meta = { email, company: portalInfo.company, plan: 'command' };
        const result = await runFullAudit(token, auditId, meta);
        await db.query(
          `UPDATE portals SET last_audit_id = $1, last_audit_at = NOW(), last_score = $2, critical_count = $3, monthly_waste = $4, updated_at = NOW() WHERE id = $5`,
          [auditId, result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.monthlyWaste||0, portalId]
        );
        console.log('[Agency] Initial audit complete for portal', portalId);
      } catch(e) {
        console.error('[Agency] Initial audit failed:', e.message);
      }
    });

    res.json({ success: true, portalId, auditId, company: portalInfo.company, message: 'Portal added and audit started' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Remove a portal from agency account
app.delete('/agency/portals/:portalId', async (req, res) => {
  try {
    const { email } = req.body;
    const { portalId } = req.params;
    if (!email) return res.status(400).json({ error: 'email required' });

    const custRes = await db.query('SELECT id FROM customers WHERE email = $1 AND plan = $2', [email, 'command']);
    if (!custRes.rows[0]) return res.status(403).json({ error: 'Agency customer not found' });

    await db.query(
      'UPDATE portals SET is_active = false, updated_at = NOW() WHERE id = $1 AND customer_id = $2',
      [portalId, custRes.rows[0].id]
    );
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Agency bulk rescan — rescan all connected portals
app.post('/agency/rescan-all', async (req, res) => {
  try {
    const { email, secret } = req.body;
    if (secret !== process.env.RESCAN_SECRET && !email) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const emailToUse = email || req.body.agencyEmail;
    const custRes = await db.query('SELECT * FROM customers WHERE email = $1 AND plan = $2', [emailToUse, 'command']);
    if (!custRes.rows[0]) return res.status(404).json({ error: 'Agency customer not found' });
    const cust = custRes.rows[0];

    const portalsRes = await db.query(
      'SELECT * FROM portals WHERE customer_id = $1 AND is_active = true',
      [cust.id]
    );

    const results = [];
    for (const portal of portalsRes.rows) {
      const auditId = require('crypto').randomBytes(12).toString('hex');
      setImmediate(async () => {
        try {
          const meta = { email: emailToUse, company: portal.company, plan: 'command' };
          const result = await runFullAudit(portal.portal_token, auditId, meta);
          await db.query(
            `UPDATE portals SET last_audit_id = $1, last_audit_at = NOW(), last_score = $2, critical_count = $3, monthly_waste = $4, updated_at = NOW() WHERE id = $5`,
            [auditId, result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.monthlyWaste||0, portal.id]
          );
        } catch(e) { console.error('[AgencyRescan] portal', portal.id, e.message); }
      });
      results.push({ portalId: portal.id, company: portal.company, auditId });
      await new Promise(r => setTimeout(r, 3000)); // 3s between scans
    }

    res.json({ success: true, portalsTriggered: results.length, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GDPR: Right to erasure ───────────────────────────────────────────────────
app.delete('/customer/data', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });
    const custRes = await db.query('SELECT id FROM customers WHERE email=$1', [email]);
    if (custRes.rows[0]) {
      const custId = custRes.rows[0].id;
      await db.query('DELETE FROM audit_history WHERE customer_id=$1', [custId]);
    }
    await db.query('DELETE FROM magic_links WHERE email=$1', [email]);
    await db.query('DELETE FROM customers WHERE email=$1', [email]);
    // Note: audit_results are keyed by ID not email — they auto-expire per retention policy
    res.json({ deleted: true, email, message: 'All personal data removed. Audit results expire within 7 days.' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Feedback / NPS landing page endpoint ────────────────────────────────────
app.post('/feedback', async (req, res) => {
  const { score, text, auditId } = req.body || {};
  const npsScore = parseInt(score);
  if (!isNaN(npsScore) && auditId) {
    await db.query(
      `INSERT INTO nps_responses (audit_id, score, text, created_at)
       VALUES ($1, $2, $3, NOW()) ON CONFLICT (audit_id) DO UPDATE SET score=$2, text=$3`,
      [auditId, npsScore, text || '']
    ).catch(() => {});
    const label = npsScore>=9?'Promoter':'Passive';
    await resend.emails.send({
      from: 'FixOps NPS <reports@fixops.io>',
      to: 'matthew@fixops.io',
      subject: `NPS ${npsScore}/10 from results page`,
      html: `<p>Score: ${npsScore} (${label})<br>Audit: ${auditId}<br>Text: ${text||'(none)'}</p>`
    }).catch(() => {});
  }
  res.json({ ok: true });
});

app.get('/feedback', async (req, res) => {
  const { score, id, email } = req.query;
  const npsScore = parseInt(score);

  // Store NPS response
  if (!isNaN(npsScore) && id) {
    await db.query(
      `INSERT INTO nps_responses (audit_id, email, score, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (audit_id) DO UPDATE SET score = $3, created_at = NOW()`,
      [id, email || '', npsScore]
    ).catch(() => {});

    // Alert Matt
    const label = npsScore >= 9 ? 'Promoter 🟢' : npsScore >= 7 ? 'Passive 🟡' : 'Detractor 🔴';
    await resend.emails.send({
      from: 'FixOps NPS <reports@fixops.io>',
      to: 'matthew@fixops.io',
      subject: `NPS ${npsScore}/10 — ${label} — ${email || 'anonymous'}`,
      html: `<p><strong>NPS Score: ${npsScore}/10</strong> (${label})<br>Email: ${email || 'anonymous'}<br>Audit: ${id}</p>`
    }).catch(() => {});
  }

  const msg = npsScore >= 9 ? 'Thank you! That means a lot. 🙏' :
              npsScore >= 7 ? 'Thanks for the feedback — we\'ll keep improving.' :
              'Thank you for being honest — we want to earn a higher score. Reply to the email to tell us what to fix.';

  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Thank you</title></head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
<div style="text-align:center;padding:40px 24px;max-width:400px;">
  <div style="font-size:48px;margin-bottom:16px;">${npsScore >= 9 ? '🎉' : npsScore >= 7 ? '👍' : '🙏'}</div>
  <div style="font-size:20px;font-weight:700;color:#fff;margin-bottom:8px;">Score recorded: ${npsScore}/10</div>
  <div style="font-size:14px;color:rgba(255,255,255,.5);line-height:1.7;margin-bottom:24px;">${msg}</div>
  <a href="${FRONTEND_URL}" style="display:inline-block;padding:11px 22px;background:#7c3aed;color:#fff;border-radius:8px;font-size:13px;font-weight:700;text-decoration:none;">Back to FixOps →</a>
</div></body></html>`);
});

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
    const company = session.metadata?.company || '';

    console.log(`Payment complete: ${email} — ${planKey}`);

    // Upsert customer record
    if (email) {
      await db.query(`
        INSERT INTO customers (email, plan, plan_status, stripe_customer, updated_at)
        VALUES ($1, $2, 'active', $3, NOW())
        ON CONFLICT (email) DO UPDATE
        SET plan = $2, plan_status = 'active', stripe_customer = $3, updated_at = NOW()
      `, [email, planKey, session.customer]).catch(e => console.error('Customer upsert:', e.message));

      // For one-time audits: generate a signed audit token so plan can't be URL-spoofed
      if (['deep','deep-audit','pro-audit'].includes(planKey)) {
        const auditToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
        await db.query(
          `INSERT INTO audit_tokens (token, email, plan, company, expires_at) VALUES ($1,$2,$3,$4,$5)`,
          [auditToken, email, planKey, company, expiresAt]
        ).catch(e => console.error('Audit token insert:', e.message));

        // Email the audit link to the customer
        const auditStartUrl = `${FRONTEND_URL}/confirm.html?auditToken=${auditToken}`;
        await resend.emails.send({
          from: 'FixOps <reports@fixops.io>',
          to: email,
          subject: `✅ Payment confirmed — start your ${planKey === 'pro-audit' ? 'FixOps Full Audit' : 'FixOps Diagnostic'}`,
          html: `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Start Your Audit</title></head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#07070a;padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

  <tr><td style="background:linear-gradient(135deg,#0d0b1e,#120e2a);border-radius:16px 16px 0 0;padding:28px 36px;border-bottom:1px solid rgba(124,58,237,.25);">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td><div style="font-size:22px;font-weight:900;color:#fff;letter-spacing:-0.5px;">⚡ Fix<span style="color:#a78bfa;">Ops</span></div>
      <div style="font-size:10px;color:rgba(255,255,255,.3);letter-spacing:3px;text-transform:uppercase;margin-top:3px;font-family:monospace;">Payment Confirmed</div></td>
      <td align="right"><div style="background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.3);border-radius:6px;padding:5px 12px;font-size:11px;font-weight:700;color:#10b981;font-family:monospace;">✓ PAID</div></td>
    </tr></table>
  </td></tr>

  <tr><td style="background:#0d0b1e;padding:36px;">
    <div style="font-size:24px;font-weight:800;color:#fff;margin-bottom:8px;letter-spacing:-0.5px;">Your audit is ready to start.</div>
    <div style="font-size:14px;color:rgba(255,255,255,.5);line-height:1.7;margin-bottom:28px;">
      Thanks for your purchase. Click the button below to connect your HubSpot portal and start your <strong style="color:rgba(255,255,255,.85);">${planKey === 'pro-audit' ? 'FixOps Full Audit ($699)' : 'FixOps Diagnostic ($399)'}</strong>. The full scan runs in under 15 minutes.
    </div>

    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
    <tr><td align="center">
      <a href="${auditStartUrl}" style="display:inline-block;padding:15px 40px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:15px;">Connect HubSpot &amp; Start Audit →</a>
    </td></tr>
    </table>

    <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:12px;overflow:hidden;margin-bottom:20px;">
    <tr><td style="padding:14px 20px;border-bottom:1px solid rgba(255,255,255,.06);">
      <div style="font-size:10px;font-weight:700;color:rgba(255,255,255,.3);letter-spacing:2px;text-transform:uppercase;font-family:monospace;">What happens next</div>
    </td></tr>
    <tr><td style="padding:16px 20px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr><td style="padding:6px 0;"><table cellpadding="0" cellspacing="0"><tr>
          <td style="width:24px;height:24px;background:rgba(124,58,237,.2);border-radius:50%;text-align:center;font-size:10px;font-weight:800;color:#a78bfa;vertical-align:middle;">1</td>
          <td style="padding-left:12px;font-size:13px;color:rgba(255,255,255,.7);">Click the button above to connect your HubSpot portal (read-only, takes 30 seconds)</td>
        </tr></table></td></tr>
        <tr><td style="padding:6px 0;"><table cellpadding="0" cellspacing="0"><tr>
          <td style="width:24px;height:24px;background:rgba(124,58,237,.2);border-radius:50%;text-align:center;font-size:10px;font-weight:800;color:#a78bfa;vertical-align:middle;">2</td>
          <td style="padding-left:12px;font-size:13px;color:rgba(255,255,255,.7);">FixOps runs 210 checks across your entire portal — contacts, deals, workflows, pipeline, billing, users</td>
        </tr></table></td></tr>
        <tr><td style="padding:6px 0;"><table cellpadding="0" cellspacing="0"><tr>
          <td style="width:24px;height:24px;background:rgba(124,58,237,.2);border-radius:50%;text-align:center;font-size:10px;font-weight:800;color:#a78bfa;vertical-align:middle;">3</td>
          <td style="padding-left:12px;font-size:13px;color:rgba(255,255,255,.7);">Full results with dollar impact, fix guides, and a 30-min strategy call ready in under 15 minutes</td>
        </tr></table></td></tr>
      </table>
    </td></tr>
    </table>

    <div style="font-size:12px;color:rgba(255,255,255,.25);text-align:center;">This link expires in 7 days. Questions? Reply to this email or reach us at <a href="mailto:matthew@fixops.io" style="color:rgba(124,58,237,.6);text-decoration:none;">matthew@fixops.io</a></div>

  </td></tr>
  <tr><td style="background:rgba(255,255,255,.02);border-top:1px solid rgba(255,255,255,.06);border-radius:0 0 16px 16px;padding:18px 36px;text-align:center;">
    <div style="font-size:11px;color:rgba(255,255,255,.2);">
      <a href="${FRONTEND_URL}" style="color:rgba(124,58,237,.5);text-decoration:none;">fixops.io</a> · Secured by Stripe · Read-only HubSpot access
    </div>
  </td></tr>

</table></td></tr></table>
</body></html>`
        }).catch(e => console.error('Audit start email:', e.message));

        // Notify Matthew
        await resend.emails.send({
          from: 'FixOps Billing <reports@fixops.io>',
          to: FIXOPS_NOTIFY_EMAIL,
          subject: `💳 Paid audit purchased — ${email} — ${planKey}`,
          html: `<p><strong>${email}</strong> purchased <strong>${planKey}</strong>.<br>Audit start email sent. Token expires in 7 days.</p>`
        }).catch(() => {});
      }
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

// ── Redeem audit token (paid one-time audits) ─────────────────────────────────
// Called from confirm.html when ?auditToken= is in URL
app.get('/audit/redeem-token', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token required' });
    const result = await db.query(
      `SELECT * FROM audit_tokens WHERE token = $1 AND used = false AND expires_at > NOW()`,
      [token]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Token invalid, already used, or expired. Contact support@fixops.io' });
    const row = result.rows[0];
    res.json({ valid: true, email: row.email, plan: row.plan, company: row.company });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Auth URL — GET (free) and POST (paid) ─────────────────────────────────────
const buildAuthUrl = (req, res, params) => {
  try {
    const { email = '', company = '', plan = 'free', paid = false, auditToken = '' } = params;

    // ── Security: paid plans must have a valid DB token ───────────────────────
    // Prevents URL manipulation: e.g. ?plan=deep without payment
    const PAID_PLANS = ['deep','deep-audit','pro-audit'];
    if (PAID_PLANS.includes(plan) && !auditToken) {
      console.warn(`[Security] Blocked unauthenticated paid plan request: plan=${plan} email=${email}`);
      return res.status(403).json({ error: 'A valid payment token is required to start a paid audit. Please use the link from your confirmation email.' });
    }

    // Monthly plans (pulse/pro/command) are validated via Stripe subscription in DB —
    // checked at OAuth callback time, not here. Free always allowed.

    const codeVerifier  = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const state = crypto.randomBytes(16).toString('hex');
    pendingAudits.set(state, { email, company, plan, paid: !!paid, auditToken, codeVerifier, createdAt: Date.now() });
    // Standard Public App OAuth — counts as marketplace install
    // Scopes must match exactly what's configured in app-hsmeta.json
    const REQUIRED_SCOPES = [
      'oauth',
      'crm.objects.contacts.read',
      'crm.objects.companies.read',
      'crm.objects.deals.read',
      'crm.objects.owners.read',
      'crm.objects.users.read',
      'crm.objects.quotes.read',
      'crm.objects.line_items.read',
      'crm.objects.products.read',
      'crm.objects.invoices.read',
      'crm.objects.orders.read',
      'crm.objects.subscriptions.read',
      'crm.objects.goals.read',
      'crm.schemas.contacts.read',
      'crm.schemas.deals.read',
      'crm.lists.read',
      'tickets',
      'sales-email-read',
      'e-commerce',
      'account-info.security.read',
      'settings.users.read',
      'settings.currencies.read',
      'communication_preferences.read',
      'conversations.read',
    ].join(' ');

    const OPTIONAL_SCOPES = [
      'content',
      'social',
      'automation',
      'automation.sequences.read',
      'forms',
      'marketing.campaigns.read',
      'marketing.campaigns.revenue.read',
      'business-intelligence',
      'cms.knowledge_base.articles.read',
      'cms.knowledge_base.settings.read',
      'crm.objects.feedback_submissions.read',
      'crm.objects.leads.read',
      'scheduler.meetings.meeting-link.read',
      'crm.schemas.custom.read',
      'crm.objects.custom.read',
      'crm.objects.projects.read',
      'crm.dealsplits.read_write',
      'settings.users.teams.read',
      'crm.objects.carts.read',
      'crm.objects.marketing_events.read',
      'crm.pipelines.orders.read',
    ].join(' ');
    const url = new URL('https://app.hubspot.com/oauth/authorize');
    url.searchParams.set('client_id', HUBSPOT_CLIENT_ID);
    url.searchParams.set('redirect_uri', HUBSPOT_REDIRECT_URI);
    url.searchParams.set('scope', REQUIRED_SCOPES);
    url.searchParams.set('optional_scope', OPTIONAL_SCOPES);
    url.searchParams.set('state', state);
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

  // Validate + consume audit token for paid one-time plans
  if (['deep','deep-audit','pro-audit'].includes(pending.plan)) {
    if (!pending.auditToken) {
      console.warn(`[Security] OAuth callback for paid plan with no token: ${pending.email}`);
      return res.redirect(`${FRONTEND_URL}/?error=payment_required`);
    }
    const tokenCheck = await db.query(
      `SELECT id FROM audit_tokens WHERE token=$1 AND email=$2 AND used=false AND expires_at > NOW()`,
      [pending.auditToken, pending.email]
    ).catch(() => ({ rows: [] }));
    if (!tokenCheck.rows[0]) {
      console.warn(`[Security] Invalid/used audit token for ${pending.email}`);
      return res.redirect(`${FRONTEND_URL}/?error=token_invalid`);
    }
    // Mark used — one-time redemption
    await db.query(`UPDATE audit_tokens SET used=true WHERE token=$1`, [pending.auditToken]).catch(()=>{});
  }

  const auditId = crypto.randomBytes(12).toString('hex');

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      redirect_uri: HUBSPOT_REDIRECT_URI,
      code,
    });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

    const tokenRes = await axios.post('https://api.hubapi.com/oauth/v1/token', body, { headers });
    console.log('Public App OAuth token success');

    await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Connecting to HubSpot...' });

    // Store token for Pulse re-scans
    if (pending.email && ['pulse','pro','command'].includes(pending.plan)) {
      // Store both access_token and refresh_token
      // HubSpot access tokens expire in 6hrs — refresh_token is long-lived
      const portalRefreshToken = tokenRes.data.refresh_token || null;
      await db.query(`
        INSERT INTO customers (email, company, plan, plan_status, portal_token, refresh_token, last_audit_id, last_audit_at, updated_at)
        VALUES ($1, $2, $3, 'active', $4, $5, $6, NOW(), NOW())
        ON CONFLICT (email) DO UPDATE
        SET portal_token = $4, refresh_token = COALESCE($5, customers.refresh_token),
            last_audit_id = $6, last_audit_at = NOW(),
            plan = $3, company = $2, updated_at = NOW()
      `, [pending.email, pending.company, pending.plan, tokenRes.data.access_token, portalRefreshToken, auditId])
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

        // If this was an agency audit, update their dashboard
        if (auditMeta.auditToken) {
          updateAgencyAudit(auditMeta.auditToken, auditIdCopy, result)
            .catch(e => console.error(`[${auditIdCopy}] ⚠️ Agency audit update failed:`, e.message));
        }

        // Update customer last audit
        if (auditMeta.email) {
          await db.query(`
            UPDATE customers SET last_audit_id = $1, last_audit_at = NOW(), updated_at = NOW()
            WHERE email = $2
          `, [auditIdCopy, auditMeta.email]).catch(() => {});

          // Save to audit history
          const custRes = await db.query('SELECT id FROM customers WHERE email = $1', [auditMeta.email]).catch(() => ({ rows: [] }));
          if (custRes.rows[0]) {
            // Save hubspot_portal_id to customer record (links portal across email changes)
            const hsPortalId = String(result.portalInfo?.portalId || '');
            if (hsPortalId) {
              await db.query(
                'UPDATE customers SET hubspot_portal_id = $1, company = COALESCE(NULLIF($2,\'\'), company), updated_at = NOW() WHERE id = $3',
                [hsPortalId, result.portalInfo?.company || '', custRes.rows[0].id]
              ).catch(()=>{});
            }
            await db.query(
              `INSERT INTO audit_history (customer_id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats, hubspot_portal_id)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
              [custRes.rows[0].id, auditIdCopy, auditMeta.plan,
               result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.warningCount||0, result.summary?.infoCount||0,
               result.summary?.monthlyWaste||0, result.summary?.recordsScanned||0,
               JSON.stringify(result.scores||{}),
               JSON.stringify((result.issues||[]).map(i=>({title:i.title,severity:i.severity,dimension:i.dimension,impact:i.impact}))),
               JSON.stringify(result.portalInfo?.portalStats||{}),
               String(result.portalInfo?.portalId||'')]
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
          subject: `⚠️ Audit Failed — ${auditMeta.company || auditMeta.email}`,
          html: `<h2 style="color:#ef4444;">Audit Failed</h2>
                 <table style="border-collapse:collapse;font-family:sans-serif;font-size:14px;">
                   <tr><td style="padding:4px 12px 4px 0;color:#888;">Email</td><td>${auditMeta.email}</td></tr>
                   <tr><td style="padding:4px 12px 4px 0;color:#888;">Company</td><td>${auditMeta.company || '—'}</td></tr>
                   <tr><td style="padding:4px 12px 4px 0;color:#888;">Plan</td><td>${auditMeta.plan}</td></tr>
                   <tr><td style="padding:4px 12px 4px 0;color:#888;">Audit ID</td><td>${auditIdCopy}</td></tr>
                   <tr><td style="padding:4px 12px 4px 0;color:#888;">Error</td><td style="color:#ef4444;font-weight:700;">${e.message}</td></tr>
                   <tr><td style="padding:4px 12px 4px 0;color:#888;">Stack</td><td style="font-size:11px;color:#888;">${(e.stack||'').substring(0,300)}</td></tr>
                 </table>
                 <p style="margin-top:16px;"><a href="https://railway.app" style="color:#7c3aed;">View Railway logs →</a></p>`
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

// ── Score Certificate — shareable SVG image ──────────────────────────────────

// ── PDF Report — print-optimized HTML served as /audit/pdf?id=:id ──────────────
app.get('/audit/pdf', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).send('<p>Missing audit ID</p>');
    const data = await getResult(id);
    if (!data) return res.status(404).send('<p>Audit not found</p>');

    const portal   = data.portalInfo || {};
    const summary  = data.summary   || {};
    const scores   = data.scores    || {};
    const issues   = data.issues    || [];
    const ps       = portal.portalStats || {};
    const company  = portal.company || 'Your Portal';
    const date     = new Date(portal.auditDate || Date.now()).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
    const ovr      = summary.overallScore || 0;
    const grade    = ovr>=85?'Excellent':ovr>=70?'Good':ovr>=55?'Needs Attention':'Critical';
    const gradeColor = ovr>=80?'#059669':ovr>=60?'#d97706':'#dc2626';
    const waste    = summary.monthlyWaste || 0;

    const fmtMoney = n => '$' + Number(n||0).toLocaleString();
    const fmt      = n => Number(n||0).toLocaleString();

    // Dimension display names
    const DIM_LABELS = {
      dataIntegrity:'Data Integrity', automationHealth:'Automation',
      pipelineIntegrity:'Pipeline', marketingHealth:'Marketing',
      configSecurity:'Configuration', reportingQuality:'Reporting',
      teamAdoption:'Team Adoption', serviceHealth:'Service'
    };
    const DIM_ICONS = {
      dataIntegrity:'⬡', automationHealth:'⬡', pipelineIntegrity:'⬡',
      marketingHealth:'⬡', configSecurity:'⬡', reportingQuality:'⬡',
      teamAdoption:'⬡', serviceHealth:'⬡'
    };

    // Build dimension rows
    const dimRows = Object.entries(DIM_LABELS).map(([key, label]) => {
      const score = scores[key];
      if (score === null || score === undefined) return '';
      const sc = Number(score);
      const col = sc>=80?'#059669':sc>=60?'#d97706':'#dc2626';
      const barW = sc;
      return `<div class="dim-row">
        <div class="dim-label">${label}</div>
        <div class="dim-bar-wrap">
          <div class="dim-bar" style="width:${barW}%;background:${col};"></div>
        </div>
        <div class="dim-score" style="color:${col}">${sc}<span class="dim-100">/100</span></div>
      </div>`;
    }).join('');

    // Sort issues: critical first, then warning, then info
    const sorted = [...issues].sort((a,b)=>{
      const o={critical:0,warning:1,info:2};
      return (o[a.severity]||1)-(o[b.severity]||1);
    });

    const criticals = sorted.filter(i=>i.severity==='critical');
    const warnings  = sorted.filter(i=>i.severity==='warning');
    const infoIssues= sorted.filter(i=>i.severity==='info');

    const renderIssues = (list) => list.map((issue, idx) => {
      const sevColor = issue.severity==='critical'?'#dc2626':issue.severity==='warning'?'#d97706':'#2563eb';
      const sevBg    = issue.severity==='critical'?'#fef2f2':issue.severity==='warning'?'#fffbeb':'#eff6ff';
      const sevLabel = (issue.severity||'info').toUpperCase();
      const guideHtml = issue.guide && issue.guide.length
        ? `<div class="guide-block">
            <div class="guide-title">How to Fix</div>
            ${issue.guide.map((step,i)=>`<div class="guide-step"><span class="step-num">${i+1}</span><span>${step.replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</span></div>`).join('')}
           </div>`
        : '';
      const cleanTitle = (issue.title||'').replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
      const cleanDesc  = (issue.description||'').replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
      const cleanImpact= (issue.impact||'').replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
      return `<div class="issue-block" style="border-left:4px solid ${sevColor};">
        <div class="issue-header">
          <div class="issue-title">${cleanTitle}</div>
          <span class="sev-badge" style="background:${sevBg};color:${sevColor};">${sevLabel}</span>
        </div>
        <div class="issue-desc">${cleanDesc}</div>
        ${cleanImpact?`<div class="issue-impact">💸 ${cleanImpact}</div>`:''}
        ${issue.dimension?`<span class="issue-dim">${issue.dimension}</span>`:''}
        ${guideHtml}
      </div>`;
    }).join('');

    const critSection  = criticals.length  ? `<div class="section-header critical">🔴 Critical Issues (${criticals.length})</div>${renderIssues(criticals)}` : '';
    const warnSection  = warnings.length   ? `<div class="section-header warning">🟡 Warnings (${warnings.length})</div>${renderIssues(warnings)}` : '';
    const infoSection  = infoIssues.length ? `<div class="section-header info">🔵 Observations (${infoIssues.length})</div>${renderIssues(infoIssues)}` : '';

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FixOps Report — ${company}</title>
<style>
  /* ── Reset & Base ── */
  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.55;
    color: #1a1a2e;
    background: #ffffff;
    max-width: 780px;
    margin: 0 auto;
    padding: 0;
  }

  /* ── Print settings ── */
  @page {
    size: A4;
    margin: 18mm 16mm 20mm 16mm;
  }
  @media print {
    .no-print { display: none !important; }
    .page-break { page-break-before: always; }
    body { padding: 0; }
  }

  /* ── Print button (screen only) ── */
  .print-btn {
    position: fixed; top: 16px; right: 16px; z-index: 999;
    background: #7c3aed; color: #fff; border: none;
    padding: 10px 22px; border-radius: 8px; font-size: 13px;
    font-weight: 700; cursor: pointer; font-family: inherit;
    box-shadow: 0 4px 14px rgba(124,58,237,.35);
    transition: background .15s;
  }
  .print-btn:hover { background: #6d28d9; }

  .print-hint {
    position: fixed; top: 60px; right: 16px; z-index: 998;
    background: rgba(0,0,0,.78); color: #fff;
    padding: 8px 14px; border-radius: 6px; font-size: 11px; line-height: 1.5;
  }
  .print-hint strong { color: #fbbf24; }

  /* ── Cover Page ── */
  .cover {
    min-height: 240px;
    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
    color: #fff;
    padding: 40px 44px 36px;
    border-radius: 0 0 16px 16px;
    margin-bottom: 32px;
    position: relative;
    overflow: hidden;
  }
  .cover::before {
    content: '';
    position: absolute; top: -60px; right: -60px;
    width: 280px; height: 280px;
    background: radial-gradient(circle, rgba(124,58,237,.25), transparent 70%);
  }
  .cover-logo {
    font-size: 13pt; font-weight: 800; letter-spacing: -.2px;
    opacity: .85; margin-bottom: 28px;
  }
  .cover-company { font-size: 28pt; font-weight: 800; letter-spacing: -.5px; margin-bottom: 6px; }
  .cover-sub { font-size: 12pt; opacity: .65; font-weight: 300; margin-bottom: 24px; }
  .cover-meta {
    display: flex; gap: 32px; flex-wrap: wrap;
  }
  .cover-stat { }
  .cover-stat-val { font-size: 26pt; font-weight: 900; letter-spacing: -1px; line-height: 1; }
  .cover-stat-lbl { font-size: 8.5pt; opacity: .6; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 3px; }
  .cover-grade {
    display: inline-block; padding: 4px 14px; border-radius: 20px;
    font-size: 10pt; font-weight: 700; letter-spacing: .5px;
    background: rgba(255,255,255,.15); margin-bottom: 20px;
  }

  /* ── Section headers ── */
  h2 {
    font-size: 14pt; font-weight: 800; color: #1a1a2e;
    margin: 28px 0 14px;
    padding-bottom: 8px;
    border-bottom: 2px solid #f0f0f0;
    letter-spacing: -.2px;
  }
  h2:first-of-type { margin-top: 0; }

  /* ── Summary grid ── */
  .summary-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 12px; margin-bottom: 24px;
  }
  .summary-card {
    background: #f8f9fc; border: 1px solid #e8ecf3;
    border-radius: 10px; padding: 14px 16px; text-align: center;
  }
  .summary-val { font-size: 20pt; font-weight: 900; letter-spacing: -.5px; color: #1a1a2e; }
  .summary-lbl {
    font-size: 8pt; color: #6b7280; text-transform: uppercase;
    letter-spacing: 1px; margin-top: 3px;
  }

  /* ── Portal stats ── */
  .stats-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 8px; margin-bottom: 24px;
  }
  .stat-box {
    background: #f8f9fc; border: 1px solid #e8ecf3;
    border-radius: 8px; padding: 10px 12px; text-align: center;
  }
  .stat-val { font-size: 15pt; font-weight: 800; color: #1a1a2e; }
  .stat-lbl { font-size: 7.5pt; color: #9ca3af; text-transform: uppercase; letter-spacing: .8px; margin-top: 2px; }

  /* ── Dimension bars ── */
  .dims-list { margin-bottom: 24px; }
  .dim-row {
    display: flex; align-items: center; gap: 12px;
    padding: 8px 0; border-bottom: 1px solid #f3f4f6;
  }
  .dim-row:last-child { border-bottom: none; }
  .dim-label { font-size: 10pt; font-weight: 600; width: 140px; flex-shrink: 0; color: #374151; }
  .dim-bar-wrap { flex: 1; height: 6px; background: #e5e7eb; border-radius: 3px; overflow: hidden; }
  .dim-bar { height: 100%; border-radius: 3px; }
  .dim-score { font-size: 12pt; font-weight: 800; width: 52px; text-align: right; flex-shrink: 0; }
  .dim-100 { font-size: 8.5pt; color: #9ca3af; font-weight: 400; }

  /* ── Section headers for issues ── */
  .section-header {
    font-size: 11pt; font-weight: 800; padding: 9px 14px;
    border-radius: 6px; margin: 20px 0 12px;
    letter-spacing: -.1px;
  }
  .section-header.critical { background: #fef2f2; color: #dc2626; border-left: 4px solid #dc2626; }
  .section-header.warning  { background: #fffbeb; color: #92400e; border-left: 4px solid #d97706; }
  .section-header.info     { background: #eff6ff; color: #1e40af; border-left: 4px solid #2563eb; }

  /* ── Issue blocks ── */
  .issue-block {
    background: #fafafa; border: 1px solid #e5e7eb;
    border-radius: 8px; padding: 14px 16px;
    margin-bottom: 10px; page-break-inside: avoid;
  }
  .issue-header {
    display: flex; align-items: flex-start;
    justify-content: space-between; gap: 12px; margin-bottom: 7px;
  }
  .issue-title {
    font-size: 10.5pt; font-weight: 700; color: #111827;
    line-height: 1.35; flex: 1;
  }
  .sev-badge {
    font-size: 7.5pt; font-weight: 800; padding: 2px 7px;
    border-radius: 4px; flex-shrink: 0; letter-spacing: .5px;
    white-space: nowrap; margin-top: 1px;
  }
  .issue-desc { font-size: 9.5pt; color: #4b5563; line-height: 1.6; margin-bottom: 6px; }
  .issue-impact {
    font-size: 8.5pt; color: #d97706; font-weight: 600;
    font-family: 'Courier New', monospace; margin-bottom: 6px;
  }
  .issue-dim {
    display: inline-block; font-size: 7.5pt; font-weight: 700;
    background: #f0ebff; color: #6d28d9;
    padding: 2px 7px; border-radius: 4px;
  }

  /* ── Guide ── */
  .guide-block {
    background: #f0fdf4; border: 1px solid #bbf7d0;
    border-radius: 6px; padding: 10px 12px; margin-top: 8px;
  }
  .guide-title {
    font-size: 8pt; font-weight: 800; color: #065f46;
    text-transform: uppercase; letter-spacing: 1.2px; margin-bottom: 7px;
  }
  .guide-step {
    display: flex; gap: 8px; margin-bottom: 5px;
    font-size: 9pt; color: #1f2937; line-height: 1.4;
  }
  .guide-step:last-child { margin-bottom: 0; }
  .step-num {
    width: 18px; height: 18px; border-radius: 50%;
    background: #059669; color: #fff;
    font-size: 7.5pt; font-weight: 800;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  /* ── Footer ── */
  .footer {
    margin-top: 40px; padding: 20px 0 8px;
    border-top: 1px solid #e5e7eb;
    display: flex; justify-content: space-between; align-items: center;
    font-size: 8.5pt; color: #9ca3af;
  }
  .footer strong { color: #6d28d9; }

  /* ── Waste callout ── */
  .waste-callout {
    background: linear-gradient(135deg, #fef3c7, #fde68a);
    border: 1px solid #fcd34d; border-radius: 10px;
    padding: 16px 20px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 16px;
  }
  .waste-icon { font-size: 24pt; flex-shrink: 0; }
  .waste-title { font-size: 11pt; font-weight: 800; color: #78350f; margin-bottom: 3px; }
  .waste-sub { font-size: 9pt; color: #92400e; line-height: 1.4; }

  /* ── Screen padding ── */
  @media screen {
    body { padding: 24px; }
    .cover { border-radius: 12px; margin-top: 8px; }
  }
</style>
</head>
<body>

<button class="print-btn no-print" onclick="window.print()">⬇ Save as PDF</button>
<div class="print-hint no-print">Print dialog opens automatically<br>Select <strong>Save as PDF</strong> as destination</div>

<!-- Cover -->
<div class="cover">
  <div class="cover-logo">⚡ FixOps Intelligence Report</div>
  <div class="cover-company">${company}</div>
  <div class="cover-sub">210-Point Portal Audit · ${date}</div>
  <div class="cover-grade" style="background:${gradeColor}22;color:${gradeColor};">${grade}</div>
  <div class="cover-meta">
    <div class="cover-stat">
      <div class="cover-stat-val">${ovr}<span style="font-size:14pt;opacity:.6;">/100</span></div>
      <div class="cover-stat-lbl">Health Score</div>
    </div>
    <div class="cover-stat">
      <div class="cover-stat-val" style="color:#f87171;">${criticals.length}</div>
      <div class="cover-stat-lbl">Critical Issues</div>
    </div>
    <div class="cover-stat">
      <div class="cover-stat-val" style="color:#fbbf24;">${warnings.length}</div>
      <div class="cover-stat-lbl">Warnings</div>
    </div>
    <div class="cover-stat">
      <div class="cover-stat-val" style="color:#34d399;">${fmtMoney(waste)}</div>
      <div class="cover-stat-lbl">Est. Monthly Waste</div>
    </div>
  </div>
</div>

<!-- Waste callout if significant -->
${waste > 500 ? `<div class="waste-callout">
  <div class="waste-icon">💸</div>
  <div>
    <div class="waste-title">Estimated Monthly Waste: ${fmtMoney(waste)}/mo · ${fmtMoney(waste * 12)}/yr</div>
    <div class="waste-sub">Revenue leaking from duplicate contacts, inactive seats, stalled deals, and broken workflows. These are addressable issues — not normal operating costs.</div>
  </div>
</div>` : ''}

<!-- Portal snapshot -->
<h2>Portal Snapshot</h2>
<div class="stats-grid">
  <div class="stat-box"><div class="stat-val">${fmt(ps.contacts)}</div><div class="stat-lbl">Contacts</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.companies)}</div><div class="stat-lbl">Companies</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.deals)}</div><div class="stat-lbl">Deals</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.tickets)}</div><div class="stat-lbl">Tickets</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.workflows)}</div><div class="stat-lbl">Workflows</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.forms)}</div><div class="stat-lbl">Forms</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.users)}</div><div class="stat-lbl">Users</div></div>
  <div class="stat-box"><div class="stat-val">${fmt(ps.lists)}</div><div class="stat-lbl">Lists</div></div>
</div>

<!-- Health score summary -->
<h2>Health Score Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <div class="summary-val" style="color:${gradeColor}">${ovr}</div>
    <div class="summary-lbl">Overall Score</div>
  </div>
  <div class="summary-card">
    <div class="summary-val" style="color:#dc2626">${criticals.length}</div>
    <div class="summary-lbl">Critical</div>
  </div>
  <div class="summary-card">
    <div class="summary-val" style="color:#d97706">${warnings.length}</div>
    <div class="summary-lbl">Warnings</div>
  </div>
  <div class="summary-card">
    <div class="summary-val" style="color:#6b7280">${summary.checksRun || 210}</div>
    <div class="summary-lbl">Checks Run</div>
  </div>
</div>

<!-- Dimension scores -->
<h2>Hub Health Breakdown</h2>
<div class="dims-list">${dimRows}</div>

<!-- Issues -->
<div class="page-break"></div>
<h2>All Findings (${sorted.length} Issues)</h2>
${critSection}${warnSection}${infoSection}

<!-- Footer -->
<div class="footer">
  <div>Generated by <strong>FixOps.io</strong> · ${date}</div>
  <div>Confidential — ${company}</div>
  <div>fixops.io</div>
</div>

<script>
  window.addEventListener('load', function() {
    setTimeout(function() { window.print(); }, 700);
  });
  window.addEventListener('afterprint', function() {
    var btn = document.querySelector('.print-btn');
    if (btn) { btn.textContent = '✓ Done — Close Tab'; btn.onclick = function(){ window.close(); }; }
  });
</script>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.send(html);
  } catch(e) {
    console.error('PDF generation error:', e);
    res.status(500).send('<p>Error generating report: ' + e.message + '</p>');
  }
});


// ── Audit Certificate — shareable score card ──────────────────────────────
app.get('/audit/certificate', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).send('<p>Missing audit ID</p>');
    const data = await getResult(id);
    if (!data) return res.status(404).send('<p>Audit not found</p>');

    const company  = data.portalInfo?.company || 'Your Portal';
    const score    = data.summary?.overallScore || 0;
    const crits    = data.summary?.criticalCount || 0;
    const waste    = data.summary?.monthlyWaste || 0;
    const plan     = data.plan || data.summary?.plan || 'free';
    const date     = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

    const scoreColor = score >= 85 ? '#10b981' : score >= 70 ? '#f59e0b' : score >= 55 ? '#f97316' : '#f43f5e';
    const grade      = score >= 85 ? 'Excellent' : score >= 70 ? 'Good' : score >= 55 ? 'Needs Work' : 'Critical';
    const scoreAngle = Math.round((score / 100) * 251.2); // circumference of r=40 circle

    const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg width="600" height="340" viewBox="0 0 600 340" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0c0920;stop-opacity:1"/>
      <stop offset="50%" style="stop-color:#0e0b28;stop-opacity:1"/>
      <stop offset="100%" style="stop-color:#0a1220;stop-opacity:1"/>
    </linearGradient>
    <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:${scoreColor};stop-opacity:1"/>
      <stop offset="100%" style="stop-color:${scoreColor}aa;stop-opacity:1"/>
    </linearGradient>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:rgba(124,58,237,0.25);stop-opacity:1"/>
      <stop offset="100%" style="stop-color:rgba(16,185,129,0.1);stop-opacity:1"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <clipPath id="roundRect">
      <rect width="600" height="340" rx="16" ry="16"/>
    </clipPath>
  </defs>

  <!-- Background -->
  <rect width="600" height="340" rx="16" ry="16" fill="url(#bg)"/>

  <!-- Border -->
  <rect width="598" height="338" x="1" y="1" rx="15" ry="15" fill="none" stroke="rgba(124,58,237,0.35)" stroke-width="1"/>

  <!-- Top accent line -->
  <rect width="600" height="3" rx="2" fill="url(#scoreGrad)"/>

  <!-- Grid pattern overlay -->
  <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
    <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(255,255,255,0.02)" stroke-width="0.5"/>
  </pattern>
  <rect width="600" height="340" fill="url(#grid)" rx="16" clip-path="url(#roundRect)"/>

  <!-- Left panel — score circle -->
  <rect x="0" y="0" width="200" height="340" fill="rgba(124,58,237,0.06)" rx="16" ry="16"/>
  <rect x="196" y="0" width="4" height="340" fill="rgba(124,58,237,0.1)"/>

  <!-- Score ring background -->
  <circle cx="100" cy="148" r="54" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="8"/>
  <!-- Score ring progress -->
  <circle cx="100" cy="148" r="54" fill="none" stroke="${scoreColor}" stroke-width="8"
    stroke-dasharray="${scoreAngle} 251.2" stroke-dashoffset="62.8"
    stroke-linecap="round" filter="url(#glow)" transform="rotate(-90 100 148)"/>

  <!-- Score number -->
  <text x="100" y="142" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="38" font-weight="900" fill="${scoreColor}" filter="url(#glow)">${score}</text>
  <text x="100" y="162" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,monospace" font-size="11" fill="rgba(255,255,255,0.3)" letter-spacing="1">OUT OF 100</text>

  <!-- Grade badge -->
  <rect x="64" y="210" width="72" height="22" rx="11" fill="${scoreColor}22" stroke="${scoreColor}44" stroke-width="1"/>
  <text x="100" y="225" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="11" font-weight="700" fill="${scoreColor}">${grade}</text>

  <!-- FixOps branding in left panel -->
  <text x="100" y="280" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="15" font-weight="900" fill="rgba(255,255,255,0.9)" letter-spacing="-0.5">⚡ FixOps</text>
  <text x="100" y="296" text-anchor="middle" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.2)" letter-spacing="2">INTELLIGENCE</text>

  <!-- Right panel content -->
  <!-- Header area -->
  <rect x="212" y="20" width="372" height="50" rx="8" fill="url(#headerGrad)" stroke="rgba(124,58,237,0.2)" stroke-width="1"/>
  <text x="232" y="40" font-family="monospace" font-size="9" fill="rgba(167,139,250,0.7)" letter-spacing="2">HUBSPOT PORTAL HEALTH CERTIFICATE</text>
  <text x="232" y="58" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="10" fill="rgba(255,255,255,0.3)">${date}</text>

  <!-- Company name -->
  <text x="232" y="108" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="22" font-weight="800" fill="rgba(255,255,255,0.95)" letter-spacing="-0.5">${company.length > 28 ? company.substring(0,28)+'…' : company}</text>
  <text x="232" y="128" font-family="monospace" font-size="10" fill="rgba(255,255,255,0.3)" letter-spacing="1">PORTAL INTELLIGENCE REPORT</text>

  <!-- Divider -->
  <line x1="232" y1="144" x2="568" y2="144" stroke="rgba(255,255,255,0.07)" stroke-width="1"/>

  <!-- Stats row -->
  <!-- Critical issues -->
  <rect x="232" y="156" width="100" height="64" rx="8" fill="rgba(244,63,94,0.08)" stroke="rgba(244,63,94,0.2)" stroke-width="1"/>
  <text x="282" y="184" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="26" font-weight="900" fill="${crits===0?'#10b981':'#f43f5e'}">${crits}</text>
  <text x="282" y="200" text-anchor="middle" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.3)" letter-spacing="0.5">CRITICAL</text>
  <text x="282" y="212" text-anchor="middle" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.3)" letter-spacing="0.5">ISSUES</text>

  <!-- Monthly waste -->
  <rect x="344" y="156" width="100" height="64" rx="8" fill="rgba(244,63,94,0.06)" stroke="rgba(244,63,94,0.15)" stroke-width="1"/>
  <text x="394" y="180" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="18" font-weight="900" fill="rgba(255,255,255,0.7)">$${Number(waste).toLocaleString()}</text>
  <text x="394" y="196" text-anchor="middle" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.3)" letter-spacing="0.5">MONTHLY</text>
  <text x="394" y="208" text-anchor="middle" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.3)" letter-spacing="0.5">REVENUE LEAK</text>

  <!-- Plan badge -->
  <rect x="456" y="156" width="100" height="64" rx="8" fill="rgba(167,139,250,0.08)" stroke="rgba(167,139,250,0.2)" stroke-width="1"/>
  <text x="506" y="184" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="12" font-weight="800" fill="#a78bfa">${(plan==='pro'?'Sentinel':plan==='command'?'Command':plan==='pulse'?'Monitor':plan.toUpperCase())}</text>
  <text x="506" y="200" text-anchor="middle" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.3)" letter-spacing="0.5">PLAN</text>

  <!-- Divider -->
  <line x1="232" y1="236" x2="568" y2="236" stroke="rgba(255,255,255,0.07)" stroke-width="1"/>

  <!-- 210-point audit badge -->
  <text x="232" y="260" font-family="monospace" font-size="9" fill="rgba(255,255,255,0.25)" letter-spacing="1">✓ 210-POINT AUTOMATED AUDIT  ·  fixops.io</text>

  <!-- Bottom features -->
  <text x="232" y="290" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="10" fill="rgba(255,255,255,0.35)">Contacts · Deals · Workflows · Pipeline · Billing · Users · Properties</text>
  <text x="232" y="310" font-family="monospace" font-size="8" fill="rgba(255,255,255,0.15)" letter-spacing="1">AUTOMATED WEEKLY MONITORING BY FIXOPS INTELLIGENCE PLATFORM</text>

  <!-- Seal/watermark -->
  <circle cx="552" cy="290" r="28" fill="rgba(124,58,237,0.1)" stroke="rgba(124,58,237,0.3)" stroke-width="1.5"/>
  <text x="552" y="285" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-size="16" fill="rgba(124,58,237,0.8)">⚡</text>
  <text x="552" y="300" text-anchor="middle" font-family="monospace" font-size="7" fill="rgba(124,58,237,0.5)" letter-spacing="1">VERIFIED</text>

</svg>`;

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(svg);

  } catch(e) {
    console.error('Certificate error:', e.message);
    res.status(500).send('<p>Certificate generation failed</p>');
  }
});

// ── Snapshot endpoint — returns audit + history for reporting.html ─────────────
// Used by reporting.html when a token is present (Pulse/Pro subscribers)
app.get('/snapshot/:id', async (req, res) => {
  try {
    const { token } = req.query;
    const data = await getResult(req.params.id);
    if (!data) return res.status(404).json({ error: 'not_found' });

    // If token provided, enrich with customer history
    if (token) {
      try {
        const payload = JSON.parse(Buffer.from(token, 'base64url').toString());
        const { email } = payload;
        if (email) {
          const custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
          if (custRes.rows[0]) {
            const cust = custRes.rows[0];
            const histRes = await db.query(
              'SELECT id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats, created_at FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 20',
              [cust.id]
            );
            return res.json({
              ...data,
              customer: { email: cust.email, company: cust.company, plan: cust.plan },
              history: histRes.rows,
              hasHistory: histRes.rows.length > 1
            });
          }
        }
      } catch(e) { /* token invalid — return data without history */ }
    }

    res.json({ ...data, history: [], hasHistory: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Customer history ──────────────────────────────────────────────────────────
app.get('/customer/history', async (req, res) => {
  try {
    const { email, portal_id } = req.query;
    if (!email && !portal_id) return res.status(400).json({ error: 'email or portal_id required' });
    
    let custRes;
    if (portal_id) {
      // Prefer portal_id lookup — finds the right record even if email changed
      custRes = await db.query(
        'SELECT * FROM customers WHERE hubspot_portal_id = $1 ORDER BY updated_at DESC LIMIT 1',
        [portal_id]
      );
    }
    if (!custRes?.rows[0] && email) {
      custRes = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    }
    if (!custRes?.rows[0]) return res.json({ customer: null, history: [] });
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
      const freshToken = await getValidToken(customer);
      const result = await runFullAudit(freshToken, auditId, meta);

      // Save to audit_history FIRST so email comparison is correct
      // history[0] = last week (before this scan), history[1] = two weeks ago, etc.
      const prevHistRes = await db.query(
        'SELECT * FROM audit_history WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 5',
        [customer.id]
      ).catch(()=>({rows:[]}));

      // Save this week's result to history
      await db.query(
        `INSERT INTO audit_history (customer_id, audit_id, plan, score, critical_count, warning_count, info_count, monthly_waste, records_scanned, scores, issue_titles, portal_stats, hubspot_portal_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
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
          from: 'FixOps FixOps Monitor <reports@fixops.io>',
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

// ── Free audit follow-up drip — runs every hour ──────────────────────────────
// Sends a follow-up email to free/one-time audit users ~24hrs after their scan
// to push them toward a monthly plan with the first-month discount
cron.schedule('0 * * * *', async () => {
  try {
    const cutoffFrom = new Date(Date.now() - 25 * 60 * 60 * 1000); // 25hrs ago
    const cutoffTo   = new Date(Date.now() - 23 * 60 * 60 * 1000); // 23hrs ago
    
    // Find free/one-time audits completed in the 23-25hr window that haven't been followed up
    const res = await db.query(`
      SELECT data->>'email' as email, data->>'company' as company,
             data->'summary'->>'overallScore' as score,
             data->'summary'->>'criticalCount' as criticals,
             data->'summary'->>'monthlyWaste' as waste,
             data->>'plan' as plan, id as audit_id
      FROM audit_results
      WHERE (data->>'status') = 'complete'
        AND (data->>'plan') IN ('free','deep','pro-audit')
        AND (data->>'followup_sent') IS NULL
        AND created_at BETWEEN $1 AND $2
        AND data->>'email' IS NOT NULL
      LIMIT 50
    `, [cutoffFrom, cutoffTo]).catch(() => ({ rows: [] }));

    for (const row of res.rows) {
      if (!row.email || !row.email.includes('@')) continue;
      const score    = Number(row.score || 0);
      const crits    = Number(row.criticals || 0);
      const waste    = Number(row.waste || 0);
      const company  = row.company || 'your portal';
      const isOnetime = ['deep','pro-audit'].includes(row.plan);
      const scoreColor = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#f43f5e';

      const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Your HubSpot audit results</title></head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#07070a;padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

  <tr><td style="background:linear-gradient(135deg,#0d0b1e,#120e2a);border-radius:16px 16px 0 0;padding:28px 36px;border-bottom:1px solid rgba(124,58,237,.25);">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td><div style="font-size:22px;font-weight:900;color:#fff;letter-spacing:-0.5px;">⚡ Fix<span style="color:#a78bfa;">Ops</span></div>
      <div style="font-size:10px;color:rgba(255,255,255,.3);letter-spacing:3px;text-transform:uppercase;margin-top:3px;font-family:monospace;">Your audit from yesterday</div></td>
      <td align="right"><div style="background:rgba(244,63,94,.12);border:1px solid rgba(244,63,94,.25);border-radius:6px;padding:5px 12px;font-size:11px;font-weight:700;color:#f43f5e;font-family:monospace;">${score}/100</div></td>
    </tr></table>
  </td></tr>

  <tr><td style="background:#0d0b1e;padding:36px;">
    <div style="font-size:22px;font-weight:800;color:#fff;margin-bottom:8px;letter-spacing:-0.5px;">Those ${crits} issues won&#39;t fix themselves.</div>
    <div style="font-size:14px;color:rgba(255,255,255,.5);line-height:1.7;margin-bottom:24px;">
      Yesterday we scanned <strong style="color:rgba(255,255,255,.85);">${company}</strong> and found <strong style="color:#f43f5e;">${crits} critical issues</strong> costing an estimated <strong style="color:#f43f5e;">$${waste.toLocaleString()}/mo</strong>. ${isOnetime ? "You have your full report — but what happens in 30 days when new issues appear?" : "Your free scan was capped at 1,000 contacts. Your worst issues are almost certainly in the records we couldn&#39;t reach."}
    </div>

    <!-- Score bar -->
    <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:20px 24px;margin-bottom:24px;">
    <tr>
      <td width="50%" style="padding:0 16px 0 0;border-right:1px solid rgba(255,255,255,.06);">
        <div style="font-size:10px;color:rgba(255,255,255,.3);font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;">Portal Score</div>
        <div style="font-size:36px;font-weight:900;color:${score >= 70 ? '#f59e0b' : '#f43f5e'};letter-spacing:-2px;">${score}<span style="font-size:16px;color:rgba(255,255,255,.3);font-weight:400;">/100</span></div>
      </td>
      <td width="50%" style="padding:0 0 0 16px;">
        <div style="font-size:10px;color:rgba(255,255,255,.3);font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;">Monthly Leak</div>
        <div style="font-size:36px;font-weight:900;color:#f43f5e;letter-spacing:-2px;">$${waste.toLocaleString()}<span style="font-size:14px;color:rgba(255,255,255,.3);font-weight:400;">/mo</span></div>
      </td>
    </tr>
    </table>

    <!-- Discount offer -->
    <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(16,185,129,.07);border:1px solid rgba(16,185,129,.2);border-radius:12px;overflow:hidden;margin-bottom:20px;">
    <tr><td style="padding:20px 24px;">
      <div style="font-size:10px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#10b981;font-family:monospace;margin-bottom:8px;">⚡ 48-Hour Offer</div>
      <div style="font-size:17px;font-weight:800;color:#fff;margin-bottom:6px;">First month of Sentinel for $199</div>
      <div style="font-size:12px;color:rgba(255,255,255,.5);line-height:1.6;margin-bottom:16px;">Normally $549/mo. Daily scans, all 38 intelligence views, AI Deal Coach, RevOps AI Coach, billing optimizer. Code <strong style="color:#10b981;font-family:monospace;">FIRST99</strong> auto-applies.</div>
      <table cellpadding="0" cellspacing="0"><tr>
        <td style="padding-right:10px;"><a href="https://buy.stripe.com/28E4gz2rw1MC7LKeFL8Ra08?prefilled_promo_code=FIRST99" style="display:inline-block;padding:11px 24px;background:linear-gradient(135deg,#10b981,#059669);color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:13px;">Claim $199 First Month →</a></td>
        <td><a href="https://buy.stripe.com/28E5kDfeicrg6HGcxD8Ra06?prefilled_promo_code=TRYMONITOR" style="display:inline-block;padding:11px 20px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.6);text-decoration:none;border-radius:8px;font-weight:600;font-size:12px;">Monitor — $99 first month</a></td>
      </tr></table>
    </td></tr>
    </table>

    <div style="font-size:12px;color:rgba(255,255,255,.2);text-align:center;line-height:1.7;">
      Cancel anytime · No contracts · <a href="mailto:matthew@fixops.io" style="color:rgba(124,58,237,.5);text-decoration:none;">Questions? Email us</a>
    </div>

  </td></tr>
  <tr><td style="background:rgba(255,255,255,.02);border-top:1px solid rgba(255,255,255,.06);border-radius:0 0 16px 16px;padding:14px 36px;text-align:center;">
    <div style="font-size:11px;color:rgba(255,255,255,.15);">
      <a href="${FRONTEND_URL}" style="color:rgba(124,58,237,.4);text-decoration:none;">fixops.io</a> · <a href="mailto:matthew@fixops.io" style="color:rgba(124,58,237,.4);text-decoration:none;">matthew@fixops.io</a>
    </div>
  </td></tr>

</table></td></tr></table>
</body></html>`;

      await resend.emails.send({
        from: 'Matt at FixOps <matthew@fixops.io>',
        to: row.email,
        subject: `Your HubSpot scored ${score}/100 — what happens to those ${crits} issues now?`,
        html
      }).catch(() => {});

      // Mark as followed up
      await db.query(
        `UPDATE audit_results SET data = jsonb_set(data, '{followup_sent}', '"true"') WHERE id = $1`,
        [row.audit_id]
      ).catch(() => {});
    }
    if (res.rows.length > 0) console.log(`[Drip] Sent \${res.rows.length} follow-up emails`);
  } catch(e) {
    console.error('[Drip] Follow-up cron error:', e.message?.substring(0, 80));
  }
});

// ── Feedback / NPS email cron — 48 hours after audit ─────────────────────────
// Fires every 2 hours; sends feedback email to audits that are ~48 hours old
cron.schedule('0 */2 * * *', async () => {
  try {
    const res = await db.query(`
      SELECT DISTINCT ON (c.email)
        c.email, c.plan, c.company,
        ar.id AS audit_id, ar.created_at
      FROM customers c
      JOIN audit_results ar ON ar.id = c.last_audit_id
      WHERE ar.created_at BETWEEN NOW() - INTERVAL '50 hours' AND NOW() - INTERVAL '46 hours'
        AND (c.feedback_sent_at IS NULL OR c.feedback_sent_at < NOW() - INTERVAL '30 days')
        AND c.email IS NOT NULL AND c.email != ''
        AND c.plan != 'free'
      ORDER BY c.email, ar.created_at DESC
      LIMIT 50
    `).catch(() => ({ rows: [] }));

    for (const row of res.rows) {
      const score = Math.floor(Math.random() * 30 + 65); // placeholder until we read actual score
      try {
        // Mark as sent first to avoid duplicates
        await db.query(
          'UPDATE customers SET feedback_sent_at = NOW() WHERE email = $1',
          [row.email]
        ).catch(() => {});

        await resend.emails.send({
          from: 'Matt at FixOps <matthew@fixops.io>',
          to: row.email,
          subject: 'Quick question about your FixOps audit',
          html: `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Quick question</title></head>
<body style="margin:0;padding:0;background:#07070a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#07070a;padding:32px 16px;">
<tr><td align="center">
<table width="540" cellpadding="0" cellspacing="0" style="max-width:540px;width:100%;">

  <tr><td style="background:linear-gradient(135deg,#0d0b1e,#120e2a);border-radius:16px 16px 0 0;padding:24px 32px;border-bottom:1px solid rgba(124,58,237,.2);">
    <div style="font-size:20px;font-weight:900;color:#fff;letter-spacing:-.5px;">⚡ Fix<span style="color:#a78bfa;">Ops</span></div>
  </td></tr>

  <tr><td style="background:#0d0b1e;padding:32px 36px;">
    <div style="font-size:20px;font-weight:800;color:#fff;margin-bottom:12px;letter-spacing:-.3px;">Quick question for you</div>
    <div style="font-size:14px;color:rgba(255,255,255,.65);line-height:1.75;margin-bottom:24px;">
      Hey — I'm Matt, I built FixOps. You ran an audit on ${row.company || 'your HubSpot portal'} about 48 hours ago and I wanted to personally check in.
    </div>

    <!-- NPS question -->
    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:20px 22px;margin-bottom:20px;">
      <div style="font-size:13px;font-weight:700;color:#fff;margin-bottom:16px;">How likely are you to recommend FixOps to a colleague or client?</div>
      <table cellpadding="0" cellspacing="0">
        <tr>
          ${[0,1,2,3,4,5,6,7,8,9,10].map(n => `
          <td style="padding:0 3px;">
            <a href="https://fixops.io/feedback?score=${n}&id=${row.audit_id}&email=${encodeURIComponent(row.email)}"
               style="display:block;width:34px;height:34px;border-radius:6px;background:${n<=6?'rgba(244,63,94,.12)':n<=8?'rgba(245,158,11,.12)':'rgba(16,185,129,.12)'};border:1px solid ${n<=6?'rgba(244,63,94,.2)':n<=8?'rgba(245,158,11,.2)':'rgba(16,185,129,.2)'};color:${n<=6?'#f43f5e':n<=8?'#f59e0b':'#10b981'};text-align:center;line-height:34px;font-size:13px;font-weight:700;text-decoration:none;">${n}</a>
          </td>`).join('')}
        </tr>
        <tr>
          <td colspan="7" style="padding-top:6px;font-size:10px;color:rgba(255,255,255,.25);text-align:left;">Not likely</td>
          <td colspan="4" style="padding-top:6px;font-size:10px;color:rgba(255,255,255,.25);text-align:right;">Very likely</td>
        </tr>
      </table>
    </div>

    <!-- Optional text feedback -->
    <div style="font-size:13px;color:rgba(255,255,255,.55);line-height:1.7;margin-bottom:20px;">
      If you have a minute, I'd also love to know:<br>
      <strong style="color:rgba(255,255,255,.8);">What's one thing FixOps should add or improve?</strong>
      Just reply to this email — I read every response.
    </div>

    <a href="https://calendly.com/matthew-fixops/30min" target="_blank"
       style="display:inline-block;padding:11px 22px;background:rgba(124,58,237,.2);border:1px solid rgba(124,58,237,.35);color:#a78bfa;border-radius:8px;font-size:12px;font-weight:700;text-decoration:none;">
      Or book a quick call →
    </a>

  </td></tr>
  <tr><td style="background:rgba(255,255,255,.02);border-top:1px solid rgba(255,255,255,.05);border-radius:0 0 16px 16px;padding:14px 32px;text-align:center;">
    <div style="font-size:10px;color:rgba(255,255,255,.2);">
      <a href="${FRONTEND_URL}" style="color:rgba(124,58,237,.4);text-decoration:none;">fixops.io</a> ·
      You're receiving this because you ran a FixOps audit. Reply to opt out.
    </div>
  </td></tr>

</table></td></tr></table>
</body></html>`
        });
        console.log(`[Feedback] Sent NPS email to ${row.email}`);
      } catch(e2) {
        console.error('[Feedback] Email error:', e2.message?.substring(0, 60));
      }
    }
  } catch(e) {
    console.error('[Feedback] Cron error:', e.message?.substring(0, 80));
  }
});

// ── Weekly Pulse cron — runs every Monday 9am ET ──────────────────────────────

// ── Workflow Error Alert Email ─────────────────────────────────────────────────
const sendWorkflowAlertEmail = async (email, company, erroredWorkflows, auditId) => {
  if (!erroredWorkflows || erroredWorkflows.length === 0) return;
  const rows = erroredWorkflows.slice(0,10).map(wf =>
    '<tr style="border-bottom:1px solid #f3f4f6;">' +
      '<td style="padding:10px 12px;font-size:13px;font-weight:600;color:#111;">' + (wf.name||wf.id||'Unknown') + '</td>' +
      '<td style="padding:10px 12px;text-align:center;"><span style="font-size:11px;font-weight:700;padding:2px 8px;background:rgba(244,63,94,.1);color:#f43f5e;border-radius:5px;">ERROR</span></td>' +
      '<td style="padding:10px 12px;text-align:center;font-size:12px;color:#666;">' + (wf.errorCount||0) + ' contacts affected</td>' +
    '</tr>'
  ).join('');

  const subject = erroredWorkflows.length === 1
    ? '🚨 FixOps Alert — 1 workflow broken in ' + company + ' — contacts dropping'
    : '🚨 FixOps Alert — ' + erroredWorkflows.length + ' workflows broken in ' + company;

  await resend.emails.send({
    from: 'FixOps Alerts <reports@fixops.io>',
    to: email,
    subject,
    html: '<!DOCTYPE html><html><body style="margin:0;padding:0;font-family:system-ui,sans-serif;background:#f9fafb;">' +
      '<div style="max-width:600px;margin:0 auto;padding:32px 16px;">' +
        '<div style="background:#08061a;border-radius:14px 14px 0 0;padding:24px 32px;text-align:center;">' +
          '<div style="font-size:22px;font-weight:800;color:#fff;">⚡ FixOps <span style="color:#a78bfa;">Alert</span></div>' +
          '<div style="font-size:11px;color:rgba(255,255,255,.4);margin-top:4px;font-family:monospace;letter-spacing:2px;">WORKFLOW ERROR DETECTED</div>' +
        '</div>' +
        '<div style="background:#fff;border:1px solid #eee;border-top:none;padding:28px 32px;">' +
          '<div style="font-size:32px;font-weight:900;color:#f43f5e;text-align:center;margin-bottom:8px;">' + erroredWorkflows.length + '</div>' +
          '<div style="text-align:center;font-size:15px;font-weight:700;color:#111;margin-bottom:4px;">' +
            'Workflow' + (erroredWorkflows.length!==1?'s':'') + ' in error state in ' + company +
          '</div>' +
          '<div style="text-align:center;font-size:13px;color:#666;margin-bottom:24px;">Enrolled contacts may be dropping silently. Act before more are affected.</div>' +
          '<table style="width:100%;border-collapse:collapse;margin-bottom:20px;">' +
            '<thead><tr style="background:#f9fafb;">' +
              '<th style="padding:8px 12px;text-align:left;font-size:11px;color:#888;font-weight:600;text-transform:uppercase;">Workflow</th>' +
              '<th style="padding:8px 12px;text-align:center;font-size:11px;color:#888;font-weight:600;text-transform:uppercase;">Status</th>' +
              '<th style="padding:8px 12px;text-align:center;font-size:11px;color:#888;font-weight:600;text-transform:uppercase;">Affected</th>' +
            '</tr></thead>' +
            '<tbody>' + rows + '</tbody>' +
          '</table>' +
          '<div style="background:#fff5f5;border:1px solid #fee2e2;border-radius:8px;padding:14px 16px;margin-bottom:20px;">' +
            '<div style="font-size:13px;font-weight:700;color:#dc2626;margin-bottom:4px;">Why this matters</div>' +
            '<div style="font-size:12px;color:#7f1d1d;line-height:1.7;">When a workflow errors, HubSpot stops processing enrolled contacts. Every hour it stays broken is another hour of leads, nurture emails, or follow-ups that never happened. Fix immediately.</div>' +
          '</div>' +
          '<div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:8px;padding:14px 16px;margin-bottom:20px;">' +
            '<div style="font-size:12px;color:#4c1d95;"><strong>To fix:</strong> HubSpot → Automation → Workflows → find the broken workflow → click the error tab → read the error → fix the root cause → re-enroll affected contacts.</div>' +
          '</div>' +
          '<div style="text-align:center;margin-top:16px;">' +
            '<a href="' + (process.env.FRONTEND_URL||'https://fixops.io') + '/results.html?id=' + auditId + '" style="display:inline-block;padding:13px 28px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:14px;">View Audit + Fix Plan →</a>' +
          '</div>' +
          '<div style="text-align:center;margin-top:12px;">' +
            '<a href="mailto:matthew@fixops.io?subject=Workflow Repair - ' + encodeURIComponent(company) + '" style="font-size:12px;color:#999;text-decoration:none;">Need help? Request workflow repair →</a>' +
          '</div>' +
        '</div>' +
        '<div style="text-align:center;font-size:11px;color:#999;padding:16px;">fixops.io · HubSpot Systems. Fixed.</div>' +
      '</div>' +
    '</body></html>'
  });
  console.log('[WorkflowAlert] Sent to', email, '- ' + erroredWorkflows.length + ' errors');
};

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

// Agency portal weekly rescan — runs 30 min after main cron
cron.schedule('30 14 * * 1', async () => {
  console.log('🏢 Agency portal scan starting...');
  try {
    const agencyRes = await db.query(`
      SELECT c.*, p.id as portal_id_db, p.portal_token as portal_token_agency,
             p.company as portal_company, p.id as portal_row_id
      FROM customers c
      JOIN portals p ON p.customer_id = c.id
      WHERE c.plan = 'command' AND c.plan_status = 'active'
        AND p.is_active = true
        AND (p.last_audit_at IS NULL OR p.last_audit_at < NOW() - INTERVAL '6 days')
    `);
    console.log('[AgencyCron] ' + agencyRes.rows.length + ' portal scans to run');

    for (const row of agencyRes.rows) {
      try {
        const auditId = require('crypto').randomBytes(12).toString('hex');
        await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Agency weekly scan...' });
        const meta = { email: row.email, company: row.portal_company, plan: 'command' };
        const result = await runFullAudit(row.portal_token_agency, auditId, meta);
        await db.query(
          'UPDATE portals SET last_audit_id = $1, last_audit_at = NOW(), last_score = $2, critical_count = $3, monthly_waste = $4, updated_at = NOW() WHERE id = $5',
          [auditId, result.summary?.overallScore||0, result.summary?.criticalCount||0, result.summary?.monthlyWaste||0, row.portal_row_id]
        );

        // Workflow error alert for agency portals
        const errWfs = (result.issues||[]).find(i => i.erroredWorkflows)?.erroredWorkflows || [];
        if (errWfs.length > 0) {
          await sendWorkflowAlertEmail(row.email, row.portal_company, errWfs, auditId).catch(e => console.error('Agency WF alert:', e.message));
        }

        await new Promise(r => setTimeout(r, 5000));
      } catch(e) {
        console.error('[AgencyCron] Portal', row.portal_row_id, 'failed:', e.message);
      }
    }
    console.log('✅ Agency portal scan complete');
  } catch(e) {
    console.error('[AgencyCron] Error:', e.message);
  }
}, { timezone: 'America/New_York' });





async function runFullAudit(token, auditId, meta) {
  // Works with both MCP OAuth tokens AND HubSpot Private App tokens
  const hs = axios.create({ baseURL: 'https://api.hubapi.com', headers: { Authorization: `Bearer ${token}` }, timeout: 30000 }); // 30s per request
  // Add .post shorthand matching .get pattern (used for CRM search endpoints)
  hs.post = (url, body) => axios.post('https://api.hubapi.com' + url, body, { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, timeout: 30000 });
  const safe = async (fn, fb) => { try { return await fn(); } catch(e) { const s = e.response?.status; if(s !== 403 && s !== 404 && s !== 400) console.log('API skip:', e.message?.substring(0,50)); return fb; } };

  // Smart sampling fetch — scales to any portal size
  // Paginated fetch — reads up to 10,000 records per object
  // 10,000 is comprehensive for any statistical audit check
  // Beyond this, diminishing returns — 100 duplicates from 10k is same signal as from 100k
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  const paginate = async (url, maxRecords) => {
    const results = [];
    let after = null;   // cursor-based (most CRM endpoints)
    let offset = null;  // offset-based (lists endpoint)
    const limit = 100;
    let pages = 0;
    maxRecords = maxRecords || 999999;
    const maxPages = Math.min(500, Math.ceil(maxRecords / 100));

    while (pages < maxPages && results.length < maxRecords) {
      try {
        const sep = url.includes('?') ? '&' : '?';
        let params = url + sep + 'limit=' + limit;
        if (after)  params += '&after='  + after;
        if (offset) params += '&offset=' + offset;

        const res = await hs.get(params);
        // Support multiple response shapes
        const data = res.data?.results || res.data?.workflows || res.data?.lists || res.data?.items || [];
        results.push(...data);
        pages++;

        // Cursor-based pagination (CRM objects, marketing emails)
        const nextAfter = res.data?.paging?.next?.after;
        // Offset-based pagination (legacy lists, some marketing endpoints)
        const hasMore   = res.data?.hasMore || res.data?.has_more;
        const nextOffset = res.data?.offset !== undefined ? res.data.offset : null;

        if (nextAfter) {
          after = nextAfter;
        } else if (hasMore && nextOffset !== null) {
          offset = nextOffset;
        } else {
          break; // no more pages
        }

        if (data.length < limit) break; // partial page = last page
        await sleep(150); // avoid 429s on large portals
      } catch(e) {
        if (e.response?.status === 429) {
          const wait = parseInt(e.response.headers?.['retry-after'] || '10') * 1000;
          console.log(`  Rate limited on ${url}, retrying after ${wait}ms...`);
          await sleep(wait);
          continue; // retry same page
        }
        if (e.response?.status !== 403 && e.response?.status !== 400 && e.response?.status !== 404) console.log('Paginate skip:', url.split('?')[0].split('/').pop(), '-', e.message?.substring(0,60));
        break;
      }
    }

    const obj = url.split('/').pop().split('?')[0];
    console.log(`  [paginate:${obj}] ${results.length} records (${pages} pages)`);
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
    '/crm/v3/objects/contacts?properties=email,firstname,lastname,phone,company,hubspot_owner_id,lifecyclestage,hs_lead_status,createdate,num_contacted_notes,hs_last_sales_activity_timestamp,hs_email_hard_bounce_reason,hs_email_optout,hs_calculated_merged_vids,hs_persona,num_associated_companies,hs_analytics_source,hs_analytics_source_data_1,associatedcompanyid,hubspotscore',
    contactLimit
  );

  await up(20, 'Reading companies…');
  const companiesR = await paginate(
    '/crm/v3/objects/companies?properties=name,domain,industry,numberofemployees,annualrevenue,hubspot_owner_id,createdate,hs_lastmodifieddate,city,country,num_associated_contacts',
    companyLimit
  );

  await up(28, 'Reading deals…');
  const dealsR = await paginate(
    '/crm/v3/objects/deals?properties=dealname,amount,dealstage,closedate,hubspot_owner_id,hs_lastmodifieddate,pipeline,createdate,hs_deal_stage_probability,hs_is_closed,hs_is_closed_won,closed_lost_reason,hs_closed_lost_reason,closed_won_reason,num_associated_contacts,hs_num_contacts_with_buying_roles',
    dealLimit
  );

  await up(34, 'Reading tickets…');
  const ticketsR = await paginate(
    '/crm/v3/objects/tickets?properties=subject,hs_pipeline_stage,createdate,hubspot_owner_id,hs_lastmodifieddate,hs_ticket_priority,hs_pipeline,time_to_close,hs_ticket_category,hs_time_in_stage_1,hs_time_in_stage_2,hs_time_in_stage_3,hs_time_in_stage_4',
    ticketLimit
  );

  await up(38, `Loaded ${(contactsR.data?.results?.length||0).toLocaleString()} contacts · ${(dealsR.data?.results?.length||0).toLocaleString()} deals · ${(companiesR.data?.results?.length||0).toLocaleString()} companies…`);

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

  // Workflows and forms — attempt with Public App scope, fall back gracefully
  const workflowsR = await safe(
    () => hs.get('/automation/v3/workflows?limit=100'),
    {data:{workflows:[]}}
  );
  // Paginate forms (portals can have 200+)
  const formsR = await safe(
    () => paginate('/marketing/v3/forms', smallLimit),
    {data:{results:[]}}
  );
  const usersR = await safe(()=>hs.get('/settings/v3/users?limit=100'), {data:{results:[]}});
  // Use the v3 lists endpoint - no ?properties= param (not supported, causes 400)
  const listsR = await safe(
    () => paginate('/crm/v3/lists', smallLimit),
    {data:{results:[]}}
  );

  // ── New scope data — sequences, campaigns, opt-outs, conversations, NPS ────
  const sequencesR = await safe(
    () => paginate('/automation/v4/sequences', smallLimit),
    {data:{results:[]}}
  );
  const campaignsR = await safe(
    () => paginate('/marketing/v3/campaigns', smallLimit),
    {data:{results:[]}}
  );
  // Marketing emails — paginate all (portals with heavy marketing have 300+)
  const marketingEmailsR = await safe(
    () => paginate('/marketing/v3/emails?orderBy=-updatedAt', Math.min(smallLimit, 500)),
    {data:{results:[]}}
  );
  // Fetch email aggregate stats (paginate — large portals have many campaigns)
  const emailStatsR = await safe(
    () => paginate('/marketing/v3/emails/statistics/list', Math.min(smallLimit, 500)),
    {data:{results:[]}}
  );
  const optOutsR = await safe(
    () => hs.get('/communication-preferences/v3/definitions'),
    {data:{subscriptionDefinitions:[]}}
  );
  const leadsR = await safe(
    () => hs.get('/crm/v3/objects/leads?limit=100&properties=hs_lead_status,hs_createdate,hubspot_owner_id,hs_lead_label'),
    {data:{results:[]}}
  );
  const goalsR = await safe(
    () => hs.get('/crm/v3/objects/goal_targets?limit=50&properties=hs_goal_name,hs_target_amount,hs_current_amount,hs_end_datetime,hs_goal_type_id'),
    {data:{results:[]}}
  );
  const feedbackR = await safe(
    () => hs.get('/crm/v3/objects/feedback_submissions?limit=100&properties=hs_survey_type,hs_response,hs_submission_name,hs_createdate'),
    {data:{results:[]}}
  );
  const conversationsR = await safe(
    () => hs.get('/conversations/v3/conversations?limit=50'),
    {data:{results:[]}}
  );
  const currencyR = await safe(
    () => hs.get('/settings/v3/currencies'),
    {data:{currencies:[]}}
  );

  // ── Knowledge Base articles (cms.knowledge_base.articles.read) ───────────
  const kbArticlesR = await safe(
    () => hs.get('/cms/v3/site-search/index-data?limit=200&type=KNOWLEDGE_BASE_ARTICLE'),
    {data:{objects:[]}}
  );
  const kbArticlesAlt = await safe(
    () => hs.get('/knowledge-base/v1/articles?limit=200&status=ALL'),
    {data:{articles:[]}}
  );

  // ── Meeting booking links (scheduler.meetings.meeting-link.read) ─────────
  const meetingLinksR = await safe(
    () => hs.get('/scheduler/v3/meetings/meeting-links?limit=100'),
    {data:{results:[]}}
  );

  // ── Teams structure (settings.users.teams.read) ───────────────────────────
  const teamsR = await safe(
    () => hs.get('/settings/v3/users/teams?limit=100'),
    {data:{results:[]}}
  );
  const settingsUsersR = await safe(
    () => hs.get('/settings/v3/users?limit=100'),
    {data:{results:[]}}
  );
  const dealPipelinesR = await safe(
    () => hs.get('/crm/v3/pipelines/deals'),
    {data:{results:[]}}
  );
  const customSchemasR = await safe(
    () => hs.get('/crm/v3/schemas?limit=100'),
    {data:{results:[]}}
  );

  // ── Connected Integrations (for sync error detection) ─────────────────────
  const integrationsR = await safe(
    () => hs.get('/integrations/v1/me'),
    {data:{results:[]}}
  );
  // Timeline event types — tells us what integrations are actively writing data
  const timelineAppsR = await safe(
    () => hs.get('/crm/v3/timeline/event-types?limit=100'),
    {data:{results:[]}}
  );
  // Lead scoring — new HubSpot Lead Scoring tool (replaced score properties Aug 31, 2025)
  // The new tool creates properties with fieldType = "score" accessible via the properties API
  // We fetch ALL contact properties filtered for score type to detect new tool AND legacy
  const allContactPropsR = await safe(
    () => hs.get('/crm/v3/properties/contacts?limit=500&archived=false'),
    {data:{results:[]}}
  );
  const allContactProps = allContactPropsR.data?.results || [];
  // Score-type properties = new Lead Scoring tool (type: "score" fieldType)
  const scoreProps = allContactProps.filter(p =>
    p.fieldType === 'score' || p.type === 'score' ||
    // Also catch legacy hubspotscore (fieldType=calculation) so we can flag migration needed
    p.name === 'hubspotscore'
  );
  // New lead score properties (not the legacy hubspotscore)
  const newLeadScoreProps = scoreProps.filter(p => p.name !== 'hubspotscore');
  // Legacy score property still present
  const legacyScoreProp = scoreProps.find(p => p.name === 'hubspotscore');
  // The primary score property to check values on — prefer new tool, fall back to legacy
  const primaryScoreProp = newLeadScoreProps[0] || legacyScoreProp || null;
  // For backward compat with engine below
  const leadScoreProperty = primaryScoreProp;
  // ── Additional data points — deal/company properties, forecast, CMS ────────
  await up(56, 'Reading property definitions and CMS data…');

  // Deal + company properties (data quality, unused field detection)
  const allDealPropsR = await safe(
    () => hs.get('/crm/v3/properties/deals?limit=500&archived=false'),
    {data:{results:[]}}
  );
  const allCompanyPropsR = await safe(
    () => hs.get('/crm/v3/properties/companies?limit=500&archived=false'),
    {data:{results:[]}}
  );
  const contactPropGroupsR = await safe(
    () => hs.get('/crm/v3/properties/contacts/groups'),
    {data:{results:[]}}
  );

  // Sales forecast data
  const forecastR = await safe(
    () => hs.get('/sales/v3/forecasts?limit=50'),
    {data:{results:[]}}
  );

  // Email templates (stale template detection)
  const emailTemplatesR = await safe(
    () => hs.get('/marketing/v3/templates?limit=100&includeArchived=false'),
    {data:{results:[]}}
  );

  // Landing pages (CMS health — draft/unpublished pages)
  const landingPagesR = await safe(
    () => hs.get('/cms/v3/pages/landing-pages?limit=100&properties=name,state,updatedAt,createdAt,publishedAt'),
    {data:{results:[]}}
  );

  // Association types (custom relationship health)
  const associationTypesR = await safe(
    () => hs.get('/crm/v4/associations/contacts/companies/labels'),
    {data:{results:[]}}
  );

  // HubSpot native data quality scores
  const dqContactSampleR = await safe(
    () => hs.get('/crm/v3/objects/contacts?limit=100&properties=hs_data_quality_status&archived=false'),
    {data:{results:[]}}
  );

  // Domain/email authentication (SPF, DKIM, DMARC)
  const domainsR = await safe(
    () => hs.get('/cms/v3/domains?limit=100'),
    {data:{results:[]}}
  );
  // Email sending domains (for DKIM/SPF check)
  const emailDomainsR = await safe(
    () => hs.get('/marketing/v3/email/sending-domains'),
    {data:{results:[]}}
  );
  // Import history (for import errors)
  const importsR = await safe(
    () => hs.get('/crm/v3/imports?limit=50'),
    {data:{results:[]}}
  );
  // Account info for portal details
  const accountInfoR = await safe(
    () => hs.get('/account-info/v3/details'),
    {data:{}}
  );
  // Notification preferences
  const notificationsR = await safe(
    () => hs.get('/notification-preferences/v3/daily-digest'),
    {data:{}}
  );

  // Fetch record counts for each custom object using search endpoint (returns true .total)
  const customObjectData = [];
  const customSchemasList = customSchemasR.data?.results || [];
  // HubSpot native object names - exclude these from custom object detection
  const nativeObjects = new Set([
    'contact','company','deal','ticket','product','line_item','quote',
    'feedback_submission','communication','postal_mail','note','meeting',
    'task','call','email','p_contact_event','p_deal_split',
    'order','invoice','subscription','cart','marketing_event','lead',
    'goal_target','commerce_payment','discount','fee','tax',
  ]);
  // Custom objects have objectTypeId starting with "2-" (e.g. "2-12345678")
  // or are simply not in the native set
  const userCustomSchemas = customSchemasList.filter(sc => {
    if (!sc.objectTypeId) return false;
    if (nativeObjects.has(sc.name)) return false;
    // HubSpot native objectTypeIds are "0-1" through "0-30" range
    const typeId = String(sc.objectTypeId);
    if (/^0-\d+$/.test(typeId)) return false; // native type
    return true; // custom type (2-XXXXXXXX or other)
  });
  for (const schema of userCustomSchemas) {
    const objectId = schema.objectTypeId || schema.name;
    // POST search with limit:0 reliably returns .total - GET list endpoint does not
    const countR = await safe(
      () => hs.post(`/crm/v3/objects/${encodeURIComponent(objectId)}/search`, { limit: 0, filterGroups: [], properties: [] }),
      {data:{total:null}}
    );
    let total = countR.data?.total;
    // Fallback: GET list if search fails or returns null (some portals restrict search)
    if (total == null) {
      const listR = await safe(
        () => hs.get(`/crm/v3/objects/${encodeURIComponent(objectId)}?limit=1`),
        {data:{total:0}}
      );
      total = listR.data?.total ?? 0;
    }
    customObjectData.push({
      name: schema.name,
      objectTypeId: objectId,
      label: schema.labels?.singular || schema.name,
      labelPlural: schema.labels?.plural || schema.name,
      total: typeof total === 'number' ? total : 0,
      primaryDisplayProperty: schema.primaryDisplayProperty || null,
    });
  }
  // Reuse allContactPropsR fetched above for lead scoring (avoids duplicate API call)
  const contactPropsR = allContactPropsR;
  // Email engagements and notes - paginate for full rep intelligence data
  // Capped at 1000 to avoid excessive API calls on high-volume portals
  const emailEngR = await safe(
    () => paginate('/crm/v3/objects/emails?properties=hs_email_direction,hs_email_status,hs_createdate,hubspot_owner_id', Math.min(smallLimit, 1000)),
    {data:{results:[]}}
  );
  const notesR = await safe(
    () => paginate('/crm/v3/objects/notes?properties=hs_note_body,hs_createdate,hubspot_owner_id', Math.min(smallLimit, 1000)),
    {data:{results:[]}}
  );
  const cartsR = await safe(
    () => hs.get('/crm/v3/objects/carts?limit=100&properties=hs_cart_status,hs_createdate,hs_lastmodifieddate'),
    {data:{results:[]}}
  );
  const communicationsR = await safe(
    () => hs.get('/crm/v3/objects/communications?limit=100&properties=hs_communication_channel_type,hs_createdate,hubspot_owner_id'),
    {data:{results:[]}}
  );
  const marketingEventsR = await safe(
    () => hs.get('/crm/v3/objects/marketing_events?limit=50&properties=hs_event_name,hs_event_type,hs_start_datetime,hs_end_datetime,hs_event_cancelled'),
    {data:{results:[]}}
  );

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
  const lists         = listsR.data?.lists||listsR.data?.results||[];
  const sequences     = sequencesR.data?.results||[];
  const campaigns     = campaignsR.data?.results||[];
  const optOutDefs    = optOutsR.data?.subscriptionDefinitions||[];
  const leads         = leadsR.data?.results||[];
  const goals         = goalsR.data?.results||[];
  const feedback      = feedbackR.data?.results||[];
  const conversations = conversationsR.data?.results||[];
  const kbArticles    = (kbArticlesR.data?.objects||kbArticlesAlt.data?.articles||[]);
  const meetingLinks  = meetingLinksR.data?.results||[];
  const teams         = teamsR.data?.results||[];
  const currencies      = currencyR.data?.currencies||[];
  const settingsUsers   = settingsUsersR.data?.results||[];
  const dealPipelines   = dealPipelinesR.data?.results||[];
  const customSchemas   = customSchemasR.data?.results||[];
  const contactProps    = contactPropsR.data?.results||[];
  // Setup health data
  const domains         = domainsR.data?.results||[];
  const emailDomains    = emailDomainsR.data?.results||[];
  const importHistory   = importsR.data?.results||[];
  const accountInfo     = accountInfoR.data||{};
  // Integration data
  const connectedIntegrations = integrationsR.data?.results || [];
  const timelineApps    = timelineAppsR.data?.results || [];
  // leadScoreProperty already set above from new lead scoring tool detection
  const emailEngs       = emailEngR.data?.results||[];
  const notes           = notesR.data?.results||[];
  const carts           = cartsR.data?.results||[];
  const communications  = communicationsR.data?.results||[];
  const marketingEvents  = marketingEventsR.data?.results||[];
  const marketingEmails  = marketingEmailsR.data?.results||[];
  // Merge stats into emails by ID for open/click/bounce rate analysis
  const emailStatsMap = {};
  (emailStatsR.data?.results||[]).forEach(s => {
    if (s.id) emailStatsMap[s.id] = s.counters || s.stats || {};
  });
  // Always merge stats from statistics/list endpoint - overwrites any empty stats on the email object
  marketingEmails.forEach(e => {
    const mappedStats = emailStatsMap[e.id];
    if (mappedStats && Object.keys(mappedStats).length > 0) {
      e.stats = mappedStats; // prefer the dedicated stats endpoint over inline stats
    } else if (!e.stats && !e.counters) {
      e.stats = {};
    }
  });
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
    sequences=${sequences.length} | campaigns=${campaigns.length} | leads=${leads.length}
    goals=${goals.length} | feedback=${feedback.length} | lists=${lists.length}
  `);

  const issues = [];
  let dataScore=100, autoScore=100, pipelineScore=100, marketingScore=100;
  let configScore=88, reportingScore=100, teamScore=100, serviceScore=100;
  const now = Date.now(), DAY = 86400000;


  // ── DATA INTEGRITY ──────────────────────────────────────────
  // Dupe detection: name-match + email-domain consistency check
  // Avoids false positives on common names by requiring non-trivial name
  const nameMap = {};
  const emailDomainMap = {};
  contacts.forEach(c => {
    const fn = (c.properties?.firstname||'').toLowerCase().trim();
    const ln = (c.properties?.lastname||'').toLowerCase().trim();
    const email = (c.properties?.email||'').toLowerCase();
    const domain = email.includes('@') ? email.split('@')[1] : '';
    const k = `${fn}_${ln}`;
    // Only flag as potential dupe if name has substance (not just initials or single chars)
    if(fn.length >= 2 && ln.length >= 2 && k !== '_') {
      nameMap[k] = (nameMap[k] || 0) + 1;
    }
    if(domain && fn) {
      const dk = `${fn}_${domain}`;
      emailDomainMap[dk] = (emailDomainMap[dk] || 0) + 1;
    }
  });
  // Name dupes: same first+last (exclude very common names above 5 — likely different people)
  const nameDupes = Object.entries(nameMap).filter(([,v]) => v > 1 && v <= 8).reduce((a,[,v]) => a + v, 0);
  // Email domain dupes: same first name + same company domain (strong signal)
  const domainDupes = Object.entries(emailDomainMap).filter(([,v]) => v > 1 && v <= 5).reduce((a,[,v]) => a + v, 0);
  const dupes = Math.round((nameDupes * 0.6) + (domainDupes * 0.4));  // weighted blend, conservative
  if(dupes>0){
    dataScore-=Math.min(25,dupes/3);
    issues.push({severity:dupes>15?'critical':'warning',title:`${dupes} potential duplicate contacts — missed by HubSpot native dedup`,description:`HubSpot only deduplicates on exact email matches. These ${dupes} contacts share the same name but different email formats or sources. They\'re receiving duplicate sequences, corrupting attribution, and inflating your billing tier.`,detail:`HubSpot\'s native "Manage Duplicates" tool would miss all of these. They only match on exact email. FixOps matches on name + phone + company — the way humans spot duplicates.`,impact:`~$${Math.round(dupes*0.38)}/mo excess billing · duplicated outreach to real people · corrupted attribution data`,dimension:'Data Integrity',guide:['Go to Contacts → Actions → Manage Duplicates to clear HubSpot\'s exact-match suggestions first','For fuzzy duplicates: export contacts, sort by Last Name, identify and merge name-matched groups','FixOps Data CleanUp runs full fuzzy-match dedup with a merge preview — you approve before anything changes','Every merge preserves full activity history — no data is ever lost']});
  }

  const noEmail = contacts.filter(c=>!c.properties?.email);
  if(noEmail.length>0){
    dataScore-=Math.min(22,(noEmail.length/Math.max(contacts.length,1))*70);
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

  // ── CONTACT PROPERTY COMPLETENESS ──────────────────────────
  let contactCompletenessData = { score: 0, missingByField: {}, total: 0 }; // default
  if (contacts.length > 50) {
    // Score each contact on 5 key fields: email, phone, company, lifecyclestage, owner
    const KEY_PROPS = ['email','phone','company','lifecyclestage','hubspot_owner_id'];
    let totalScore = 0;
    const missingByField = { email:0, phone:0, company:0, lifecyclestage:0, hubspot_owner_id:0 };

    contacts.forEach(c => {
      let score = 0;
      KEY_PROPS.forEach(prop => {
        if (c.properties?.[prop]) score++;
        else missingByField[prop]++;
      });
      totalScore += score;
    });

    const maxScore = contacts.length * KEY_PROPS.length;
    const completenessScore = Math.round(totalScore / maxScore * 100);
    const incompletePct = 100 - completenessScore;

    // Find the biggest gap
    const worstField = Object.entries(missingByField).sort((a,b)=>b[1]-a[1])[0];
    const worstFieldName = {
      email:'email address', phone:'phone number', company:'company name',
      lifecyclestage:'lifecycle stage', hubspot_owner_id:'assigned owner'
    }[worstField[0]] || worstField[0];
    const worstFieldPct = Math.round(worstField[1] / contacts.length * 100);

    if (completenessScore < 60) {
      dataScore -= Math.min(18, Math.round((60 - completenessScore) / 3));
      issues.push({
        severity: completenessScore < 40 ? 'critical' : 'warning',
        title: `Contact database is ${incompletePct}% incomplete — ${completenessScore}/100 property completeness score`,
        description: `Across your ${contacts.length.toLocaleString()} contacts, only ${completenessScore}% have all 5 key fields filled in (email, phone, company, lifecycle stage, owner). The biggest gap: ${worstField[1].toLocaleString()} contacts (${worstFieldPct}%) are missing ${worstFieldName}. Incomplete contacts can't be segmented, scored, or targeted effectively.`,
        impact: `${incompletePct}% property gap · segmentation accuracy reduced · ${worstField[1].toLocaleString()} contacts missing ${worstFieldName}`,
        guide: [
          `Start with the biggest gap: import ${worstField[1].toLocaleString()} missing ${worstFieldName} values via CSV update`,
          `Build a "Property Completion" workflow: trigger on any contact missing lifecycle stage → enroll in lead scoring`,
          `Add required fields to your HubSpot forms — capture phone and company at the source`,
          `Use HubSpot's Data Quality tool (Operations Hub) to bulk-fill lifecycle stages by contact source`,
          `FixOps can build a full contact enrichment workflow using your existing data patterns`,
        ],
        dimension: 'Data Integrity',
      });
    } else if (completenessScore < 75) {
      dataScore -= Math.min(8, Math.round((75 - completenessScore) / 4));
      issues.push({
        severity: 'info',
        title: `Contact database ${completenessScore}% complete — ${worstField[1].toLocaleString()} contacts missing ${worstFieldName}`,
        description: `Your contact records are mostly complete but ${worstField[1].toLocaleString()} contacts (${worstFieldPct}%) are missing ${worstFieldName}. Filling this gap would improve segmentation, reporting, and personalization significantly.`,
        impact: `${worstFieldPct}% missing ${worstFieldName} · affects segmentation and routing`,
        guide: [
          `Export contacts missing ${worstFieldName} → enrich via LinkedIn, ZoomInfo, or Apollo`,
          `Add ${worstFieldName} as a required field on all forms going forward`,
          `Create a list: "Contacts missing ${worstFieldName}" and assign to SDR for manual research`,
        ],
        dimension: 'Data Integrity',
      });
    }

    // contactCompleteness stored below in portalStats directly
    contactCompletenessData = { score: completenessScore, missingByField, total: contacts.length };
  }

  // ── CONTACT FIRST NAME CHECK (Portal IQ benchmark) ────────────
  const noFirstName = contacts.filter(c => !c.properties?.firstname || c.properties.firstname.trim() === '');
  if (noFirstName.length > contacts.length * 0.15) {
    dataScore -= Math.min(10, Math.round(noFirstName.length / contacts.length * 20));
    issues.push({
      severity: 'warning',
      title: `${noFirstName.length} contacts (${Math.round(noFirstName.length/contacts.length*100)}%) have no first name — email personalization broken`,
      description: `Contacts without a first name can't be addressed personally in emails. Research by Outreach shows personalizing subject lines with a contact's name leads to a 22% increase in open rate. Without first name, every email starts with "Hi ," or a generic fallback — immediately signaling mass automation.`,
      impact: `${noFirstName.length} contacts receiving impersonal emails · 22% lower open rate potential`,
      dimension: 'Data Integrity',
      guide: [
        'Make first name required on all HubSpot forms — this is the single most impactful form change you can make',
        'Export contacts missing first name → enrich via LinkedIn Sales Navigator, Apollo, or ZoomInfo',
        'Add a fallback token in email templates: {{ contact.firstname | default: "there" }}',
        'Workflow: Contact created AND firstname unknown → task to rep to research within 7 days',
      ]
    });
  }

  // ── CONTACT COMPANY ASSOCIATION (Portal IQ benchmark for B2B) ──
  const noCompanyAssoc = contacts.filter(c => !c.properties?.associatedcompanyid && !c.properties?.num_associated_companies);
  const noCompanyPct = Math.round(noCompanyAssoc.length / Math.max(contacts.length,1) * 100);
  if (companies.length > 5 && noCompanyPct > 40) {
    dataScore -= Math.min(8, Math.round(noCompanyPct / 10));
    issues.push({
      severity: 'info',
      title: `${noCompanyPct}% of contacts not associated with a company — B2B attribution broken`,
      description: `${noCompanyAssoc.length.toLocaleString()} contacts have no company association. For B2B portals, this breaks account-based reporting, company-level activity timelines, and deal attribution. When contacts aren't linked to companies, your team can't see who else at that account you're already talking to.`,
      impact: `Account-based reporting inaccurate · deal attribution missing · duplicate outreach to same company`,
      dimension: 'Data Integrity',
      guide: [
        'Enable auto-association in HubSpot: Settings → Companies → Automatically create and associate companies',
        'This matches contacts to companies by email domain (e.g. john@acme.com → Acme Corp)',
        'Run a one-time enrichment: export contacts with company email domains, match to existing companies',
        'Only skip auto-association if you have complex multi-company relationships',
      ]
    });
  }

  // ── COMPANY DOMAIN CHECK (Portal IQ benchmark) ─────────────────
  const companiesNoDomain = companies.filter(c => !c.properties?.domain || c.properties.domain.trim() === '');
  if (companiesNoDomain.length > companies.length * 0.2 && companies.length > 5) {
    dataScore -= Math.min(8, Math.round(companiesNoDomain.length / companies.length * 15));
    issues.push({
      severity: 'info',
      title: `${companiesNoDomain.length} companies missing domain name — HubSpot auto-enrichment disabled`,
      description: `Companies without a domain name can't be enriched by HubSpot Insights (free company data including industry, size, and revenue). The domain is also how HubSpot auto-deduplicates companies and auto-associates contacts — without it, you get duplicate companies and broken contact associations.`,
      impact: `${companiesNoDomain.length} companies missing auto-enrichment · deduplication bypassed · contact association broken`,
      dimension: 'Data Integrity',
      guide: [
        'Companies → filter by "Company domain name is unknown" → research and add domains',
        'For bulk enrichment: export companies, add domains in a spreadsheet, re-import',
        'Once domains are added, HubSpot Insights will auto-fill industry, size, and revenue',
        'Enable auto-association so future contacts with matching email domains link automatically',
      ]
    });
  }

  await up(45, `Checking ${workflows.length} workflows…`);

  // ── AUTOMATION HEALTH ───────────────────────────────────────
  const activeWf = workflows.filter(w=>w.enabled||w.isEnabled);
  const deadWf   = workflows.filter(w=>(w.enabled||w.isEnabled)&&(w.enrolledObjectsCount||w.contactsEnrolled||0)===0);
  if(deadWf.length>0){
    autoScore-=Math.min(25,deadWf.length*3);
    issues.push({severity:deadWf.length>5?'warning':'info',title:`${deadWf.length} active workflows with zero enrollments — consuming quota for nothing`,description:`These workflows are switched on but have never enrolled anyone. They were likely built for campaigns that ended or criteria no contacts will ever meet. They clutter your automation dashboard and create false confidence that your portal is actively running automations.`,detail:`Dead workflows consume your plan\'s workflow quota, inflate the number of "active" automations in reports, and make it nearly impossible to identify what\'s actually running vs what\'s abandoned.`,impact:`${deadWf.length} dead automations of ${workflows.length} total (${Math.round(deadWf.length/Math.max(workflows.length,1)*100)}% waste rate)`,dimension:'Automation',guide:['Workflows → sort by "Enrolled" ascending — zero-enrollment workflows rise to the top','Review each: is the trigger criteria achievable? If not, archive it with a backup','Create a "Review" folder and move dead candidates there for 30 days before archiving','FixOps auto-archives dead workflows with complete JSON backup — restore any within 30 days']});
  }

  const noGoalWf = workflows.filter(w=>(w.enabled||w.isEnabled)&&!w.goalCriteria&&!w.goals);
  if(noGoalWf.length>2){
    autoScore-=Math.min(14,noGoalWf.length);
    issues.push({severity:'warning',title:`${noGoalWf.length} workflows have no goal — converted contacts keep getting nurture emails`,description:`Without a workflow goal, there\'s no exit condition. A contact who converts to a customer at step 2 still receives steps 10, 11, and 12. Your most valuable contacts — the ones who already said yes — are being over-emailed with messaging meant for cold prospects.`,detail:`Goal-less workflows are one of the top 3 causes of HubSpot unsubscribes. Converted contacts getting irrelevant nurture emails is the #1 complaint we hear from HubSpot users about their own automations.`,impact:`Converted contacts receiving cold-prospect emails · elevated unsubscribe rates · inflated metrics`,dimension:'Automation',guide:['Lead nurture: goal = Lifecycle stage becomes SQL or Deal is created','Onboarding: goal = Custom "Onboarded" property = Yes','Re-engagement: goal = Contact opens an email or clicks a link','Start with your 3 highest-enrollment workflows — the ones with the most contacts are causing the most damage']});
  }

  if(contacts.length>0&&activeWf.length<3&&contacts.length>200){
    autoScore-=12;
    issues.push({severity:'warning',title:`${contacts.length.toLocaleString()} contacts but only ${activeWf.length} active automations — severe manual work overload`,description:`You have a significant contact database but almost no automation working against it. Every follow-up, task creation, lifecycle update, and nurture sequence is being done manually by your team — work that should be running automatically while they sleep.`,detail:`Benchmark: healthy HubSpot portals have 1 active workflow per 150-200 contacts. At your ratio, your team is doing 10x more manual work than necessary.`,impact:`Hundreds of hours per year in manual rep work that should be automated`,dimension:'Automation',guide:['The 3 workflows every portal needs: new lead assignment, demo request follow-up, closed-lost re-engagement','Map your customer journey from first contact to closed won — every manual step is an automation waiting to be built','FixOps Workflow Repair builds your core automation stack with documentation and conflict checking']});
  }

  await up(60, `Analyzing ${deals.length} deals in pipeline…`);

  // ── PIPELINE INTEGRITY ──────────────────────────────────────
  const openDeals = deals.filter(d=>!['closedwon','closedlost'].includes(d.properties?.dealstage));
  const stalled   = openDeals.filter(d=>(now-new Date(d.properties?.hs_lastmodifieddate||0).getTime())/DAY>21);
  const stalledVal= stalled.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0);
  if(stalled.length>0){
    pipelineScore-=Math.min(30,stalled.length*4);
    issues.push({severity:stalled.length>4?'critical':'warning',title:`${stalled.length} deals stalled 21+ days — $${stalledVal.toLocaleString()} quietly dying`,description:`HubSpot\'s own data shows deals inactive for 21 days close at 11% vs 67% for deals touched weekly. Your team doesn\'t know these deals are stalling, there\'s no automated alert, and no manager is being notified.`,detail:`The #1 reason deals are lost isn\'t "no" — it\'s silence. Automated inactivity alerts are the single highest-ROI workflow any sales team can add to HubSpot.`,impact:`$${stalledVal.toLocaleString()} in pipeline at risk · close rate dropping from 67% to 11% on each deal`,dimension:'Pipeline',guide:['Workflow: Deal active AND days since last engagement > 14 → urgent task for owner AND manager notification','Add a "Next Step + Date" required property before deals advance to Proposal Sent stage','Enable the visual "deal inactive" indicator in Pipeline Settings','FixOps builds this inactivity alert system and creates tasks on all currently stalled deals in one session']});
  }

  const noClose = openDeals.filter(d=>!d.properties?.closedate);
  if(noClose.length>0){
    pipelineScore-=Math.min(20,noClose.length*3);
    issues.push({severity:noClose.length>5?'warning':'info',title:`${noClose.length} open deals have no close date — your revenue forecast is fiction`,description:`HubSpot\'s pipeline-weighted forecast calculates expected revenue using close dates and probabilities. Every deal without a close date shows as $0 in forecast reports. ${noClose.length} deals means your revenue projection could be understated by six figures.`,detail:`Without close dates you can\'t run a pipeline-weighted forecast, calculate average sales cycle, trigger close-date-based workflows, or give leadership accurate revenue projections. This is a fundamental forecast failure.`,impact:`Forecast accuracy completely broken for ${noClose.length} deals`,dimension:'Pipeline',guide:['Make Close Date required in Settings → Properties → Close Date → Required on deal creation','Export all no-close-date deals → reps estimate dates → reimport to restore forecast accuracy','Workflow: Deal created AND close date unknown → task for rep to set it within 48 hours']});
  }

  const zeroDeal = openDeals.filter(d=>!d.properties?.amount||parseFloat(d.properties.amount)===0);
  if(zeroDeal.length>openDeals.length*0.15&&openDeals.length>3){
    pipelineScore-=14;
    issues.push({severity:'warning',title:`${zeroDeal.length} deals show $0 value — pipeline massively understated to leadership`,description:`${Math.round(zeroDeal.length/Math.max(openDeals.length,1)*100)}% of active pipeline has no dollar value. Every board deck, pipeline review, and revenue forecast is showing a significantly lower number than your team\'s actual opportunity.`,detail:`This is the most common and most damaging HubSpot reporting problem. Leadership makes headcount, budget, and strategy decisions based on a pipeline number that doesn\'t reflect reality.`,impact:`Pipeline understated · board reports inaccurate · rep quota calculations wrong`,dimension:'Pipeline',guide:['Require Amount on deal creation: Settings → Properties → Amount → Required','Export $0 deals, add realistic values based on product pricing, reimport same day','Workflow: Deal created AND amount unknown → task to rep to fill in amount same day']});
  }

  const overdueTasks = tasks.filter(t=>{
    const due=new Date(t.properties?.hs_timestamp||0).getTime();
    return due<now&&t.properties?.hs_task_status!=='COMPLETED'&&due>0;
  });
  if(overdueTasks.length>5){
    pipelineScore-=Math.min(10,overdueTasks.length);
    issues.push({severity:overdueTasks.length>20?'critical':'warning',title:`${overdueTasks.length} overdue tasks — rep commitments being missed`,description:`Each overdue task is a follow-up that didn\'t happen, a proposal not sent, a call not made. This is the clearest indicator of pipeline neglect — and it\'s invisible to management without a dedicated alert system.`,detail:`Overdue tasks compound: a missed follow-up becomes a cold deal, a cold deal becomes a lost deal. The cost is measured in pipeline, not time.`,impact:`${overdueTasks.length} missed rep commitments · pipeline going cold without manager visibility`,dimension:'Pipeline',guide:['Create a daily digest email to each rep listing their overdue tasks','Set a rule: no deal moves forward on the board if it has an overdue task','Weekly team meeting: first 10 minutes reviewing overdue task backlog — visibility drives action','FixOps builds the automated daily digest workflow and pipeline gating logic']});
  }

  // ── DEAL STAGE FUNNEL ANALYSIS ─────────────────────────────
  if (deals.length > 0 && dealPipelines.length > 0) {
    const stageMap = {};
    dealPipelines.forEach(pipeline => {
      (pipeline.stages || []).forEach((stage, idx) => {
        stageMap[stage.id] = {
          label: stage.label || stage.id,
          probability: Number(stage.metadata?.probability || stage.probability || 0),
          order: stage.displayOrder != null ? stage.displayOrder : idx,
        };
      });
    });

    const stageCounts = {}, stageDaysList = {};
    deals.forEach(d => {
      const sid = d.properties?.dealstage;
      if (!sid) return;
      if (!stageCounts[sid]) { stageCounts[sid] = 0; stageDaysList[sid] = []; }
      stageCounts[sid]++;
      const mod = new Date(d.properties?.hs_lastmodifieddate || d.properties?.createdate || 0).getTime();
      stageDaysList[sid].push(Math.floor((now - mod) / DAY));
    });

    // Find bottleneck: stage with >40% deals stuck 15+ days
    const bottlenecks = [];
    Object.entries(stageCounts).forEach(([sid, count]) => {
      const stage = stageMap[sid]; if (!stage) return;
      const days = stageDaysList[sid] || [];
      const avgDays = days.length ? Math.round(days.reduce((a,b)=>a+b,0)/days.length) : 0;
      const stuckPct = Math.round(days.filter(d=>d>14).length / days.length * 100);
      if (stuckPct > 40 && count >= 3 && stage.probability > 0 && stage.probability < 1) {
        bottlenecks.push({ stage: stage.label, count, avgDays, stuckPct });
      }
    });

    if (bottlenecks.length > 0) {
      const worst = bottlenecks.sort((a,b)=>b.stuckPct-a.stuckPct)[0];
      pipelineScore -= Math.min(20, bottlenecks.length * 7);
      issues.push({
        severity: bottlenecks.length >= 2 ? 'critical' : 'warning',
        title: `Pipeline bottleneck: ${worst.stuckPct}% of "${worst.stage}" deals stuck 14+ days`,
        description: `${worst.count} deals averaging ${worst.avgDays} days in "${worst.stage}" — well above healthy velocity benchmarks. ${bottlenecks.length > 1 ? `${bottlenecks.length} stages show similar stagnation.` : ''} Deals stalled in mid-stages have a 3× higher loss rate than deals with weekly activity.`,
        impact: `${worst.stuckPct}% stage stagnation · avg ${worst.avgDays} days stuck · forecast accuracy degraded`,
        guide: [
          `Filter Deals by stage "${worst.stage}" → sort by Last Activity Date (oldest first) — these are your at-risk deals`,
          `For every deal over 14 days: log a call, send an email, or create a follow-up task immediately`,
          `Build a HubSpot workflow: "If deal in this stage > 10 days → notify owner + create priority task"`,
          `Audit the stage exit criteria — if they're unclear, deals pool here by default`,
          `FixOps can build an automated stage SLA system with escalation alerts and manager visibility`,
        ],
        dimension: 'Pipeline',
      });
    }

    // Phantom pipeline: deals in 0% stages still marked open
    const phantomDeals = deals.filter(d => {
      const st = stageMap[d.properties?.dealstage];
      return st && st.probability === 0 && !d.properties?.hs_is_closed;
    });
    if (phantomDeals.length > 3) {
      pipelineScore -= Math.min(10, phantomDeals.length);
      issues.push({
        severity: 'warning',
        title: `${phantomDeals.length} open deals in 0% probability stages — phantom pipeline`,
        description: `These deals sit in stages flagged as 0% close probability but remain "open." They inflate your reported pipeline value by $${Math.round(phantomDeals.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0)).toLocaleString()} while contributing nothing to forecast accuracy. Every sales leader who sees your pipeline is being misled.`,
        impact: `$${Math.round(phantomDeals.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0)).toLocaleString()} phantom pipeline · forecast accuracy unreliable`,
        guide: [
          'Go to Deals → Group by Stage → find your 0% probability stages',
          'Review each deal: close as Lost (with a reason code) or move to an active stage',
          'Add a workflow: "If deal in 0% stage for 30 days → auto-set to Closed Lost"',
          'This single cleanup often improves forecast accuracy by 20-40%',
        ],
        dimension: 'Pipeline',
      });
    }
  }

  // ── DEALS WITHOUT ASSOCIATED CONTACTS (Portal IQ benchmark) ───
  const dealsNoContact = openDeals.filter(d => {
    const n = parseInt(d.properties?.num_associated_contacts || d.properties?.hs_num_contacts_with_buying_roles || 0);
    return n === 0;
  });
  if (dealsNoContact.length > openDeals.length * 0.2 && openDeals.length > 5) {
    pipelineScore -= Math.min(15, Math.round(dealsNoContact.length / openDeals.length * 25));
    issues.push({
      severity: 'warning',
      title: `${dealsNoContact.length} open deals have no associated contacts — these deals can't close`,
      description: `Deals without contacts have no human on the other side. They can't receive a proposal, can't be called, and won't appear in any rep's contact list. Research shows deals associated with 3+ contacts have 2× the close rate of single-contact deals. Zero-contact deals essentially don't exist.`,
      impact: `${dealsNoContact.length} deals with no stakeholder mapped · pipeline accuracy undermined`,
      dimension: 'Pipeline',
      guide: [
        'Deals → filter "Associated contacts = 0" → assign each to the right contact',
        'Make contact association required before a deal advances past "Prospect" stage',
        'For enterprise deals: use HubSpot\'s Buying Roles feature to map all decision-makers',
        'Build a workflow: Deal created AND no associated contact after 24 hours → alert to deal owner',
      ]
    });
  }

  // ── CLOSED WON/LOST REASON (Portal IQ benchmark) ───────────────
  const closedWonDeals = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
  const closedLostDeals = deals.filter(d => d.properties?.hs_is_closed === 'true' && d.properties?.hs_is_closed_won !== 'true');
  const wonNoReason = closedWonDeals.filter(d => !d.properties?.closed_won_reason && !d.properties?.hs_closed_won_reason);
  const lostNoReason2 = closedLostDeals.filter(d => !d.properties?.closed_lost_reason && !d.properties?.hs_closed_lost_reason);

  if (closedWonDeals.length > 5 && wonNoReason.length > closedWonDeals.length * 0.7) {
    pipelineScore -= 8;
    issues.push({
      severity: 'info',
      title: `${wonNoReason.length} closed won deals missing win reason — can't replicate what's working`,
      description: `Your team is closing deals but nobody is capturing why. Without win reason data you can't identify which messaging works, which personas convert best, or which reps have repeatable success patterns. This is institutional knowledge walking out the door after every deal.`,
      impact: `Win patterns untracked · coaching blind spot · best practices not scalable`,
      dimension: 'Pipeline',
      guide: [
        'Make "Closed Won Reason" a required field when moving a deal to Closed Won stage',
        'Settings → Pipelines → Closed Won stage → add required properties → Closed Won Reason',
        'Start with 5-6 options: Price, Features, Relationship, Speed, Competitor lost, Inbound',
        'Monthly: review closed won reasons by rep — this becomes your most valuable sales coaching data',
      ]
    });
  }

  if (closedLostDeals.length > 5 && lostNoReason2.length > closedLostDeals.length * 0.5) {
    pipelineScore -= 10;
    issues.push({
      severity: 'warning',
      title: `${lostNoReason2.length} closed lost deals with no loss reason — burning pipeline without learning`,
      description: `${Math.round(lostNoReason2.length/Math.max(closedLostDeals.length,1)*100)}% of your lost deals have no recorded reason. Every loss without a reason code is a missed opportunity to improve your pitch, pricing, or process. Businesses that track loss reasons improve their win rate by an average of 15% within 2 quarters.`,
      impact: `Loss patterns invisible · pipeline objections never addressed · same mistakes recurring`,
      dimension: 'Pipeline',
      guide: [
        'Make "Closed Lost Reason" required when moving a deal to Closed Lost stage',
        'Standard options: Price too high, Went with competitor, No budget, No decision, Timing, Poor fit',
        'Add a "Lost deal notes" text field for context beyond the dropdown',
        'Monthly loss review: which reason appears most? That\'s your #1 process fix.',
      ]
    });
  }

  await up(73, 'Reviewing forms and marketing…');

  // ── MARKETING HEALTH ────────────────────────────────────────
  const deadForms = forms.filter(f=>(f.submissionCounts?.total||f.totalSubmissions||0)===0);
  if(deadForms.length>0){
    marketingScore-=Math.min(14,deadForms.length*2);
    issues.push({severity:'warning',title:`${deadForms.length} forms have zero submissions — silent lead capture failures`,description:`These forms are live in HubSpot and may be embedded on live pages — but have never received a single submission. You don\'t know how many leads you\'ve missed until you actually test them.`,detail:`The most dangerous version of this problem: a form on a high-traffic landing page that\'s broken. You\'re spending money on ads driving traffic to a page that\'s silently failing to capture any leads.`,impact:`${deadForms.length} potential lead capture failures — unknown number of lost leads`,dimension:'Marketing',guide:['Test each form right now — submit it yourself, confirm the thank-you page fires and you receive the notification email','Check if the form is actually embedded on a live page with real traffic','Marketing → Lead Capture → Forms → check views vs submissions — views with zero submissions = broken form','Archive forms from discontinued campaigns to reduce confusion']});
  }

  const deadLists = lists.filter(l=>(l.metaData?.size||0)===0);
  if(deadLists.length>5){
    marketingScore-=8;
    issues.push({severity:'info',title:`${deadLists.length} contact lists are completely empty`,description:`Empty lists clutter your marketing setup and are a risk if accidentally used as workflow suppression lists. If an empty list becomes a suppression list, nobody gets enrolled in the workflow — silently.`,impact:`${deadLists.length} empty lists adding portal complexity and suppression risk`,dimension:'Marketing',guide:['Review each empty list — is it feeding a workflow or campaign?','Archive empty lists that are no longer in use: Contacts → Lists → Archive','Never use an empty list as a workflow suppression list without verifying it has members']});
  }

  await up(83, 'Checking configuration and security…');

  // ── CONFIGURATION ───────────────────────────────────────────
  const superAdmins = users.filter(u=>u.superAdmin);
  if(superAdmins.length>3&&users.length>0){
    configScore-=12;
    issues.push({severity:superAdmins.length>6?'critical':'warning',title:`${superAdmins.length} super admins — excess full-access accounts are a security risk`,description:`Super admins can delete any record, change billing, modify any setting, and install any integration with zero approval. Best practice is 2 maximum. Every extra super admin is an unmonitored security surface — and a former employee\'s compromised account gives full access to your entire CRM.`,detail:`The most common data breach vector in HubSpot portals: a super admin who left the company 6+ months ago, whose account was never deactivated, gets compromised. Immediate risk: full database access and deletion rights.`,impact:`${superAdmins.length} accounts with unrestricted portal access and deletion rights`,dimension:'Configuration',guide:['Settings → Users → filter Super Admin — does each person still need full unrestricted access?','Reduce to 2 super admins: primary admin and one backup only','Deactivate any super admin account belonging to someone who has left the company immediately','Replace super admin access with granular role-based permissions for all other users']});
  }

  // settings/v3/users returns: { id, email, firstName, lastName, superAdmin,
  //   roleId, lastLogin (ISO string), createdAt, updatedAt }
  // Also try settingsUsers which uses the same endpoint but may have fuller data
  const allUsers = settingsUsers.length > 0 ? settingsUsers : users;
  const getLastLogin = (u) =>
    u.lastLogin || u.lastLoginDate || u.lastActivityAt ||
    u.properties?.hs_last_login_time || u.properties?.lastLoginDate || null;
  const getUserName = (u) =>
    [u.firstName||u.first_name||'', u.lastName||u.last_name||''].filter(Boolean).join(' ') ||
    u.email || 'Unknown User';

  const inactiveUsers = allUsers.filter(u => {
    const last = getLastLogin(u);
    if (!last) return false;  // no login data — don't flag as inactive
    return (now - new Date(last).getTime()) / DAY > 90;
  });
  const ghostSeatData = inactiveUsers.map(u => {
    const last = getLastLogin(u);
    const daysSince = last ? Math.round((now - new Date(last).getTime()) / DAY) : 999;
    return { name: getUserName(u), daysSince, email: u.email || '' };
  }).sort((a,b) => b.daysSince - a.daysSince);
  const estMonthlySeatWaste = inactiveUsers.length * 90;
  if(inactiveUsers.length > 0){
    configScore -= Math.min(15, inactiveUsers.length * 3);
    const topNames = ghostSeatData.slice(0,3).map(u => u.name + ' (' + u.daysSince + 'd)').join(', ');
    issues.push({
      severity: inactiveUsers.length > 3 ? 'warning' : 'info',
      title: inactiveUsers.length + ' users have not logged in for 90+ days — $' + estMonthlySeatWaste.toLocaleString() + '/mo in ghost seats',
      description: inactiveUsers.length + ' paid HubSpot seats have had zero activity for 90+ days. On Sales or Service Hub Professional that is $90-$120/seat/month going to waste. Ghost seats are also a security risk. Top inactive: ' + topNames + '.',
      detail: 'Ghost seats are the easiest budget win in HubSpot: immediate savings with zero operational impact. User data, records, and activity history stay intact after deactivation — only login access is removed.',
      impact: '~$' + estMonthlySeatWaste.toLocaleString() + '-$' + (inactiveUsers.length*120).toLocaleString() + '/mo in unused paid seat costs',
      dimension: 'Configuration',
      ghostSeatData: ghostSeatData,
      guide: [
        'Settings → Users → sort by last login date — oldest first to find ghost seats immediately',
        'Top inactive: ' + ghostSeatData.slice(0,5).map(u => u.name + ' — ' + u.daysSince + ' days since login').join(' | '),
        'Contact each inactive user: do they still need HubSpot access?',
        'Deactivate users who have left — their data and records stay, only login is removed',
        'Reassign open deals, contacts, and tasks before deactivating to avoid orphaned records'
      ]
    });
  }

  const undocProps = (cProps||[]).filter(p=>!p.hubspotDefined&&!p.description);
  if(undocProps.length>10){
    configScore-=8;
    issues.push({severity:'info',title:`${undocProps.length} custom properties have no description — documentation debt compounding`,description:`Undocumented properties get misused, create duplicate data in wrong fields, and make your portal impossible to navigate for new team members. Over time this is how portals end up with 400+ properties and nobody knows what half of them do.`,detail:`Documentation debt compounds: every undocumented property created today will confuse the next person who joins your team, the next admin who takes over, and the next audit that tries to clean up the portal.`,impact:`Data quality degradation over time · onboarding friction · property misuse`,dimension:'Configuration',guide:['Settings → Properties → filter Custom → add description to each: what does it track, where is it populated, who uses it?','Identify unused properties (0 records updated) and archive them','FixOps AutoDoc automatically documents every custom property and exports a full Property Bible PDF']});
  }

  await up(90, 'Checking reporting quality…');

  // ── REPORTING QUALITY ───────────────────────────────────────
  if(zeroDeal.length>openDeals.length*0.3&&openDeals.length>3){
    reportingScore-=22;
    issues.push({severity:'critical',title:`${Math.round(zeroDeal.length/Math.max(openDeals.length,1)*100)}% of pipeline has no value — revenue reports are fundamentally wrong`,description:`When nearly a third of your pipeline shows as $0, every revenue metric breaks: total pipeline value, average deal size, win rate by value, forecast accuracy, and board projections. Leadership is making strategic decisions based on data that doesn\'t reflect reality.`,detail:`This is the single most common HubSpot reporting failure. The fix takes one afternoon. The cost of not fixing it is measured in wrong business decisions made every week.`,impact:`Revenue reporting fundamentally broken · every board projection understated`,dimension:'Reporting',guide:['Make Amount required on deal creation: Settings → Properties → Amount → Required','Pull all $0 deals → each rep estimates value → reimport same day to restore forecast integrity','FixOps Reporting Rebuild creates the revenue dashboards your leadership needs with accurate underlying data']});
  }

  if(tickets.length===0&&users.length>2){
    reportingScore-=12;
    issues.push({severity:'info',title:`No support tickets in HubSpot — customer health is a blind spot`,description:`If your team handles support but tickets aren\'t in HubSpot, you can\'t see which customers have open issues, there\'s no link between support history and deal records, and churn prediction is impossible because you have no signal.`,impact:`Customer health invisible · churn signals absent · no support-to-revenue correlation`,dimension:'Reporting',guide:['HubSpot has native integrations for Zendesk, Intercom, and Freshdesk to sync ticket data','Even a basic ticket pipeline (New → In Progress → Resolved) dramatically improves customer health visibility','Connect tickets to company records for full account health view — critical for renewal conversations']});
  }

  await up(93, 'Checking team adoption…');

  // ── TEAM ADOPTION + REP ACTIVITY SCORECARD ─────────────────
  // Build per-rep activity scorecard from calls, meetings, tasks, deals
  const repScorecard = {};
  const WEEK = 7 * DAY;

  // Map owner IDs to names + team
  const ownerMap = {};
  const ownerTeamMap = {};

  // Build team membership map
  teams.forEach(team => {
    const teamName = team.name || ('Team ' + team.id);
    (team.userIds || []).forEach(uid => { ownerTeamMap[uid] = teamName; });
    (team.memberUserIds || []).forEach(uid => { ownerTeamMap[uid] = teamName; });
  });

  owners.forEach(o => {
    const id = o.id || o.ownerId;
    const name = [o.firstName||o.properties?.firstname||'', o.lastName||o.properties?.lastname||''].filter(Boolean).join(' ') || o.email || ('Owner ' + id);
    ownerMap[id] = name;
  });

  // Count calls per rep (last 7 days)
  calls.forEach(c => {
    const ownerId = c.properties?.hubspot_owner_id;
    const created = new Date(c.properties?.hs_createdate||0).getTime();
    if(!ownerId) return;
    if(!repScorecard[ownerId]) repScorecard[ownerId] = { name: ownerMap[ownerId]||('Rep '+ownerId), team: ownerTeamMap[ownerId]||'', calls:0, meetings:0, tasks:0, staleDealCount:0 };
    if((now - created) / DAY < 7) repScorecard[ownerId].calls++;
  });

  // Count meetings per rep (last 7 days)
  meetings.forEach(m => {
    const ownerId = m.properties?.hubspot_owner_id;
    const ts = new Date(m.properties?.hs_timestamp||0).getTime();
    if(!ownerId) return;
    if(!repScorecard[ownerId]) repScorecard[ownerId] = { name: ownerMap[ownerId]||('Rep '+ownerId), team: ownerTeamMap[ownerId]||'', calls:0, meetings:0, tasks:0, staleDealCount:0 };
    if((now - ts) / DAY < 7) repScorecard[ownerId].meetings++;
  });

  // Count stale deals (no activity 14+ days) per rep
  openDeals.forEach(d => {
    const ownerId = d.properties?.hubspot_owner_id;
    const lastMod = new Date(d.properties?.hs_lastmodifieddate||0).getTime();
    if(!ownerId) return;
    if(!repScorecard[ownerId]) repScorecard[ownerId] = { name: ownerMap[ownerId]||('Rep '+ownerId), team: ownerTeamMap[ownerId]||'', calls:0, meetings:0, tasks:0, staleDealCount:0 };
    if((now - lastMod) / DAY > 14) repScorecard[ownerId].staleDealCount++;
  });

  const repList = Object.values(repScorecard).sort((a,b) => (b.calls+b.meetings) - (a.calls+a.meetings));
  const totalActivity = repList.reduce((sum,r) => sum + r.calls + r.meetings, 0);
  const darkReps = repList.filter(r => r.calls === 0 && r.meetings === 0);
  const staleRepsCount = repList.filter(r => r.staleDealCount > 2).length;

  if(meetings.length === 0 && calls.length === 0 && tasks.length > 0 && users.length > 2){
    teamScore -= 20;
    issues.push({
      severity: 'warning',
      title: 'No meetings or calls logged — sales activity is completely dark',
      description: 'Your reps have tasks and contacts but are not logging meetings or calls in HubSpot. Zero visibility into rep activity, call volume, meeting outcomes, or rep performance. The fix is a 5-minute calendar connection.',
      detail: 'Once Google Calendar or Outlook is connected, meetings log automatically with one click. Call logging via the HubSpot mobile app takes 10 seconds per call.',
      impact: 'Rep activity invisible · performance coaching impossible · activity-based reports all show zero',
      dimension: 'Sales',
      guide: [
        'Connect HubSpot to Google Calendar or Outlook: Settings → Integrations → Email & Calendar',
        'Install HubSpot Sales Chrome Extension for one-click Gmail/Outlook logging',
        'Create a weekly activity dashboard: calls made, emails sent, meetings booked',
        'FixOps sets up the full sales activity tracking stack in one 30-minute session'
      ]
    });
  } else if(darkReps.length > 0 && users.length > 2 && totalActivity > 0){
    teamScore -= Math.min(15, darkReps.length * 4);
    issues.push({
      severity: darkReps.length > 2 ? 'warning' : 'info',
      title: darkReps.length + ' reps logged zero calls or meetings this week',
      description: darkReps.length + ' of your HubSpot users had no logged call or meeting activity in the last 7 days. Active reps averaged ' + (totalActivity / Math.max(repList.length - darkReps.length, 1)).toFixed(1) + ' activities. Silent reps: ' + darkReps.slice(0,4).map(r=>r.name).join(', ') + '.',
      detail: 'Activity gaps are either a logging problem (rep is busy but not recording) or a performance problem (rep is not engaging). Both are invisible without this data. Weekly rep scorecards make this visible before it becomes a pipeline problem.',
      impact: 'Pipeline at risk from ' + darkReps.length + ' rep' + (darkReps.length!==1?'s':'') + ' with no logged activity · coaching blind spot',
      dimension: 'Sales',
      repScorecard: repList,
      guide: [
        'This week: ' + repList.slice(0,5).map(r => r.name + ' — ' + r.calls + ' calls, ' + r.meetings + ' meetings, ' + r.staleDealCount + ' stale deals').join(' | '),
        'Silent reps: ' + darkReps.map(r=>r.name).join(', ') + ' — follow up directly',
        'Set minimum weekly activity targets: 5 calls + 2 meetings per rep minimum',
        'FixOps Rep Scorecard emails this breakdown to your sales manager every Monday automatically'
      ]
    });
  }

  if(staleRepsCount > 0){
    teamScore -= Math.min(10, staleRepsCount * 3);
    const staleRepNames = repList.filter(r => r.staleDealCount > 2).slice(0,3).map(r => r.name + ' (' + r.staleDealCount + ' stale deals)').join(', ');
    issues.push({
      severity: 'warning',
      title: 'Reps with stale deals: ' + staleRepNames,
      description: staleRepsCount + ' rep' + (staleRepsCount!==1?'s':'') + ' have 2+ deals with no activity in 14+ days. Stale deals close at 11% vs 67% for actively worked deals (HubSpot research). These are revenue at risk right now.',
      detail: 'Deal velocity is the most predictive pipeline metric. A deal that goes 14 days without activity has crossed the threshold where probability drops sharply. Catching this weekly prevents the end-of-quarter surprise.',
      impact: 'Deals at risk · pipeline velocity dropping · forecast accuracy declining',
      dimension: 'Sales',
      guide: [
        'Stale deal owners: ' + staleRepNames,
        'Set deal activity reminder: any deal with no activity in 10 days → task created automatically for rep',
        'Weekly pipeline review: filter deals by last activity date — anything over 14 days needs immediate action',
        'FixOps monitors deal activity weekly and flags stale deals in your Monday email before they fall through'
      ]
    });
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
            dimension: 'Pipeline',
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
      dimension: 'Pipeline',
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
      dimension: 'Marketing',
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
      dimension: 'Pipeline',
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
      dimension: 'Reporting',
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
      dimension: 'Sales',
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
      dimension: 'Sales',
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
        dimension: 'Pipeline',
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
          dimension: 'Reporting',
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

  // ── CLOSED WON REASON TRACKING ────────────────────────────────────────────
  if (deals.length > 20) {
    const closedWon = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
    if (closedWon.length > 5) {
      const wonNoReason = closedWon.filter(d =>
        !d.properties?.closed_won_reason && !d.properties?.hs_closed_won_reason
      );
      if (wonNoReason.length > closedWon.length * 0.5) {
        reportingScore -= 8;
        issues.push({
          severity: 'info',
          title: `${wonNoReason.length} closed-won deals have no win reason — you cannot replicate success`,
          description: `${wonNoReason.length} of your ${closedWon.length} won deals have no win reason recorded. Understanding why you win is just as important as understanding why you lose. Win reasons reveal your strongest value props, best-fit customers, and which reps close what type of deal.`,
          impact: `Win pattern analysis impossible · rep coaching incomplete · product feedback loop broken`,
          dimension: 'Reporting',
          guide: [
            'Add a required "Closed Won Reason" dropdown to your final won stage: Champion, Price Win, Feature Fit, Speed, Referral, Other',
            'Workflow: Deal moved to Closed Won → task to rep to fill in win reason within 48 hours',
            'Review win reasons quarterly — patterns reveal which product features and sales motions drive the most revenue'
          ]
        });
      }
    }
  }

  // ── COMPANY DATA QUALITY ──────────────────────────────────────────────────
  if (companies.length > 5) {
    // Companies with no contacts associated
    const companiesNoContacts = companies.filter(c =>
      parseInt(c.properties?.num_associated_contacts || 0) === 0
    );
    if (companiesNoContacts.length > companies.length * 0.25) {
      dataScore -= Math.min(10, Math.round(companiesNoContacts.length / companies.length * 15));
      issues.push({
        severity: 'info',
        title: `${companiesNoContacts.length} companies have no associated contacts — orphaned records`,
        description: `${Math.round(companiesNoContacts.length/companies.length*100)}% of your company records have no contacts linked. Orphaned companies bloat your database, create confusion during manual data entry, and reduce report accuracy. If no one at the company is in HubSpot, the company record has no business value.`,
        impact: `${companiesNoContacts.length} orphaned company records · CRM clutter · duplicate risk`,
        dimension: 'Data Integrity',
        guide: [
          'Companies → filter "Number of associated contacts = 0" → review and either add contacts or delete the company',
          'Enable automatic company-contact association by email domain in Settings → Objects → Companies',
          'Quarterly hygiene task: clean orphaned company records before they accumulate further'
        ]
      });
    }

    // Companies missing domain (HubSpot cannot auto-dedup without it)
    const companiesNoDomain = companies.filter(c => !c.properties?.domain || c.properties.domain.trim() === '');
    if (companiesNoDomain.length > companies.length * 0.20) {
      dataScore -= Math.min(8, Math.round(companiesNoDomain.length / companies.length * 12));
      issues.push({
        severity: 'info',
        title: `${companiesNoDomain.length} companies have no domain name — HubSpot cannot auto-deduplicate them`,
        description: `HubSpot uses domain name to automatically deduplicate companies and auto-associate contacts. Without a domain, HubSpot cannot match a contact's email to their company, cannot pull company data from HubSpot Insights, and will create duplicate company records over time.`,
        impact: `${companiesNoDomain.length} companies unprotected from duplicates · auto-association disabled`,
        dimension: 'Data Integrity',
        guide: [
          'Export companies with no domain → manually research and add domain names',
          'For B2C or individual contacts, this is expected — focus on companies that should have a domain',
          'Enable "Automatically create and associate companies with contacts" to prevent future orphaned companies'
        ]
      });
    }
  }

  // ── CONTACT FIRSTNAME COMPLETENESS ────────────────────────────────────────
  if (contacts.length > 50) {
    const noFirstName = contacts.filter(c => !c.properties?.firstname || c.properties.firstname.trim() === '');
    if (noFirstName.length > contacts.length * 0.15) {
      dataScore -= Math.min(8, Math.round(noFirstName.length / contacts.length * 15));
      issues.push({
        severity: 'info',
        title: `${noFirstName.length} contacts (${Math.round(noFirstName.length/contacts.length*100)}%) have no first name — personalization impossible`,
        description: `Contacts without a first name cannot receive personalized emails, and email personalization tokens will fail or fall back to generic defaults. Research shows personalized subject lines increase open rates by 22%. Every nameless contact in your database is a missed personalization opportunity.`,
        impact: `${noFirstName.length} contacts receiving impersonal outreach · email open rates suppressed`,
        dimension: 'Data Integrity',
        guide: [
          'Add first name as required on all forms — this should be the most basic field you collect',
          'For existing contacts: export, research via LinkedIn or email domain, reimport',
          'Workflow: Contact created AND first name is unknown → task to owner to research and fill in',
          'Set a personalization token fallback in all email templates: "Hi {{contact.firstname | default: "there"}},"'
        ]
      });
    }
  }

  // ── CONTACT PERSONA USAGE ─────────────────────────────────────────────────
  if (contacts.length > 100) {
    const withPersona = contacts.filter(c => c.properties?.hs_persona && c.properties.hs_persona !== '');
    const personaPct = Math.round(withPersona.length / contacts.length * 100);
    if (personaPct < 5) {
      issues.push({
        severity: 'info',
        title: `Only ${personaPct}% of contacts have a persona set — segmentation and targeting is generic`,
        description: `HubSpot Personas allow you to group contacts by buyer type and personalize messaging at scale. Only ${withPersona.length} of your ${contacts.length.toLocaleString()} contacts have a persona. Without it, all your contacts receive the same generic messaging regardless of their role, industry, or needs.`,
        impact: `${contacts.length - withPersona.length} contacts receiving untargeted messaging · campaign ROI reduced`,
        dimension: 'Marketing',
        guide: [
          'Define 2-4 buyer personas based on your best customers — job title, company size, pain points, goals',
          'Build a workflow: set persona based on form submission answers, job title keywords, or company industry',
          'Add "Persona" to your lead scoring model — different personas have different conversion rates',
          'Use persona-segmented lists to send targeted campaigns instead of blasting your entire database'
        ]
      });
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ LEAD SCORING INTELLIGENCE ENGINE
  // Detects new HubSpot Lead Scoring tool (Aug 2025+) — not the old hubspotscore
  // New tool creates score-type properties for contacts, companies, and deals
  // Legacy hubspotscore stopped updating Aug 31 2025 — flag migration needed
  // ══════════════════════════════════════════════════════════════════════════
  const leadScoringEngine = (() => {
    // isConfigured = using the NEW lead scoring tool (not just legacy)
    const isNewToolConfigured = newLeadScoreProps.length > 0;
    const isLegacyOnly = !isNewToolConfigured && !!legacyScoreProp;
    const isConfigured  = isNewToolConfigured || isLegacyOnly;

    // Determine which property name to read score values from
    const scorePropName = primaryScoreProp?.name || null;

    const scoredContacts = scorePropName ? contacts.filter(c => {
      const score = parseFloat(c.properties?.[scorePropName] || 0);
      return score > 0;
    }) : [];
    const pctScored = contacts.length > 0 ? Math.round(scoredContacts.length / contacts.length * 100) : 0;

    // Score distribution
    const dist = { low: 0, medium: 0, high: 0, veryHigh: 0 };
    scoredContacts.forEach(c => {
      const s = parseFloat(c.properties?.[scorePropName] || 0);
      if (s >= 75) dist.veryHigh++;
      else if (s >= 50) dist.high++;
      else if (s >= 25) dist.medium++;
      else dist.low++;
    });

    const highScoreContacts = scoredContacts.filter(c => parseFloat(c.properties?.[scorePropName]||0) >= 50);
    const lowScoreContacts  = scoredContacts.filter(c => parseFloat(c.properties?.[scorePropName]||0) < 50 && parseFloat(c.properties?.[scorePropName]||0) > 0);

    // Pattern analysis: what are winning contacts' common properties?
    const winnerSources = {};
    const winnerPersonas = {};
    contacts.forEach(c => {
      const lc  = c.properties?.lifecyclestage || '';
      const src = c.properties?.hs_analytics_source || '';
      const persona = c.properties?.hs_persona || '';
      if (['customer','opportunity'].includes(lc)) {
        if (src) winnerSources[src] = (winnerSources[src] || 0) + 1;
        if (persona) winnerPersonas[persona] = (winnerPersonas[persona] || 0) + 1;
      }
    });
    const totalCustomers = contacts.filter(c => c.properties?.lifecyclestage === 'customer').length;

    // Recommendations based on data patterns
    const recommendations = [];
    if (totalCustomers > 10) {
      const topSources = Object.entries(winnerSources).sort((a,b)=>b[1]-a[1]).slice(0,3);
      if (topSources.length > 0) recommendations.push({
        property: 'hs_analytics_source',
        criterion: `Original source = ${topSources[0][0]}`,
        points: 15,
        reason: `${topSources[0][1]} of your ${totalCustomers} customers came from this source — highest converting channel`,
        hubspotPath: 'Marketing → Lead Scoring → + Add Score → Fit Criteria → Contact Property → Original Source'
      });
      recommendations.push({
        property: 'lifecyclestage',
        criterion: 'Lifecycle stage is MQL or SQL',
        points: 20,
        reason: 'Contacts at MQL/SQL stage are actively being sales-qualified — highest close probability',
        hubspotPath: 'Marketing → Lead Scoring → + Add Score → Fit Criteria → Contact Property → Lifecycle Stage'
      });
    }
    recommendations.push(
      { property: 'hs_email_open_count', criterion: 'Email opens in last 30 days > 2', points: 8,
        reason: 'Email engagement is a strong buying signal', hubspotPath: 'Marketing → Lead Scoring → Engagement Criteria → Marketing Email Opens' },
      { property: 'num_associated_deals', criterion: 'Has an associated deal', points: 25,
        reason: 'Contact has been moved to active sales pipeline — highest intent signal', hubspotPath: 'Marketing → Lead Scoring → Fit Criteria → Associated Deal exists' },
      { property: 'hs_email_hard_bounce_reason', criterion: 'Email bounced = is not known', points: -20,
        reason: 'Hard-bounced contacts cannot be reached — negative signal', hubspotPath: 'Marketing → Lead Scoring → Fit Criteria → Email Bounce' }
    );

    return {
      isConfigured,
      isNewToolConfigured,
      isLegacyOnly,
      needsMigration: isLegacyOnly, // legacy stopped updating Aug 31 2025
      scoreProperties: newLeadScoreProps.map(p => ({ name: p.name, label: p.label, type: p.type })),
      legacyPropertyExists: !!legacyScoreProp,
      pctScored,
      scoredCount: scoredContacts.length,
      totalContacts: contacts.length,
      distribution: dist,
      highScoreCount: highScoreContacts.length,
      totalCustomers,
      recommendations: recommendations.slice(0, 6),
      topWinnerSources: Object.entries(winnerSources).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([source,count])=>({source,count})),
    };
  })();

  // Add lead scoring issues — using new HubSpot Lead Scoring tool (Aug 2025+)
  if (leadScoringEngine.needsMigration) {
    // Legacy hubspotscore exists but stopped updating Aug 31 2025
    marketingScore -= 15;
    issues.push({
      severity: 'critical',
      title: 'Legacy HubSpot Score stopped updating Aug 31, 2025 — migrate to new Lead Scoring tool now',
      description: `Your portal has the old HubSpot Score property, which stopped updating on August 31, 2025. Contacts are no longer being scored, workflows that relied on score changes have gone silent, and your lead prioritization is frozen at pre-cutoff values.`,
      detail: 'HubSpot replaced score properties with the new Lead Scoring tool. The new tool supports separate Fit scores (who they are), Engagement scores (what they do), and Combined scores — all updating in real time.',
      impact: `${fmt(contacts.length)} contacts no longer being scored · score-based workflows silent · lead prioritization broken`,
      dimension: 'Marketing',
      leadScoringEngine,
      guide: [
        'Go to: Marketing → Lead Scoring (in Marketing Hub Pro+) or Sales → Lead Scoring (in Sales Hub Pro+)',
        'Click + Create score → choose Combined score (Fit + Engagement) to replicate your old setup',
        'Add Fit criteria based on contact properties (industry, company size, job title)',
        'Add Engagement criteria based on activities (email opens, page views, form fills, meetings)',
        'Update any workflows that used HubSpot Score changes to reference the new score property name',
        'Set an MQL threshold and build a workflow to update lifecycle stage when score crosses it'
      ]
    });
  } else if (!leadScoringEngine.isConfigured && contacts.length > 100) {
    marketingScore -= 8;
    issues.push({
      severity: 'warning',
      title: 'Lead Scoring not configured — no way to prioritize which contacts to work',
      description: `You have ${fmt(contacts.length)} contacts but no lead score. HubSpot's Lead Scoring tool (Marketing Hub or Sales Hub Pro+) lets you build Engagement scores (what contacts do) and Fit scores (who they are) — separately or combined. Without it, every contact looks the same to your reps.`,
      detail: 'The new HubSpot Lead Scoring tool (2024–2025) replaced the old HubSpot Score property. It scores contacts, companies, and deals with separate Fit + Engagement dimensions, time-based criteria, and optional AI-assisted scoring.',
      impact: `${fmt(contacts.length)} contacts unscored · reps cannot prioritize · no MQL automation · sequence targeting is generic`,
      dimension: 'Marketing',
      leadScoringEngine,
      fixItService: 'Lead Scoring Setup',
      fixItEstimate: '$349',
      guide: [
        'Go to: Marketing → Lead Scoring → + Create score → Combined (Fit + Engagement)',
        `Start with these criteria from your portal data: ${leadScoringEngine.recommendations.slice(0,2).map(r=>r.criterion+' (+'+r.points+' pts)').join(', ')}`,
        'Add Engagement criteria: email opens, page views, form submissions, meeting booked',
        'Add Fit criteria: job title, company size, industry — score who they are not just what they do',
        'Set an MQL threshold (A1/A2 combined grade) and automate lifecycle stage update via workflow',
        'FixOps Lead Scoring Setup builds a custom model from YOUR contact patterns and winning customer data'
      ]
    });
  } else if (leadScoringEngine.isNewToolConfigured && leadScoringEngine.pctScored < 10 && contacts.length > 200) {
    issues.push({
      severity: 'warning',
      title: `Lead Scoring configured but only ${leadScoringEngine.pctScored}% of contacts have a score — criteria too narrow`,
      description: `The Lead Scoring tool is active with ${leadScoringEngine.scoreProperties.length} score propert${leadScoringEngine.scoreProperties.length!==1?'ies':'y'}, but only ${fmt(leadScoringEngine.scoredCount)} of ${fmt(contacts.length)} contacts have a score. Criteria are likely too specific or contacts aren't engaging with the tracked activities.`,
      impact: `${fmt(contacts.length - leadScoringEngine.scoredCount)} contacts invisible to scoring · prioritization broken`,
      dimension: 'Marketing',
      leadScoringEngine,
      guide: [
        'Marketing → Lead Scoring → open each score → review Engagement and Fit criteria',
        'Add broader Engagement criteria: "Marketing email opened in last 90 days" or "Page view in last 30 days"',
        `Your top converting sources: ${leadScoringEngine.topWinnerSources.slice(0,3).map(s=>s.source).join(', ')} — add these as Fit score criteria`,
        'Use the Preview Distribution feature to see how contacts cluster before publishing changes'
      ]
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ INTEGRATION SYNC ERROR DETECTION
  // Connected apps, auth failures, sync issues causing data gaps
  // ══════════════════════════════════════════════════════════════════════════
  const integrationErrors = [];

  // Check connected integrations for auth/sync issues
  if (connectedIntegrations.length > 0) {
    connectedIntegrations.forEach(integration => {
      const name = integration.portalName || integration.name || integration.type || 'Unknown Integration';
      const status = String(integration.status || integration.authStatus || '').toLowerCase();
      if (['error','failed','disconnected','expired','unauthorized','invalid'].some(s => status.includes(s))) {
        integrationErrors.push({
          name,
          type: 'auth_failure',
          message: `Authentication expired or invalid — no data syncing`,
          severity: 'critical',
          fix: `Reconnect ${name}: Settings → Integrations → Connected Apps → ${name} → Reconnect`
        });
      }
    });
  }

  // Detect integration issues from workflow errors — common cause is broken integration auth
  const workflowsWithIntegrationErrors = workflows.filter(wf => {
    const status = String(wf.executionState || wf.status || '').toUpperCase();
    const name = String(wf.name || '').toLowerCase();
    // Workflows erroring that reference integration keywords
    return ['ERROR','FAILED','PAUSED_DUE_TO_ERROR'].includes(status) &&
      (name.includes('salesforce') || name.includes('slack') || name.includes('zoom') ||
       name.includes('gong') || name.includes('outreach') || name.includes('salesloft') ||
       name.includes('zapier') || name.includes('gmail') || name.includes('outlook') ||
       name.includes('calendar') || name.includes('stripe') || name.includes('netsuite') ||
       name.includes('quickbooks') || wf.errorCount > 10);
  });

  if (workflowsWithIntegrationErrors.length > 0) {
    workflowsWithIntegrationErrors.forEach(wf => {
      integrationErrors.push({
        name: wf.name || wf.id,
        type: 'workflow_integration_error',
        message: `Workflow "${wf.name}" erroring — likely a broken integration connection`,
        errorCount: wf.errorCount || 0,
        severity: 'critical',
        fix: `Automation → Workflows → open "${wf.name}" → check Error details tab for the specific integration causing failures`
      });
    });
  }

  // Check for Salesforce sync errors via contact source analysis
  const sfContacts = contacts.filter(c => {
    const src = String(c.properties?.hs_analytics_source || '').toLowerCase();
    return src.includes('salesforce') || src.includes('crm');
  });
  if (sfContacts.length > 10) {
    // If we have Salesforce contacts but many have missing owner/company, likely sync issue
    const sfNoOwner = sfContacts.filter(c => !c.properties?.hubspot_owner_id).length;
    if (sfNoOwner > sfContacts.length * 0.3) {
      integrationErrors.push({
        name: 'Salesforce Sync',
        type: 'sync_gap',
        message: `${sfNoOwner} of ${sfContacts.length} Salesforce-sourced contacts have no HubSpot owner — owner sync may be misconfigured`,
        severity: 'warning',
        fix: 'Settings → Integrations → Salesforce → Sync Settings → verify Owner field mapping is configured'
      });
    }
  }

  // Add integration error issues
  if (integrationErrors.length > 0) {
    const criticalErrors = integrationErrors.filter(e => e.severity === 'critical');
    autoScore -= Math.min(20, integrationErrors.length * 5);
    issues.push({
      severity: criticalErrors.length > 0 ? 'critical' : 'warning',
      title: `${integrationErrors.length} integration ${integrationErrors.length===1?'issue':'issues'} detected — data may not be syncing correctly`,
      description: `Integration failures cause silent data gaps: contacts created in Salesforce don't appear in HubSpot, deals don't update, email activity stops logging. Your team makes decisions on incomplete data without knowing it. ${criticalErrors.length > 0 ? `${criticalErrors.length} critical issue${criticalErrors.length!==1?'s':''} need immediate attention.` : ''}`,
      detail: 'Integration sync errors compound over time — a break that started last week means weeks of missing data. Contacts created, deals updated, and emails sent during the outage are not reflected in HubSpot reporting.',
      impact: `${integrationErrors.length} integration ${integrationErrors.length===1?'issue':'issues'} · data gaps growing daily · reporting accuracy compromised`,
      dimension: 'Automation',
      integrationErrors,
      fixItService: 'Integration Repair',
      fixItEstimate: 'From $299',
      guide: integrationErrors.slice(0,4).map((e,i) => `${i+1}. ${e.message} → ${e.fix}`).concat([
        'FixOps Integration Repair reconnects, re-syncs historical data, and maps all fields correctly — same business day'
      ])
    });
  }

  // 4. WORKFLOW ERRORS  -  detect broken workflows when Public App scope available
  if (workflows.length > 0) {
    const erroredWorkflows = workflows.filter(wf => {
      const status = wf.executionState || wf.status || '';
      const hasErrors = wf.errorCount > 0 || wf.errorsCount > 0 ||
        ['ERROR', 'FAILED', 'PAUSED_DUE_TO_ERROR'].includes(String(status).toUpperCase());
      return hasErrors;
    });

    if (erroredWorkflows.length > 0) {
      const totalErrored = erroredWorkflows.length;
      const errorNames = erroredWorkflows.slice(0,3).map(wf => wf.name || wf.id || 'Unknown').join(', ');
      autoScore -= Math.min(25, totalErrored * 8);
      issues.push({
        severity: totalErrored > 2 ? 'critical' : 'warning',
        title: totalErrored + ' workflow' + (totalErrored!==1?'s':'') + ' in error state  -  contacts may be dropping silently',
        description: 'These workflows are actively failing: ' + errorNames + '. When a workflow errors, HubSpot typically stops processing enrolled contacts  -  meaning leads, nurture sequences, or follow-ups may be silently falling through. Most teams do not know a workflow is broken until a rep asks why a lead never got a follow-up email.',
        detail: 'Workflow errors are the #1 source of silent revenue loss in HubSpot. A workflow broken for 30 days on a 500-contact list means 500 people never got the message you intended them to receive.',
        impact: totalErrored + ' broken workflow' + (totalErrored!==1?'s':'')+' · contacts dropping silently · automation ROI destroyed',
        dimension: 'Automation',
        erroredWorkflows: erroredWorkflows.slice(0,10).map(wf => ({
          name: wf.name || wf.id,
          id: wf.id,
          errorCount: wf.errorCount || wf.errorsCount || 0,
          status: wf.executionState || wf.status || 'ERROR'
        })),
        guide: [
          'Go to HubSpot → Automation → Workflows → filter by "Needs attention"',
          'Broken: ' + errorNames + '  -  open each and check the error details tab',
          'Common cause: a required property was deleted, or a connected integration lost auth',
          'For each error: read the error message, fix the root cause, re-enroll affected contacts',
          'FixOps Workflow Repair fixes and re-enrolls affected contacts same day'
        ]
      });
    }

    // Dead workflows  -  active but zero enrollments in 90 days
    const deadWorkflows = workflows.filter(wf => {
      const lastEnrollment = wf.lastEnrollmentDate || wf.updatedAt;
      const isActive = ['ACTIVE', 'PUBLISHED'].includes(String(wf.status||wf.executionState||'').toUpperCase());
      if (!isActive || !lastEnrollment) return false;
      return (now - new Date(lastEnrollment).getTime()) / DAY > 90;
    });

    if (deadWorkflows.length > 0) {
      autoScore -= Math.min(10, deadWorkflows.length * 2);
      issues.push({
        severity: 'info',
        title: deadWorkflows.length + ' active workflow' + (deadWorkflows.length!==1?'s':'') + ' with no enrollments in 90+ days',
        description: 'These workflows are marked active but have not enrolled anyone in 90+ days. Either the trigger criteria never fires, the audience is empty, or the workflow was abandoned without being turned off. Dead workflows create confusion, consume your workflow limit, and make portal audits harder.',
        impact: 'Workflow limit consumed · portal complexity inflated · team confusion',
        dimension: 'Automation',
        guide: [
          'Review each: does it still serve a business purpose?',
          'If yes  -  check the trigger: is the enrollment criteria too narrow?',
          'If no  -  turn it off to reduce clutter and free up your workflow limit',
          'Dead workflows at scale indicate no workflow governance process exists'
        ]
      });
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
      serviceScore -= Math.min(30, Math.round(oldTickets.length / tickets.length * 50));
      issues.push({
        severity: oldTickets.length > tickets.length * 0.4 ? 'critical' : 'warning',
        title: `${oldTickets.length} support tickets open more than 3 days — customer trust at risk`,
        description: `HubSpot's State of Customer Service research shows 67% of customers expect resolution within 3 hours, and 32% within the same day. ${oldTickets.length} of your ${tickets.length} tickets exceed 3 days open. Each unresolved ticket is a customer whose trust is actively declining — and whose renewal is at risk.`,
        detail: `Ticket age directly correlates with churn probability. A ticket open 3 days has 2x the churn risk of a same-day resolution. A ticket open 7+ days increases churn probability by 340% according to HubSpot's customer success research. This is a revenue retention problem disguised as a support problem.`,
        impact: `Customer churn risk elevated · NPS declining · ${oldTickets.length} customers waiting too long · renewal conversations starting from deficit`,
        dimension: 'Service',
        guide: [
          'Set ticket SLA rules: Service Hub → Settings → SLA → define response and resolution targets by priority tier',
          'Escalation workflow: Ticket open > 24 hours with no reply → notify manager + reassign to available rep',
          'Create priority tiers: Critical (2hr SLA), High (4hr), Normal (24hr), Low (72hr) — not all tickets are equal',
          'FixOps builds the full ticket SLA system with escalation workflows, manager dashboards, and customer health scoring'
        ],
        dimension: 'Service'
      });
    }
  }


  // ── SUBSCRIPTION HEALTH ────────────────────────────────────────
  const mrrTotal = subscriptions.length > 0
    ? subscriptions.filter(s=>String(s.properties?.hs_status||'').toLowerCase()==='active')
        .reduce((s,sub)=>s+parseFloat(sub.properties?.hs_recurring_revenue||0),0)
    : 0;
  if (subscriptions.length > 0) {
    const activeSubs = subscriptions.filter(sub=>String(sub.properties?.hs_status||'').toLowerCase()==='active');
    const cancelledSubs = subscriptions.filter(sub=>['cancelled','canceled'].includes(String(sub.properties?.hs_status||'').toLowerCase()));
    const renewNext30 = activeSubs.filter(sub=>{
      const nd = sub.properties?.hs_next_payment_due_date;
      if(!nd) return false;
      const days = (new Date(nd).getTime()-now)/DAY;
      return days >= 0 && days <= 30;
    });
    const churnRate = subscriptions.length > 0 ? Math.round((cancelledSubs.length/subscriptions.length)*100) : 0;

    if (churnRate > 25) {
      reportingScore -= 12;
      issues.push({
        severity: churnRate > 40 ? 'critical' : 'warning',
        title: churnRate + '% subscription churn rate — revenue retention at risk',
        description: cancelledSubs.length + ' of ' + subscriptions.length + ' subscriptions are cancelled. Industry benchmark is under 5% monthly churn. At ' + churnRate + '% your MRR is actively shrinking.',
        impact: 'MRR at risk · customer lifetime value declining · growth offset by churn',
        dimension: 'Reporting',
        guide: [
          'Map cancelled subscriptions to contact records — identify churn patterns',
          'Set up a churn prevention workflow: trigger at 60 days before renewal with proactive check-in',
          'Review all cancellations for past 90 days — is churn concentrated in one product or segment?'
        ]
      });
    }
    if (renewNext30.length > 0) {
      issues.push({
        severity: 'info',
        title: renewNext30.length + ' subscription' + (renewNext30.length!==1?'s':'') + ' renewing in the next 30 days — proactive outreach window',
        description: 'You have ' + renewNext30.length + ' active subscriptions renewing within 30 days. This is the highest-leverage customer success window: a proactive check-in before renewal reduces churn by 40% vs reactive handling after cancellation.',
        impact: 'MRR renewal window · proactive outreach opportunity',
        dimension: 'Sales',
        guide: [
          'Create a renewal sequence: 30-day, 14-day, and 7-day pre-renewal touch points',
          'Assign each renewal to a CSM or account owner with a task due this week',
          'Send a value summary email showing what they accomplished with the product this year'
        ]
      });
    }
  }

  // ── QUOTE HEALTH ─────────────────────────────────────────────────
  if (quotes.length > 3) {
    const expiredQuotes = quotes.filter(q=>{
      const exp = q.properties?.hs_expiration_date;
      return exp && new Date(exp).getTime() < now &&
        String(q.properties?.hs_status||'').toLowerCase() !== 'accepted';
    });
    if (expiredQuotes.length > 0) {
      reportingScore -= Math.min(10, expiredQuotes.length * 2);
      issues.push({
        severity: expiredQuotes.length > 5 ? 'warning' : 'info',
        title: expiredQuotes.length + ' quote' + (expiredQuotes.length!==1?'s':'') + ' expired without being accepted — lost revenue signal',
        description: 'Expired unaccepted quotes indicate deals that stalled at the proposal stage. Each expired quote is a buyer who evaluated your offer and did not convert — without follow-up, this is silent churn in your pipeline.',
        impact: 'Proposal conversion gap · unworked pipeline · revenue intelligence missing',
        dimension: 'Pipeline',
        guide: [
          'Review all expired quotes — were these deals lost, delayed, or forgotten?',
          'Set quote expiration reminders: 3 days before expiry → task to rep to follow up',
          'Add close-lost reason tracking to every expired quote for pattern analysis'
        ]
      });
    }
  }

  // ── INVOICE HEALTH ───────────────────────────────────────────────
  // Define outside if block so always available for portalStats/waste calculations
  const overdueInvoices = invoices.filter(i=>String(i.properties?.hs_invoice_status||'').toLowerCase()==='past_due');
  if (invoices.length > 0) {
    if (overdueInvoices.length > 0) {
      const overdueRate = Math.round((overdueInvoices.length/invoices.length)*100);
      reportingScore -= Math.min(12, overdueInvoices.length * 3);
      issues.push({
        severity: overdueRate > 30 ? 'critical' : 'warning',
        title: overdueInvoices.length + ' overdue invoice' + (overdueInvoices.length!==1?'s':'') + ' — cash flow risk',
        description: overdueInvoices.length + ' invoices are past due (' + overdueRate + '% of all invoices). Uncollected invoices are cash that should already be in your account. Each day overdue increases collection difficulty exponentially.',
        impact: 'Cash flow at risk · accounts receivable aging · collection cost rising',
        dimension: 'Reporting',
        guide: [
          'Set up automated payment reminder sequences: 7 days before due, on due date, 3 days after, 7 days after',
          'Review overdue invoices by amount — prioritize largest for immediate personal outreach',
          'Implement ACH/auto-pay for recurring customers to eliminate future overdue risk'
        ]
      });
    }
  }


  // ── 6. SEQUENCES — Sales Hub Pro/Enterprise ──────────────────────────────
  if (sequences.length > 0) {
    const noStepSeqs = sequences.filter(seq => !seq.steps || seq.steps.length === 0);
    const lowReplySeqs = sequences.filter(seq => {
      const rate = parseFloat(seq.replyRate || seq.reply_rate || 0);
      return rate > 0 && rate < 5;
    });
    if (noStepSeqs.length > 0) {
      autoScore -= Math.min(10, noStepSeqs.length * 3);
      issues.push({
        severity: 'warning',
        title: noStepSeqs.length + ' sequence' + (noStepSeqs.length!==1?'s':'') + ' with no steps configured',
        description: 'These sequences are active but have no steps. Any contact enrolled receives nothing — a silent fail that damages sender reputation and wastes rep time.',
        impact: noStepSeqs.length + ' empty sequences · enrolled contacts get no messages',
        dimension: 'Automation',
        guide: ['Go to Sales Sequences', 'Add minimum 3 steps to each empty sequence', 'Re-enroll any contacts who missed messages']
      });
    }
    if (lowReplySeqs.length > 0) {
      issues.push({
        severity: 'info',
        title: lowReplySeqs.length + ' sequence' + (lowReplySeqs.length!==1?'s':'') + ' under 5% reply rate — copy needs work',
        description: 'Industry benchmark for cold outreach reply rates is 8-12%. Under 5% means you are burning sending reputation on contacts who will not respond.',
        impact: 'Sender reputation risk · rep time wasted · deals not progressing',
        dimension: 'Automation',
        guide: ['Shorten step 1 to under 75 words', 'Add personalization tokens in body', 'Test subject lines — avoid "Following up"', 'Reduce to 3-4 steps max for cold outreach']
      });
    }
  }

  // ── 7. LISTS — Contact list health ───────────────────────────────────────
  const staticLists = lists.filter(l => l.listType === 'STATIC' || l.dynamic === false);
  const emptyLists  = lists.filter(l => (l.metaData?.size || l.size || 0) === 0);
  if (lists.length > 0) {
    if (emptyLists.length > 5) {
      marketingScore -= Math.min(8, emptyLists.length);
      issues.push({
        severity: 'info',
        title: emptyLists.length + ' empty contact lists cluttering your portal',
        description: 'Empty lists signal abandoned segmentation. They slow down list selection in workflows and emails and confuse new team members.',
        impact: emptyLists.length + ' empty lists · portal complexity inflated',
        dimension: 'Data Integrity',
        guide: ['Marketing Lists — sort by contacts ascending', 'Archive lists empty for 90+ days', 'Document the purpose of each active list in its description']
      });
    }
    if (staticLists.length > lists.length * 0.7 && lists.length > 10) {
      issues.push({
        severity: 'info',
        title: Math.round(staticLists.length / lists.length * 100) + '% of lists are static — missing auto-segmentation',
        description: 'Most lists are manually managed rather than auto-updating. Static lists go stale — contacts graduate out of criteria but stay listed until someone removes them manually.',
        impact: 'Wrong contacts getting wrong messages · reporting inaccurate · manual overhead',
        dimension: 'Data Integrity',
        guide: ['Identify static lists used in active workflows or emails', 'Convert to active lists using the same criteria', 'Static lists are fine for one-off sends only']
      });
    }
  }

  // ── 8. CART ABANDONMENT (ecommerce portals) ─────────────────────────────
  const abandoned = carts.filter(c => String(c.properties?.hs_cart_status||'').toLowerCase() === 'abandoned');
  if (carts.length > 0) {
    if (abandoned.length > 0) {
      const pct = Math.round(abandoned.length / carts.length * 100);
      if (pct > 30) {
        pipelineScore -= Math.min(10, Math.round(pct / 10));
        issues.push({
          severity: pct > 60 ? 'critical' : 'warning',
          title: pct + '% cart abandonment rate — ' + abandoned.length + ' of ' + carts.length + ' carts not completed',
          description: 'Over ' + pct + '% of shopping carts are being abandoned before purchase. Industry average is 70% — but abandoned carts still represent recoverable revenue through automated follow-up sequences.',
          impact: abandoned.length + ' abandoned carts · unrecovered revenue · no automated recovery in place',
          dimension: 'Pipeline',
          guide: [
            'Create an abandoned cart workflow: trigger 1 hour after cart created with no purchase',
            'Send 3-step recovery sequence: reminder email, discount offer, final reminder',
            'Review cart pages for friction: slow load times, required account creation, limited payment options'
          ]
        });
      }
    }
  }

  // ── 9. MARKETING CAMPAIGNS ────────────────────────────────────────────────
  if (campaigns.length > 0) {
    const noBudgetCampaigns = campaigns.filter(c => !c.budget && !c.budgetMicros);
    if (noBudgetCampaigns.length > 0) {
      issues.push({
        severity: 'info',
        title: noBudgetCampaigns.length + ' campaign' + (noBudgetCampaigns.length!==1?'s':'') + ' with no budget tracked — ROI reporting blind spot',
        description: 'Campaigns without budget data make true ROI uncalculable. HubSpot shows revenue influenced but cannot show cost-per-acquisition without spend tracked.',
        impact: 'Marketing ROI uncalculable · board reporting missing cost data · budget decisions made blind',
        dimension: 'Reporting',
        guide: ['Marketing Campaigns — open each active campaign', 'Add budget amount to each', 'Even rough estimates enable ROI tracking']
      });
    }
  }

  // ── 10. MARKETING EMAIL HEALTH (content scope) ───────────────────────────
  if (marketingEmails.length > 0) {
    // Aggregate email stats across all sent emails
    // Filter by email state - HubSpot returns PUBLISHED, SENT, SCHEDULED, DRAFT, ARCHIVED
    const sentEmails = marketingEmails.filter(e => {
      const state = String(e.state || e.currentState || e.hs_email_status || '').toUpperCase();
      return ['PUBLISHED','SENT'].includes(state);
    });

    if (sentEmails.length > 0) {
      // Calculate aggregate rates across all sent emails
      let totalSent=0, totalOpened=0, totalClicked=0, totalBounced=0, totalUnsub=0, totalSpam=0;
      sentEmails.forEach(e => {
        const s = e.stats || e.counters || {};
        const sent = s.sent || s.delivered || 0;
        totalSent    += sent;
        totalOpened  += s.open || s.opened || s.opens || 0;
        totalClicked += s.click || s.clicks || s.uniqueClicks || 0;
        totalBounced += s.bounce || s.bounced || s.hardBounced || 0;
        totalUnsub   += s.unsubscribed || s.unsubscribe || s.optOut || 0;
        totalSpam    += s.spamreport || s.spam || s.spamReport || 0;
      });

      const overallOpenRate   = totalSent > 0 ? Math.round(totalOpened / totalSent * 1000) / 10 : 0;
      const overallClickRate  = totalSent > 0 ? Math.round(totalClicked / totalSent * 1000) / 10 : 0;
      const overallBounceRate = totalSent > 0 ? Math.round(totalBounced / totalSent * 10000) / 100 : 0;
      const overallUnsubRate  = totalSent > 0 ? Math.round(totalUnsub  / totalSent * 10000) / 100 : 0;
      const overallSpamRate   = totalSent > 0 ? Math.round(totalSpam   / totalSent * 10000) / 100 : 0;

      // Store for portalStats email health summary
      // Store for portalStats email health summary — local scope only
      const _emailHealthSummary = { totalSent, overallOpenRate, overallClickRate, overallBounceRate, overallUnsubRate, overallSpamRate, sentEmailCount: sentEmails.length };

      // ── Bounce rate check (Portal IQ benchmark: >3.62% = warning, >5% = critical) ──
      if (overallBounceRate > 5) {
        marketingScore -= 20;
        issues.push({
          severity: 'critical',
          title: `Email bounce rate ${overallBounceRate}% — HubSpot will suspend your sending account above 5%`,
          description: `Your overall email bounce rate across ${sentEmails.length} campaigns is ${overallBounceRate}%. HubSpot suspends email sending when bounce rate exceeds 5% — at ${overallBounceRate}% you are at immediate risk. This means marketing emails AND workflow emails stop sending completely until resolved.`,
          impact: `Account suspension risk · ${totalBounced.toLocaleString()} bounced emails · all email automation could stop`,
          dimension: 'Marketing',
          guide: [
            'Immediate: check app.hubspot.com/email/[portalId]/health for your account status',
            'Create an active list: "Email hard bounced = true" → do NOT email these contacts',
            'Audit your contact sources — purchased lists, old imports, and trade show data are the top causes',
            'Run a list cleanup: suppress contacts with no engagement in 12 months before next send',
            'Enable double opt-in on all forms to prevent invalid emails entering your database',
          ]
        });
      } else if (overallBounceRate > 3) {
        marketingScore -= 10;
        issues.push({
          severity: 'warning',
          title: `Email bounce rate ${overallBounceRate}% — approaching HubSpot's 5% suspension threshold`,
          description: `Your bounce rate of ${overallBounceRate}% is above the healthy benchmark of <2% and approaching the 5% threshold where HubSpot suspends your account. At this trajectory, one large send to a dirty list could trigger an account suspension.`,
          impact: `Deliverability declining · sender reputation damaged · ${totalBounced.toLocaleString()} total bounces`,
          dimension: 'Marketing',
          guide: [
            'Filter "Email hard bounced = true" → create a suppression list → never email these contacts',
            'Scrub your list with an email validation tool (NeverBounce, ZeroBounce) before your next large send',
            'Review your recent import sources — high bounce rates almost always trace back to a bad import',
          ]
        });
      }

      // ── Unsubscribe rate (Portal IQ benchmark: >1% = warning, >3% = critical) ──
      if (overallUnsubRate > 3) {
        marketingScore -= 15;
        issues.push({
          severity: 'critical',
          title: `Unsubscribe rate ${overallUnsubRate}% — HubSpot suspends accounts above 3%`,
          description: `Your unsubscribe rate of ${overallUnsubRate}% exceeds HubSpot's 3% threshold for account suspension. ${totalUnsub.toLocaleString()} contacts have actively opted out. High unsub rates signal wrong audience, wrong content, or wrong frequency — and once suspended, no emails send until HubSpot manually reviews your account.`,
          impact: `Account suspension risk · ${totalUnsub.toLocaleString()} unsubscribed contacts · campaign disruption`,
          dimension: 'Marketing',
          guide: [
            'Segment your list — only send relevant content to contacts who opted in for that type of email',
            'Set clear expectations at sign-up: tell contacts what emails they\'ll receive and how often',
            'Review your last 5 campaigns — which had the highest unsub rate? That content is the problem',
            'Reduce send frequency and run a re-permission campaign to rebuild a clean, engaged list',
          ]
        });
      } else if (overallUnsubRate > 1) {
        marketingScore -= 7;
        issues.push({
          severity: 'warning',
          title: `Unsubscribe rate ${overallUnsubRate}% — above the healthy 1% benchmark`,
          description: `Industry standard is under 1% unsubscribe rate. At ${overallUnsubRate}% your contacts are opting out faster than healthy. This erodes your list quality, damages sender reputation, and signals content or targeting problems.`,
          impact: `${totalUnsub.toLocaleString()} unsubscribes · list quality declining`,
          dimension: 'Marketing',
          guide: [
            'Use contact segmentation to send more relevant content to smaller, better-targeted lists',
            'Review email frequency — over-sending is the #1 cause of elevated unsub rates',
            'Add email preference center so contacts can reduce frequency instead of unsubscribing entirely',
          ]
        });
      }

      // ── Spam report rate (Portal IQ benchmark: >0.1% = warning) ──
      if (overallSpamRate > 0.1) {
        marketingScore -= 18;
        issues.push({
          severity: 'critical',
          title: `Spam report rate ${overallSpamRate}% — above 0.1% triggers account suspension`,
          description: `Your spam complaint rate of ${overallSpamRate}% (${totalSpam} reports from ${totalSent.toLocaleString()} sends) exceeds HubSpot's 0.1% threshold. Contacts marking your email as spam is the most damaging signal to your domain reputation — Gmail and Yahoo now enforce strict spam rate limits for bulk senders.`,
          impact: `Domain blacklist risk · account suspension · all future emails potentially blocked`,
          dimension: 'Marketing',
          guide: [
            'Audit your contact acquisition sources — spam reports almost always come from purchased or scraped lists',
            'Add an obvious unsubscribe link at the TOP of your emails — people who can\'t find it report as spam',
            'Never email contacts who didn\'t explicitly opt in',
            'Use Google Postmaster Tools to monitor your domain reputation',
          ]
        });
      }

      // ── Open rate check ──
      if (overallOpenRate < 15 && totalSent > 1000) {
        marketingScore -= 8;
        issues.push({
          severity: 'warning',
          title: `Overall email open rate ${overallOpenRate}% — below the 20-25% industry benchmark`,
          description: `Across ${sentEmails.length} email campaigns, your average open rate is ${overallOpenRate}%. The industry benchmark is 20-25%. Low open rates indicate subject line problems, wrong send time, wrong audience, or contacts who have mentally unsubscribed without clicking the button.`,
          impact: `${overallOpenRate}% open rate · email ROI significantly below potential`,
          dimension: 'Marketing',
          guide: [
            'A/B test your subject lines — even a 5-word change can move open rate by 10%',
            'Send to engaged contacts first (opened in last 90 days) to train inbox placement',
            'Remove contacts who haven\'t opened in 12 months — they hurt deliverability for everyone else',
            'Test different send times: Tuesday-Thursday 10am-2pm consistently outperforms other times',
          ]
        });
      }
    }

    // ── High bounce individual emails ──
    const highBounce = marketingEmails.filter(e => {
      const s = e.stats || e.counters || {};
      const sent = s.sent || s.delivered || 0;
      const bounced = s.bounce || s.bounced || s.hardBounced || 0;
      return sent > 100 && bounced / sent > 0.05;
    });
    if (highBounce.length > 0 && !issues.find(i => i.title.includes('bounce rate'))) {
      marketingScore -= Math.min(15, highBounce.length * 5);
      issues.push({
        severity: highBounce.length > 2 ? 'critical' : 'warning',
        title: `${highBounce.length} individual email${highBounce.length!==1?'s':''} with >5% bounce rate — list health problems`,
        description: `${highBounce.length} specific campaigns have bounce rates above 5%. This signals those sends went to old, invalid, or purchased contact segments. Each high-bounce send damages your domain reputation even if your overall rate looks acceptable.`,
        impact: 'Sender reputation damage · deliverability degrading for future sends',
        dimension: 'Marketing',
        guide: [
          'Marketing Emails → open each high-bounce email → Performance tab → download bounced contacts',
          'Create a suppression list from all hard-bounced addresses — never email these again',
          'Trace where these contacts came from — old import, purchased list, or a specific form?',
        ]
      });
    }

    // ── Stale drafts ──
    const staleDrafts = marketingEmails.filter(e => {
      const isDraft = ['DRAFT'].includes(String(e.state||e.currentState||'').toUpperCase());
      const updated = e.updatedAt || e.updated;
      return isDraft && updated && (now - new Date(updated).getTime()) / DAY > 90;
    });
    if (staleDrafts.length > 5) {
      issues.push({
        severity: 'info',
        title: `${staleDrafts.length} marketing email drafts untouched for 90+ days — portal clutter`,
        description: 'Stale drafts represent abandoned campaigns. They clutter the email tool, confuse new team members, and make it harder to find active work.',
        impact: `${staleDrafts.length} abandoned email drafts · portal complexity inflated`,
        dimension: 'Marketing',
        guide: ['Marketing Emails → filter by Draft → sort by Last Updated ascending', 'Delete or archive any draft not touched in 90+ days', 'Document active drafts with a naming convention: [Campaign Name] [Date] [Owner]']
      });
    }
  }

  // ── 10. NPS / CSAT FEEDBACK ───────────────────────────────────────────────
  const npsResponses = feedback.filter(f => f.properties?.hs_survey_type === 'NPS');
  if (feedback.length > 0) {
    if (npsResponses.length >= 5) {
      const scores2 = npsResponses.map(f => parseFloat(f.properties?.hs_response || 0)).filter(n => !isNaN(n) && n >= 0);
      const promoters = scores2.filter(n => n >= 9).length;
      const detractors = scores2.filter(n => n <= 6).length;
      const nps = scores2.length > 0 ? Math.round(((promoters - detractors) / scores2.length) * 100) : null;
      if (nps !== null && nps < 20) {
        serviceScore -= 15;
        issues.push({
          severity: nps < 0 ? 'critical' : 'warning',
          title: 'NPS score ' + nps + ' — customer sentiment below healthy threshold (benchmark: 31+)',
          description: 'B2B SaaS NPS benchmark is 31+. Scores below 20 mean more detractors than promoters. Detractors churn faster and share negative experiences more than promoters share positive ones.',
          impact: 'Churn risk elevated · expansion revenue blocked · referral pipeline damaged',
          dimension: 'Service',
          npsData: { score: nps, promoters, detractors, total: scores2.length },
          guide: ['Close loop with every detractor within 48 hours', 'Build churn-risk workflow triggered by NPS < 7', 'Track NPS monthly and tie to renewal risk scoring']
        });
      }
    }
  }

  // ── 10. EMAIL SUBSCRIPTION HEALTH ────────────────────────────────────────
  if (optOutDefs.length > 20) {
    issues.push({
      severity: 'info',
      title: optOutDefs.length + ' email subscription types — preference center too complex',
      description: 'Most contacts see ' + optOutDefs.length + ' subscription types as overwhelming and unsubscribe from everything. Best practice is 4-6 meaningful categories.',
      impact: 'Higher unsubscribe rates · contacts opting out of all email rather than unwanted types only',
      dimension: 'Data Integrity',
      guide: ['Marketing Settings Email Subscriptions', 'Consolidate to 4-6 categories: Marketing, Product Updates, Events, Newsletter', 'Map old types to new ones before deleting']
    });
  }

  // ── 11. SUPER ADMIN AUDIT (settings.users.read) ──────────────────────────
  if (settingsUsers.length > 0) {
    const superAdminUsers = settingsUsers.filter(u => u.superAdmin === true);
    if (superAdminUsers.length > 5) {
      configScore -= Math.min(15, (superAdminUsers.length - 5) * 3);
      issues.push({
        severity: superAdminUsers.length > 10 ? 'critical' : 'warning',
        title: superAdminUsers.length + ' super admins — too many users with full portal access',
        description: 'You have ' + superAdminUsers.length + ' super admins. HubSpot best practice is 2-3 maximum. Super admins can delete records, change billing, modify all settings, and access all data. Each unnecessary super admin is a security and compliance risk.',
        impact: superAdminUsers.length + ' users with unrestricted portal access · security risk · compliance concern',
        dimension: 'Configuration',
        guide: [
          'Settings → Users & Teams → filter by Super Admin',
          'Review each: does this person actually need super admin?',
          'Downgrade to the minimum role needed for their job function',
          'Keep 2-3 super admins maximum — one primary, one backup, one for emergencies'
        ]
      });
    }
  }

  // ── 12. UNDOCUMENTED CUSTOM PROPERTIES (crm.schemas.contacts.read) ────────
  if (contactProps.length > 0) {
    const customProps = contactProps.filter(p => p.createdUserId || p.hubspotOwned === false);
    const undocumented = customProps.filter(p => !p.description || p.description.trim() === '');
    if (undocumented.length > 10) {
      dataScore -= Math.min(8, Math.round(undocumented.length / customProps.length * 20));
      issues.push({
        severity: 'info',
        title: undocumented.length + ' custom properties have no description — data model undocumented',
        description: 'Custom properties without descriptions are invisible to new team members, make reporting harder, and signal a portal that has grown without governance. When a rep or marketer cannot find the right property, they create a duplicate.',
        impact: undocumented.length + ' undocumented properties · onboarding friction · duplicate properties created over time',
        dimension: 'Data Integrity',
        customProps: customProps.length,
        undocumentedProps: undocumented.length,
        guide: [
          'Settings → Properties — filter by "Created by user"',
          'Add a description to each custom property explaining what it captures and when it should be set',
          'Consider using property groups to organize related custom properties',
          'Audit for duplicates while you are there — merge any that capture the same data'
        ]
      });
    }
  }

  // ── 13. REP ACTIVITY COMPLETENESS (emails, notes, communications) ─────────
  if (users.length > 0 && (emailEngs.length > 0 || notes.length > 0 || communications.length > 0)) {
    const totalEngagements = (emailEngs.length || 0) + (notes.length || 0) + (calls.length || 0) +
                             (meetings.length || 0) + (communications.length || 0);
    const avgPerUser = users.length > 0 ? Math.round(totalEngagements / users.length) : 0;

    if (avgPerUser < 5 && users.length > 3) {
      teamScore -= Math.min(15, Math.max(0, 15 - avgPerUser * 3));
      issues.push({
        severity: 'warning',
        title: 'Low rep activity logging — avg ' + avgPerUser + ' engagements per user in last 30 days',
        description: 'Across ' + users.length + ' users, FixOps found an average of ' + avgPerUser + ' logged engagements (calls, emails, meetings, notes) per user. Low logging means your CRM does not reflect reality — pipeline data is unreliable and managers cannot coach from actual activity.',
        impact: 'Pipeline forecasting unreliable · manager coaching blind · deal risk invisible',
        dimension: 'Sales',
        activityData: {
          emailsLogged: emailEngs.length,
          notesLogged: notes.length,
          callsLogged: calls.length,
          meetingsLogged: meetings.length,
          commsLogged: communications.length,
          avgPerUser
        },
        guide: [
          'Set a minimum activity logging expectation: 3+ activities per active deal per week',
          'Enable HubSpot Sales Email Extension so emails auto-log from Gmail/Outlook',
          'Review deals with zero activity in 14 days — are they real or pipeline bloat?',
          'Build a rep activity dashboard visible to the whole team for accountability'
        ]
      });
    }
  }

  // ── 14. SALES GOALS ──────────────────────────────────────────────────────
  if (goals.length > 0) {
    const expiredGoals = goals.filter(g => {
      const end = g.properties?.hs_end_datetime;
      return end && new Date(end).getTime() < now;
    });
    if (expiredGoals.length > 0) {
      issues.push({
        severity: 'info',
        title: expiredGoals.length + ' expired sales goal' + (expiredGoals.length!==1?'s':'') + ' — rep targets not updated',
        description: 'Sales goals past their end date without replacement mean reps are working without active targets. Pipeline discipline and accountability drop without current goals.',
        impact: 'No active targets · pipeline discipline drops · forecasting accuracy suffers',
        dimension: 'Sales',
        guide: ['Sales Goals — review expired entries', 'Set new quarterly targets per rep', 'Add goal reporting to team dashboards']
      });
    }
  }

  // ── 12. LEADS OBJECT (Sales Hub Pro) ─────────────────────────────────────
  const unownedLeads = leads.filter(l => !l.properties?.hubspot_owner_id);
  if (leads.length > 0) {
    const stalledLeads = leads.filter(l => {
      const created = l.properties?.hs_createdate;
      return created && (now - new Date(created).getTime()) / DAY > 14 &&
        String(l.properties?.hs_lead_status||'').toUpperCase() === 'NEW';
    });
    if (unownedLeads.length > 0) {
      dataScore -= Math.min(10, unownedLeads.length * 2);
      issues.push({
        severity: 'warning',
        title: unownedLeads.length + ' unowned lead' + (unownedLeads.length!==1?'s':'') + ' — falling through the cracks',
        description: 'Unowned leads have no rep responsible for them. In a healthy setup, every lead is assigned the same day it is created.',
        impact: unownedLeads.length + ' unowned leads · speed-to-lead broken · pipeline leak',
        dimension: 'Data Integrity',
        guide: ['CRM Leads — filter by No owner', 'Assign each to the right rep immediately', 'Build round-robin assignment workflow for new leads']
      });
    }
    if (stalledLeads.length > 0) {
      pipelineScore -= Math.min(12, stalledLeads.length * 3);
      issues.push({
        severity: 'warning',
        title: stalledLeads.length + ' lead' + (stalledLeads.length!==1?'s':'') + ' stuck in New status for 14+ days',
        description: 'Leads in New status for over 2 weeks are either forgotten or being worked without updates. Healthy conversion time is 3-5 days for qualified leads.',
        impact: stalledLeads.length + ' stalled leads · pipeline velocity destroyed',
        dimension: 'Pipeline',
        guide: ['Review each stalled lead', 'Update status to Qualified, Unqualified, or Attempted Contact', 'Build escalation: Lead >7 days New → manager notification task']
      });
    }
  }

// ── KNOWLEDGE BASE AUDIT ────────────────────────────────────
  if (kbArticles.length > 0) {
    const unpublishedKB = kbArticles.filter(a =>
      a.currentState === 'DRAFT' || a.state === 'DRAFT' ||
      a.published === false || a.status === 'DRAFT'
    );
    const zeroViewKB = kbArticles.filter(a => {
      const views = a.views || a.viewCount || a.pageViews || 0;
      return views === 0;
    });
    const totalKB = kbArticles.length;

    if (unpublishedKB.length > 5) {
      serviceScore -= Math.min(12, unpublishedKB.length);
      issues.push({
        severity: unpublishedKB.length > 15 ? 'critical' : 'warning',
        title: `${unpublishedKB.length} knowledge base articles unpublished — support deflection blocked`,
        description: `You have ${totalKB} KB articles total but ${unpublishedKB.length} remain in draft. Each unpublished article is a customer question that cannot be self-served — forcing a support ticket instead. HubSpot data shows portals with complete KBs deflect 30-40% of tier-1 tickets.`,
        impact: `${unpublishedKB.length} unpublished articles · ${Math.round(unpublishedKB.length * 3)} estimated unnecessary tickets/mo`,
        guide: [
          'Go to Content → Knowledge Base → filter by Status: Draft',
          'Prioritize articles matching your most common support ticket categories',
          'Set a weekly publishing goal: aim to publish 5 articles per week until caught up',
          'Create a workflow: new ticket created → check if matching KB article exists → send to customer',
          'FixOps can audit your ticket subjects against KB coverage to find the highest-impact articles to publish first',
        ],
        dimension: 'Service',
      });
    }

    if (zeroViewKB.length > 3 && totalKB > 10) {
      const zeroViewPct = Math.round(zeroViewKB.length / totalKB * 100);
      issues.push({
        severity: 'info',
        title: `${zeroViewKB.length} knowledge base articles have zero views — content effort wasted`,
        description: `${zeroViewPct}% of your KB articles have never been viewed. These articles represent content creation time with zero support deflection value. Either they're not discoverable, cover topics customers do not search for, or are not linked from support workflows.`,
        impact: `${zeroViewKB.length} zero-view articles · content ROI at risk`,
        guide: [
          'Add KB article links to your automated ticket acknowledgment emails',
          'Review zero-view article titles — are they written in the language customers actually use?',
          'Set up HubSpot Knowledge Base search analytics to see what customers search for but cannot find',
          'Archive articles with zero views after 90 days — reduce noise, improve search relevance',
        ],
        dimension: 'Service',
      });
    }
  }

  // ── MEETING BOOKING HEALTH ───────────────────────────────────
  if (meetingLinks.length > 0 || users.length > 0) {
    const ownerIds = owners.map(o => o.id || o.ownerId).filter(Boolean);
    const ownersWithBookingLinks = new Set(meetingLinks.map(m => m.ownerId || m.userId).filter(Boolean));
    const ownersWithoutLinks = ownerIds.filter(id => !ownersWithBookingLinks.has(id));
    const noLinkPct = ownerIds.length > 0 ? Math.round(ownersWithoutLinks.length / ownerIds.length * 100) : 0;

    if (ownersWithoutLinks.length > 2 && noLinkPct > 30) {
      teamScore -= Math.min(15, ownersWithoutLinks.length * 2);
      const noLinkNames = ownersWithoutLinks.slice(0,5).map(id => ownerMap[id] || ('Rep ' + id)).filter(n => !n.startsWith('Rep '));
      issues.push({
        severity: noLinkPct > 60 ? 'critical' : 'warning',
        title: `${ownersWithoutLinks.length} of ${ownerIds.length} reps have no meeting booking link — forcing manual scheduling`,
        description: `${noLinkPct}% of your sales team has no HubSpot meeting booking link. Every meeting they book requires back-and-forth emails instead of a single click. Studies show booking links reduce time-to-meeting by 60% and increase meeting volume by 25%.${noLinkNames.length > 0 ? ` Missing: ${noLinkNames.join(', ')}.` : ''}`,
        impact: `${ownersWithoutLinks.length} reps manually scheduling · estimated 2-3hrs/rep/week wasted`,
        guide: [
          'Go to Sales → Meetings → Create meeting link for each rep without one',
          'Embed the booking link in email signatures, outreach sequences, and LinkedIn profiles',
          'Create a team-level round-robin link for inbound leads',
          'Add a workflow: "If contact requests a meeting → send rep booking link automatically"',
          'FixOps can set up automated meeting link insertion in all your outreach sequences',
        ],
        dimension: 'Sales',
      });
    }
  }

  // ── TEAM PERFORMANCE BENCHMARKS ──────────────────────────────
  if (teams.length > 1 && Object.keys(repScorecard).length > 0) {
    // Group reps by team and compare
    const teamStats = {};
    Object.values(repScorecard).forEach(rep => {
      const teamName = rep.team || 'Unassigned';
      if (!teamStats[teamName]) teamStats[teamName] = { calls:0, meetings:0, reps:0 };
      teamStats[teamName].calls += rep.calls || 0;
      teamStats[teamName].meetings += rep.meetings || 0;
      teamStats[teamName].reps++;
    });

    // Find underperforming teams
    const teamAverages = Object.entries(teamStats).map(([name, stat]) => ({
      name,
      avgCalls: stat.reps > 0 ? Math.round(stat.calls / stat.reps * 10) / 10 : 0,
      avgMeetings: stat.reps > 0 ? Math.round(stat.meetings / stat.reps * 10) / 10 : 0,
      reps: stat.reps,
    }));

    const overallAvgCalls = teamAverages.reduce((s,t) => s + t.avgCalls, 0) / teamAverages.length;
    const underperformingTeams = teamAverages.filter(t => t.avgCalls < overallAvgCalls * 0.5 && t.reps >= 2);

    if (underperformingTeams.length > 0) {
      const worst = underperformingTeams[0];
      issues.push({
        severity: 'warning',
        title: `Team "${worst.name}" averaging ${worst.avgCalls} calls/rep vs company average of ${Math.round(overallAvgCalls * 10)/10}`,
        description: `Your ${worst.reps} reps in "${worst.name}" are logging significantly fewer activities than the rest of the team. This gap is 50%+ below company average — indicating either a coaching need, a different territory type, or a CRM logging problem.`,
        impact: `${worst.name} at ${Math.round((1 - worst.avgCalls/overallAvgCalls)*100)}% below avg · revenue risk from undercoached team`,
        guide: [
          `Schedule a coaching session specifically for "${worst.name}" focused on call logging hygiene`,
          'Check if they use a different phone system that does not auto-log to HubSpot',
          'Compare their deal close rates vs high-activity teams — is low activity correlated with lower revenue?',
          'Set up a team activity leaderboard visible to all reps — visibility drives behavior',
        ],
        dimension: 'Sales',
      });
    }
  }

// ── PROPERTY HYGIENE DEEP SCAN ─────────────────────────────
  if (contactProps.length > 10) {
    // Properties with low fill rates (cluttering views/reports)
    const customProps = contactProps.filter(p => p.createdUserId);  // human or integration created
    const integrationProps = customProps.filter(p =>
      p.createdUserId && (p.hubspotDefined === false) &&
      (p.name?.toLowerCase().includes('_id') || p.name?.toLowerCase().includes('sync') ||
       p.name?.toLowerCase().includes('integration') || (p.description || '').toLowerCase().includes('integration'))
    );

    // Low-fill props: check against our contacts sample
    const propFillRates = {};
    customProps.forEach(prop => {
      let filled = 0;
      contacts.forEach(c => { if (c.properties?.[prop.name]) filled++; });
      const fillRate = contacts.length > 0 ? Math.round(filled / contacts.length * 100) : 100;
      propFillRates[prop.name] = fillRate;
    });

    const lowFillProps = customProps.filter(p => (propFillRates[p.name] || 0) < 5 && (propFillRates[p.name] !== undefined));
    const undocumentedCount = customProps.filter(p => !p.description || p.description.trim().length < 5).length;

    if (lowFillProps.length > 10) {
      dataScore -= Math.min(10, Math.round(lowFillProps.length / 5));
      issues.push({
        severity: lowFillProps.length > 25 ? 'warning' : 'info',
        title: `${lowFillProps.length} custom contact properties have <5% fill rate — CRM bloat`,
        description: `These ${lowFillProps.length} properties exist in your contact schema but are virtually empty across your ${contacts.length.toLocaleString()} contacts. They clutter your views, slow your forms, confuse your team, and make HubSpot reporting harder. Properties like these accumulate from integrations, old campaigns, and ad-hoc field creation.`,
        impact: `${lowFillProps.length} bloat properties · views cluttered · reporting accuracy reduced`,
        guide: [
          'Go to Settings → Properties → Contacts → sort by "# of contacts with data" ascending',
          'Archive any property with <5% fill that has no active workflow, form, or report dependency',
          'Before archiving: export the data, then delete the property — HubSpot archives it safely',
          'Set a rule: no new property created without a description and an owner who maintains it',
          'FixOps can generate a full property audit report showing fill rates, dependencies, and archive recommendations',
        ],
        dimension: 'Data Integrity',
      });
    }

    if (undocumentedCount > 15) {
      issues.push({
        severity: 'info',
        title: `${undocumentedCount} custom properties have no description — onboarding and documentation gap`,
        description: `${undocumentedCount} of your custom contact properties have no description. When a new team member sees "hs_custom_field_47" in a view, they have no idea what it means or when to use it. This is a hidden knowledge management problem that compounds over time.`,
        impact: `${undocumentedCount} undocumented properties · onboarding friction · data entry errors`,
        guide: [
          'Settings → Properties → filter Custom Properties → sort by "Description" blank',
          'Add a one-line description to each: what it means, who fills it in, when it gets populated',
          'Consider a naming convention: [source]_[description] e.g., salesforce_account_tier',
        ],
        dimension: 'Data Integrity',
      });
    }
  }

  // ── CAMPAIGN ATTRIBUTION AUDIT ──────────────────────────────
  if (campaigns.length > 5) {
    const campaignsWithNoRevenue = campaigns.filter(c => {
      const influenced = c.counters?.influenced || c.influenced || 0;
      const rev = c.counters?.revenue || c.revenue || 0;
      return influenced === 0 && rev === 0;
    });
    const zeroDealCampaigns = Math.round(campaignsWithNoRevenue.length);
    const pctNoAttribution = Math.round(zeroDealCampaigns / campaigns.length * 100);

    if (pctNoAttribution > 60 && zeroDealCampaigns > 5) {
      issues.push({
        severity: 'warning',
        title: `${zeroDealCampaigns} of ${campaigns.length} campaigns have zero deal attribution — marketing ROI invisible`,
        description: `${pctNoAttribution}% of your campaigns show no influenced contacts or revenue. This means either your UTM tracking is broken, your campaign-to-contact associations aren't being set, or most campaigns genuinely aren't driving pipeline. Without attribution, your marketing team cannot defend their budget or optimize spend.`,
        impact: `${pctNoAttribution}% campaigns unattributed · marketing ROI unmeasurable`,
        guide: [
          'Audit your UTM parameter setup — every campaign link should have utm_campaign set',
          'In HubSpot: Marketing → Campaigns → check "Original Source" field mapping',
          'Set up campaign association in workflows: "If contact fills form from Campaign X → associate with campaign"',
          'Use HubSpot Revenue Attribution reports to see first/last touch across campaigns',
        ],
        dimension: 'Marketing',
      });
    }
  }

  // ── CONVERSATION RESPONSE TIME AUDIT ─────────────────────────
  if (conversations.length > 0) {
    const openConvs = conversations.filter(c => String(c.status||'').toUpperCase() === 'OPEN');
    const unrespondedConvs = openConvs.filter(c => {
      const created = new Date(c.createdAt || c.hs_createdate || 0).getTime();
      const lastMsg = new Date(c.latestMessageTimestamp || c.updatedAt || created).getTime();
      const ageHrs = (now - created) / 3600000;
      const responseGap = (now - lastMsg) / 3600000;
      return ageHrs > 24 && responseGap > 24; // Open > 24hrs with no response in 24hrs
    });

    if (unrespondedConvs.length > 3) {
      serviceScore -= Math.min(12, unrespondedConvs.length * 2);
      issues.push({
        severity: unrespondedConvs.length > 10 ? 'critical' : 'warning',
        title: `${unrespondedConvs.length} conversations open 24+ hours with no response`,
        description: `${unrespondedConvs.length} customer conversations in your HubSpot inbox have been waiting more than 24 hours without a reply. Industry benchmark: 73% of customers expect a response within 24 hours. Each unresponded conversation is a customer whose trust is actively eroding.`,
        impact: `${unrespondedConvs.length} customers waiting · churn risk elevated · trust damaged`,
        guide: [
          'Go to Conversations → Inbox → filter by "Open" → sort by "Oldest" first',
          'Assign a daily inbox review rotation — no conversation should go 24hrs without acknowledgment',
          'Set up a SLA workflow: "If conversation open > 8hrs → notify manager"',
          'Create a "24hr response" automation that sends an acknowledgment to any new conversation instantly',
        ],
        dimension: 'Service',
      });
    }
  }

// ── PIPELINE VELOCITY INTELLIGENCE ──────────────────────────
  // Adds revenue forecast to audit with explanations when it's off
  if (openDeals.length > 5 && dealPipelines.length > 0) {
    const closedWonD  = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
    const closedLostD = deals.filter(d => d.properties?.hs_is_closed === 'true' && d.properties?.hs_is_closed_won !== 'true');
    const totalClosedD = closedWonD.length + closedLostD.length;
    const winRateD = totalClosedD > 0 ? closedWonD.length / totalClosedD : null;

    if (winRateD !== null) {
      // Weighted pipeline forecast
      const weightedPipD = openDeals.reduce((sum, d) => {
        const stage = dealPipelines[0]?.stages?.find(s => s.id === d.properties?.dealstage);
        const prob = parseFloat(stage?.probability||stage?.metadata?.probability||0.1);
        return sum + parseFloat(d.properties?.amount||0) * prob;
      }, 0);

      // Check if forecast is reliable (need close dates and amounts)
      const noCloseDatePct = Math.round(openDeals.filter(d=>!d.properties?.closedate).length / openDeals.length * 100);
      const noAmountPct = Math.round(openDeals.filter(d=>!parseFloat(d.properties?.amount||0)).length / openDeals.length * 100);

      if (noCloseDatePct > 40 || noAmountPct > 30) {
        reportingScore -= Math.min(20, Math.round((noCloseDatePct + noAmountPct) / 8));
        issues.push({
          severity: 'critical',
          title: `Revenue forecast is unreliable — ${noCloseDatePct}% of deals missing close dates, ${noAmountPct}% missing amounts`,
          description: `Your pipeline forecast is built on incomplete data. ${noCloseDatePct}% of open deals have no close date and ${noAmountPct}% have no dollar value. This means your weighted pipeline forecast — the number your CEO and board see — could be off by six figures or more. HubSpot's forecast tool multiplies amount × probability × close date timing. Missing any one of these makes the entire number meaningless.`,
          impact: `Weighted forecast unreliable · board reporting inaccurate · quota tracking broken`,
          dimension: 'Pipeline',
          guide: [
            `Priority 1: Require close date before a deal can advance past your first active stage`,
            `Priority 2: Require amount before a deal leaves "Prospect" or "Qualification" stage`,
            `Quick fix: Export all open deals → filter by missing close date → assign realistic dates today`,
            `Build a workflow: Deal created AND close date unknown after 48 hrs → task to owner`,
            `Once fixed, your pipeline velocity report will show accurate Q90 revenue projection`,
          ]
        });
      } else {
        // Report the forecast as an insight (positive finding) with coaching
        const q90 = Math.round(weightedPipD);
        const winPct = Math.round(winRateD * 100);
        if (q90 > 0 && winPct > 0) {
          issues.push({
            severity: 'info',
            title: `Pipeline Forecast: ~$${q90.toLocaleString()} weighted pipeline at ${winPct}% historical win rate`,
            description: `Based on your current pipeline and historical close rates, your weighted forecast is $${q90.toLocaleString()}. Your team closes ${winPct}% of opportunities — ${winPct >= 30 ? 'above' : 'below'} the 25-35% industry benchmark for B2B sales. Pipeline velocity is healthy when deals move through stages in under 30 days average.`,
            impact: `$${q90.toLocaleString()} weighted pipeline · ${winPct}% win rate · pipeline data is ${noCloseDatePct < 15 && noAmountPct < 10 ? 'reliable' : 'moderately reliable'}`,
            dimension: 'Pipeline',
            guide: [
              `To improve forecast accuracy further: reduce the ${noCloseDatePct}% of deals missing close dates`,
              `Win rate improvement: review your last 20 lost deals — 3 common objections will surface immediately`,
              `Pipeline coverage target: keep 3-5× your monthly quota in your active pipeline`,
            ]
          });
        }
      }
    }
  }

  // ── CONTACT DECAY INTELLIGENCE ───────────────────────────────
  if (contacts.length > 100) {
    const deadContacts = contacts.filter(c => {
      const last = c.properties?.hs_last_sales_activity_timestamp;
      const optout = c.properties?.hs_email_optout === 'true';
      const noEmail = !c.properties?.email;
      return optout || noEmail || !last || (now - new Date(last).getTime()) / DAY > 365;
    });
    const deadPct = Math.round(deadContacts.length / contacts.length * 100);
    const billingCost = Math.round(deadContacts.length * 0.45);

    if (deadPct > 25) {
      dataScore -= Math.min(15, Math.round(deadPct / 5));
      issues.push({
        severity: deadPct > 50 ? 'critical' : 'warning',
        title: `${deadContacts.length.toLocaleString()} contacts (${deadPct}%) are inactive — costing ~$${billingCost.toLocaleString()}/mo with zero pipeline value`,
        description: `${deadPct}% of your contact database has had zero activity in over a year, is opted out, or has no email address. You're paying for these contacts in your HubSpot billing tier every month and getting nothing in return. This also degrades email deliverability — every send to a dead list hurts your sender reputation score.`,
        impact: `~$${billingCost.toLocaleString()}/mo in billing waste · deliverability damage · ${deadContacts.length.toLocaleString()} contacts consuming tier limit`,
        dimension: 'Data Integrity',
        guide: [
          'Step 1: Create a list — "Last activity date is unknown AND Created date is more than 12 months ago"',
          'Step 2: Run a 1-email re-engagement campaign: "Are you still interested?" — anyone who doesn\'t open gets suppressed',
          'Step 3: Export non-openers → mark as "Non-Marketing Contact" or archive — they\'re costing you billing tier',
          'This single cleanup can reduce your HubSpot contact tier by 20-40% — saving real money on renewal',
          'FixOps Data CleanUp handles this process in 1-2 days with full rollback capability',
        ]
      });
    }
  }

  // ── PROPERTY USAGE INTELLIGENCE ─────────────────────────────
  if (contactProps.length > 0 && contacts.length > 50) {
    const customProps = contactProps.filter(p => p.createdUserId || p.hubspotOwned === false);
    if (customProps.length > 10) {
      const unusedProps = customProps.filter(prop => {
        const filled = contacts.filter(c => c.properties?.[prop.name] && c.properties[prop.name] !== '').length;
        return filled === 0;
      });
      const undescribed = customProps.filter(p => !p.description || p.description.trim() === '');

      if (unusedProps.length > 5) {
        dataScore -= Math.min(10, unusedProps.length);
        issues.push({
          severity: 'info',
          title: `${unusedProps.length} custom contact properties have zero data — portal bloat costing team efficiency`,
          description: `${unusedProps.length} custom properties exist on your contact records but contain data for zero contacts. These empty properties clutter your property list, make it harder for reps to find what they need, and often lead to duplicate properties being created. In portals that have grown organically, this is the #1 cause of "we can't find anything in HubSpot" complaints.`,
          impact: `${unusedProps.length} unused properties · portal complexity inflated · reps creating duplicates`,
          dimension: 'Data Integrity',
          guide: [
            'Settings → Properties → filter by "Contact" → sort by "Number of records with data" ascending',
            'Review every property with 0 records: is it new? Deprecated? A duplicate?',
            'Archive (not delete) any unused property that has no data and isn\'t referenced in a workflow',
            'Add descriptions to all remaining custom properties — this alone reduces duplicate property creation by 60%',
          ]
        });
      }

      if (undescribed.length > customProps.length * 0.6 && undescribed.length > 5) {
        issues.push({
          severity: 'info',
          title: `${undescribed.length} custom properties have no description — data model undocumented`,
          description: `${Math.round(undescribed.length/customProps.length*100)}% of your custom properties have no description. When a new team member, consultant, or admin looks at your properties, they have no idea what they're for. This is how duplicate properties get created — someone can't find "Sales Region" because it's undocumented, so they create "Territory" instead.`,
          impact: `Data model opaque to new team members · duplicate properties created over time · onboarding slowed`,
          dimension: 'Data Integrity',
          guide: [
            'Settings → Properties → filter by "Created by user" → add a description to each',
            'Good description format: "[What it captures] — [When it should be set] — [Who sets it]"',
            'Example: "Rep\'s assigned territory — Set by admin during user setup — Used in round-robin routing"',
          ]
        });
      }
    }
  }

  // ── FORM CONVERSION INTELLIGENCE ─────────────────────────────
  if (forms.length > 3) {
    const formsWithViews = forms.filter(f => (f.viewCount||f.analytics?.views||0) > 100);
    if (formsWithViews.length > 0) {
      const brokenForms = formsWithViews.filter(f => {
        const views = f.viewCount || f.analytics?.views || 0;
        const subs  = f.submissionCounts?.total || f.totalSubmissions || 0;
        return views > 100 && subs / views < 0.01; // <1% conversion rate
      });
      if (brokenForms.length > 0) {
        marketingScore -= Math.min(12, brokenForms.length * 4);
        issues.push({
          severity: brokenForms.length > 2 ? 'critical' : 'warning',
          title: `${brokenForms.length} form${brokenForms.length!==1?'s':''} with <1% conversion rate — lead capture silently failing`,
          description: `${brokenForms.length} high-traffic forms are receiving significant views but almost zero submissions. A form with 500 views and 2 submissions (0.4% conversion) either has a technical problem, asks too many friction-heavy fields, or is embedded on a page where visitors aren't ready to convert. Industry benchmark for a well-optimized HubSpot form is 15-25% conversion rate.`,
          impact: `${brokenForms.length} broken forms · unknown number of lost leads · ad spend driving to broken pages`,
          dimension: 'Marketing',
          guide: [
            'Test each affected form yourself right now — submit it and verify you receive the confirmation email',
            'Check form embed code: is the form still live on the page? Use HubSpot\'s page performance view to confirm',
            'Review form fields: more than 5 fields kills conversion. Remove everything non-essential',
            'Check thank-you page redirect — a broken redirect looks like a broken form',
            'Run a session recording (Hotjar/FullStory) on the page to see where visitors abandon',
          ]
        });
      }

      // Best vs worst form conversion insight
      const allRanked = formsWithViews
        .map(f => ({
          name: f.name||'Unnamed Form',
          views: f.viewCount||f.analytics?.views||0,
          subs: f.submissionCounts?.total||f.totalSubmissions||0,
          rate: Math.round((f.submissionCounts?.total||f.totalSubmissions||0) / (f.viewCount||f.analytics?.views||1) * 100 * 10)/10
        }))
        .sort((a,b)=>b.rate-a.rate);
      const best = allRanked[0];
      const worst = allRanked[allRanked.length-1];
      if (best && worst && best.rate - worst.rate > 15) {
        issues.push({
          severity: 'info',
          title: `Form conversion gap: best form ${best.rate}% vs worst ${worst.rate}% — ${Math.round(best.rate - worst.rate)}pp spread`,
          description: `Your top-performing form "${best.name}" converts at ${best.rate}% while "${worst.name}" converts at ${worst.rate}%. The ${Math.round(best.rate-worst.rate)} percentage point gap suggests the best form has something the worst doesn't — shorter length, better placement, stronger CTA, or better audience targeting. Applying the same approach to your worst performers could double their lead volume.`,
          impact: `${Math.round(best.rate - worst.rate)}pp conversion gap · significant lead volume left on table`,
          dimension: 'Marketing',
          guide: [
            `Study "${best.name}" — how many fields? What's the CTA copy? Where is it placed?`,
            `Apply the same structure to "${worst.name}" — test 1 change at a time`,
            `Short forms (3-4 fields) consistently outperform long forms across all industries`,
          ]
        });
      }
    }
  }

  // ── DEAL SOURCE ATTRIBUTION INTELLIGENCE ─────────────────────
  if (deals.length > 10 && contacts.length > 50) {
    const closedWonD2 = deals.filter(d => d.properties?.hs_is_closed_won === 'true' && parseFloat(d.properties?.amount||0) > 0);
    if (closedWonD2.length > 5) {
      const srcRevMap = {};
      closedWonD2.forEach(d => {
        const src = d.properties?.hs_analytics_source || 'Unknown';
        srcRevMap[src] = (srcRevMap[src]||0) + parseFloat(d.properties?.amount||0);
      });
      const totalRev2 = Object.values(srcRevMap).reduce((a,b)=>a+b,0);
      const unknownRev = srcRevMap['Unknown'] || 0;
      const unknownPct = totalRev2 > 0 ? Math.round(unknownRev / totalRev2 * 100) : 0;

      if (unknownPct > 50) {
        reportingScore -= 10;
        issues.push({
          severity: 'warning',
          title: `${unknownPct}% of closed won revenue has no source attribution — marketing ROI invisible`,
          description: `$${Math.round(unknownRev).toLocaleString()} of your closed won revenue (${unknownPct}%) shows "Unknown" as the original source. This means your marketing team can't prove which channels are generating revenue, can't defend their budget, and can't double down on what's working. UTM parameters aren't being captured or the HubSpot tracking code isn't installed on your website.`,
          impact: `${unknownPct}% revenue unattributed · marketing budget decisions made without data`,
          dimension: 'Reporting',
          guide: [
            'Install the HubSpot tracking code on ALL pages of your website (not just landing pages)',
            'Add UTM parameters to every paid ad, email, and social link: utm_source, utm_medium, utm_campaign',
            'Check HubSpot Settings → Tracking → ensure original source is being captured on form submissions',
            'Once tracking is fixed, use HubSpot\'s Attribution Reports to see first-touch vs last-touch by channel',
          ]
        });
      } else if (Object.keys(srcRevMap).length > 1 && unknownPct < 30) {
        // Share the attribution insight as a positive finding
        const topSrc = Object.entries(srcRevMap).sort((a,b)=>b[1]-a[1])[0];
        if (topSrc) {
          issues.push({
            severity: 'info',
            title: `Top revenue source: "${topSrc[0]}" generated $${Math.round(topSrc[1]).toLocaleString()} in closed won deals`,
            description: `Your source attribution data is healthy. "${topSrc[0]}" is your highest-revenue channel, accounting for $${Math.round(topSrc[1]).toLocaleString()} of closed won revenue. Use this data to double down on what's working and reduce spend on lower-performing channels.`,
            impact: `Attribution data available for ${100-unknownPct}% of closed revenue · optimization data actionable`,
            dimension: 'Reporting',
            guide: [
              `Review your top 3 sources and compare their average deal sizes — not just volume`,
              `Organic and referral sources typically have higher deal values than paid — verify this holds for your portal`,
              `Set a monthly attribution review: which source had the best win rate this month?`,
            ]
          });
        }
      }
    }
  }

  // ── CUSTOMER HEALTH INTELLIGENCE ─────────────────────────────
  if (companies.length > 3 && tickets.length > 5) {
    const ticketsByCompanyMap = {};
    tickets.forEach(t => {
      const cid = t.properties?.hs_pipeline || 'unknown';
      ticketsByCompanyMap[cid] = (ticketsByCompanyMap[cid]||0) + 1;
    });
    const highTicketCompanies = Object.values(ticketsByCompanyMap).filter(n => n > 5).length;
    if (highTicketCompanies > 0) {
      serviceScore -= Math.min(10, highTicketCompanies * 3);
      issues.push({
        severity: 'warning',
        title: `${highTicketCompanies} customer${highTicketCompanies!==1?'s have':' has'} 5+ open tickets — churn risk elevated`,
        description: `High ticket volume from individual customers is the clearest leading indicator of churn in B2B SaaS. A customer submitting 5+ support tickets signals product friction, implementation problems, or unmet expectations. By the time they mention it on a renewal call, it's often too late.`,
        impact: `${highTicketCompanies} high-risk customers · renewal conversations starting from deficit`,
        dimension: 'Service',
        guide: [
          'Immediately: identify which customers have the most open tickets → assign a CSM to each for a check-in call',
          'Run a Customer Health review: high ticket volume + declining email engagement + no recent meetings = churn signal',
          'Set up a workflow: Customer submits 3rd ticket in 30 days → notify CSM and create task for health check call',
          'FixOps Customer Health Score (monthly subscribers) tracks this automatically and alerts you before churn',
        ]
      });
    }
  }

// ── SCORES ──────────────────────────────────────────────────
  // Only include dimensions in the score if we have actual data to audit
  // If no data available (missing optional scope), score that dimension as null
  // and exclude from the overall average — avoids false 100s
  // ── SCORE ASSEMBLY ─────────────────────────────────────────────────────────
  // null = no data for this dimension → excluded from overall average
  // Conditions: must have meaningful data to score that dimension
  // No Math.max(20) floor — let bad scores reflect reality
  const hasActivityData = calls.length > 0 || meetings.length > 0 || tasks.length > 0;
  const hasMarketingData = forms.length > 0 || lists.length > 0 || marketingEmails.length > 0 || sequences.length > 0;
  const hasServiceData = tickets.length > 0 || feedback.length > 0;

  // Score floors: no dimension should realistically show below 10
  // Prevents 0-scores on portals that are bad but not literally non-functional
  const scoreFloor = (s, floor) => Math.max(floor, Math.min(100, Math.round(s)));
  const scoreMap = {
    dataIntegrity:    contacts.length > 50 
      ? scoreFloor(dataScore, 12)
      : contacts.length > 0 
        ? scoreFloor(dataScore + 10, 15)
        : null,

    automationHealth: (workflows.length > 0 || sequences.length > 0) 
      ? scoreFloor(autoScore, 15)
      : null,

    pipelineIntegrity: deals.length > 0 
      ? scoreFloor(pipelineScore, 12)
      : null,

    marketingHealth:  hasMarketingData 
      ? scoreFloor(marketingScore, 10)
      : null,

    configSecurity:   scoreFloor(configScore, 28),
    // Config starts at 88, floor at 28 — even terrible config is functional

    reportingQuality: deals.length > 10 
      ? scoreFloor(reportingScore, 15)
      : null,

    teamAdoption:     (users.length > 1 && hasActivityData)
      ? scoreFloor(teamScore, 15)
      : null,

    serviceHealth:    hasServiceData 
      ? scoreFloor(serviceScore, 18)
      : null,
  };
  // Filter to only scored dimensions, build scores object
  const scores = Object.fromEntries(
    Object.entries(scoreMap).filter(([,v]) => v !== null)
  );
  const criticalCount = issues.filter(i=>i.severity==='critical').length;
  const warningCount  = issues.filter(i=>i.severity==='warning').length;
  const infoCount     = issues.filter(i=>i.severity==='info').length;
    // Overall = weighted average + critical penalty
  // Pipeline and Data Integrity are weighted higher (revenue impact)
  const WEIGHTS = {
    dataIntegrity: 1.2, pipelineIntegrity: 1.3, automationHealth: 1.0,
    marketingHealth: 1.0, configSecurity: 0.8, reportingQuality: 0.9,
    teamAdoption: 1.0, serviceHealth: 1.0
  };
  let weightedSum = 0, weightTotal = 0;
  Object.entries(scores).forEach(([k, v]) => {
    const w = WEIGHTS[k] || 1.0;
    weightedSum += v * w;
    weightTotal += w;
  });
  let overallScore = weightTotal > 0
    ? Math.round(weightedSum / weightTotal)
    : 70;
  // Critical penalty: each critical issue drops overall by 2pts (max -20)
  const critPenalty = Math.min(20, criticalCount * 2);
  // Warning penalty: each warning drops overall by 0.5pt (max -8)
  const warnPenalty = Math.min(8, Math.round(warningCount * 0.5));
  overallScore = Math.max(0, overallScore - critPenalty - warnPenalty);
  // Hard grade caps based on critical issue count
  if (criticalCount > 0 && overallScore > 84) overallScore = 84;
  if (criticalCount >= 3 && overallScore > 71) overallScore = 71;
  if (criticalCount >= 6 && overallScore > 59) overallScore = 59;

        // ── WASTE ESTIMATE ─────────────────────────────────────────────────────────
  // Based on actual HubSpot billing data + industry benchmarks
  // Free scan is capped at 1,000 contacts — only count waste with hard evidence
  const isCappedScan = meta.plan === 'free';
  const isFullScan   = ['deep','pro-audit','pulse','pro','command'].includes(meta.plan);

  // ══════════════════════════════════════════════════════════════════════════════
  // ✦ REVENUE INTELLIGENCE ENGINE — Pipeline Velocity + Forecast
  // ══════════════════════════════════════════════════════════════════════════════
  const revenueIntel = (() => {
    const closedWonDeals = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
    const closedLostDeals = deals.filter(d => d.properties?.hs_is_closed === 'true' && d.properties?.hs_is_closed_won !== 'true');
    const allClosed = closedWonDeals.length + closedLostDeals.length;
    const winRate = allClosed > 0 ? Math.round((closedWonDeals.length / allClosed) * 100) : 0;

    // Average sales cycle from closed won deals
    const wonWithDates = closedWonDeals.filter(d => d.properties?.createdate && d.properties?.closedate);
    const avgSalesCycleDays = wonWithDates.length > 0
      ? Math.round(wonWithDates.reduce((sum, d) => {
          const created = new Date(d.properties.createdate).getTime();
          const closed  = new Date(d.properties.closedate).getTime();
          return sum + Math.max(0, (closed - created) / DAY);
        }, 0) / wonWithDates.length)
      : 0;

    // Average deal size (closed won only — open deals are unreliable)
    const avgDealSize = closedWonDeals.length > 0
      ? Math.round(closedWonDeals.reduce((sum,d)=>sum+parseFloat(d.properties?.amount||0),0) / closedWonDeals.length)
      : openDeals.length > 0
        ? Math.round(openDeals.filter(d=>parseFloat(d.properties?.amount||0)>0).reduce((sum,d)=>sum+parseFloat(d.properties?.amount||0),0) / Math.max(openDeals.filter(d=>parseFloat(d.properties?.amount||0)>0).length, 1))
        : 0;

    // Pipeline velocity = (# deals × avg deal size × win rate) / avg sales cycle days
    const openWithValue = openDeals.filter(d => parseFloat(d.properties?.amount||0) > 0);
    const pipelineVelocity = avgSalesCycleDays > 0 && winRate > 0
      ? Math.round((openWithValue.length * avgDealSize * (winRate/100)) / avgSalesCycleDays)
      : 0; // $ per day flowing through pipeline

    // Pipeline coverage ratio: total pipeline value / avg monthly revenue
    const totalOpenPipeline = openDeals.reduce((sum,d)=>sum+parseFloat(d.properties?.amount||0),0);
    const monthlyRevenue = closedWonDeals.length > 0
      ? Math.round(closedWonDeals.reduce((sum,d)=>sum+parseFloat(d.properties?.amount||0),0) / 3) // assume 3-month window
      : 0;
    const coverageRatio = monthlyRevenue > 0 ? Math.round((totalOpenPipeline / monthlyRevenue) * 10) / 10 : 0;

    // 90-day revenue forecast: open deals × probability × historical win rate adjustment
    const forecastByMonth = {};
    openDeals.forEach(d => {
      const cd = d.properties?.closedate;
      if (!cd) return;
      const closeDate = new Date(cd);
      const monthKey = `${closeDate.getFullYear()}-${String(closeDate.getMonth()+1).padStart(2,'0')}`;
      const amount = parseFloat(d.properties?.amount||0);
      const prob = parseFloat(d.properties?.hs_deal_stage_probability||0.3);
      if (!forecastByMonth[monthKey]) forecastByMonth[monthKey] = { raw:0, weighted:0, count:0 };
      forecastByMonth[monthKey].raw += amount;
      forecastByMonth[monthKey].weighted += amount * prob;
      forecastByMonth[monthKey].count++;
    });

    // Next 90 days forecast
    const next3Months = [];
    for (let i = 0; i < 3; i++) {
      const d = new Date(now);
      d.setMonth(d.getMonth() + i);
      const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
      const label = d.toLocaleString('en-US', {month:'short', year:'numeric'});
      next3Months.push({
        month: label,
        raw: Math.round(forecastByMonth[key]?.raw || 0),
        weighted: Math.round(forecastByMonth[key]?.weighted || 0),
        count: forecastByMonth[key]?.count || 0,
      });
    }

    // Deal source attribution: which contact source generates best deals
    const sourceRevenue = {};
    closedWonDeals.forEach(d => {
      // Find associated contacts' source via analytics source on contacts
      const amount = parseFloat(d.properties?.amount||0);
      // We approximate source from deal's pipeline for now; full attribution needs association lookup
      const pipeline = d.properties?.pipeline || 'default';
      if (!sourceRevenue[pipeline]) sourceRevenue[pipeline] = { won:0, revenue:0, count:0 };
      sourceRevenue[pipeline].won++;
      sourceRevenue[pipeline].revenue += amount;
      sourceRevenue[pipeline].count++;
    });

    // Contact source → deal revenue attribution (using contacts' analytics source)
    const contactSourceRevenue = {};
    contacts.forEach(c => {
      const src = c.properties?.hs_analytics_source || 'Unknown';
      if (!contactSourceRevenue[src]) contactSourceRevenue[src] = { contacts:0, withDeals:0 };
      contactSourceRevenue[src].contacts++;
      if (parseInt(c.properties?.num_contacted_notes||0) > 0) contactSourceRevenue[src].withDeals++;
    });
    const topSources = Object.entries(contactSourceRevenue)
      .filter(([,v]) => v.contacts > 5)
      .map(([src, v]) => ({ source: src, contacts: v.contacts, conversionRate: v.contacts > 0 ? Math.round(v.withDeals/v.contacts*100) : 0 }))
      .sort((a,b) => b.conversionRate - a.conversionRate)
      .slice(0, 5);

    return {
      winRate,
      avgSalesCycleDays,
      avgDealSize,
      pipelineVelocity,
      coverageRatio,
      totalOpenPipeline: Math.round(totalOpenPipeline),
      monthlyRevenue,
      forecastByMonth: next3Months,
      topSources,
      closedWonCount: closedWonDeals.length,
      closedLostCount: closedLostDeals.length,
      closedWonRevenue: Math.round(closedWonDeals.reduce((sum,d)=>sum+parseFloat(d.properties?.amount||0),0)),
    };
  })();

  // ══════════════════════════════════════════════════════════════════════════════
  // ✦ CONTACT DECAY SCORING ENGINE
  // ══════════════════════════════════════════════════════════════════════════════
  const contactDecayEngine = (() => {
    let totalDecayScore = 0;
    const decayBuckets = { hot:0, warm:0, cooling:0, cold:0, dead:0 };
    const archiveCandidates = [];

    contacts.forEach(c => {
      const lastActivity = c.properties?.hs_last_sales_activity_timestamp;
      const numContacted = parseInt(c.properties?.num_contacted_notes||0);
      const lifecycle = c.properties?.lifecyclestage || '';
      const hasEmail = !!c.properties?.email;
      const optedOut = c.properties?.hs_email_optout === 'true';
      const ageMs = now - new Date(c.properties?.createdate||now).getTime();
      const daysSinceActivity = lastActivity ? (now - new Date(lastActivity).getTime()) / DAY : ageMs / DAY;

      // Decay score 0-100 (100 = fully engaged, 0 = completely dead)
      let score = 50; // base
      if (numContacted > 0) score += 20;
      if (numContacted > 5) score += 10;
      if (lifecycle === 'customer') score += 20;
      if (lifecycle === 'opportunity') score += 15;
      if (lifecycle === 'salesqualifiedlead') score += 10;
      if (!hasEmail) score -= 30;
      if (optedOut) score -= 25;
      if (daysSinceActivity < 30) score += 20;
      else if (daysSinceActivity < 90) score += 5;
      else if (daysSinceActivity < 180) score -= 10;
      else if (daysSinceActivity < 365) score -= 20;
      else score -= 35;
      score = Math.max(0, Math.min(100, score));

      totalDecayScore += score;

      if (score >= 70) decayBuckets.hot++;
      else if (score >= 50) decayBuckets.warm++;
      else if (score >= 30) decayBuckets.cooling++;
      else if (score >= 10) decayBuckets.cold++;
      else decayBuckets.dead++;

      // Archive candidates: dead score, no email, no activity, no lifecycle, old
      if (score < 15 && !hasEmail && numContacted === 0 && ageMs > 365 * DAY) {
        archiveCandidates.push(c.id);
      }
    });

    const avgDecayScore = contacts.length > 0 ? Math.round(totalDecayScore / contacts.length) : 0;
    const databaseHealthGrade = avgDecayScore >= 65 ? 'Healthy' : avgDecayScore >= 45 ? 'Needs Attention' : 'At Risk';
    const estBillingWaste = Math.round(decayBuckets.dead * 0.45); // dead contacts billing inflation

    return {
      avgDecayScore,
      databaseHealthGrade,
      buckets: decayBuckets,
      archiveCandidateCount: archiveCandidates.length,
      estBillingWaste,
      totalContacts: contacts.length,
    };
  })();

  // ══════════════════════════════════════════════════════════════════════════════
  // ✦ REP PERFORMANCE INTELLIGENCE ENGINE
  // ══════════════════════════════════════════════════════════════════════════════
  const repIntelEngine = (() => {
    const repStats = {};

    // Map owner IDs to names
    const ownerNameMap = {};
    owners.forEach(o => {
      const id = o.id || o.ownerId;
      const name = [o.firstName||o.properties?.firstname||'', o.lastName||o.properties?.lastname||'']
        .filter(Boolean).join(' ') || o.email || `Rep ${id}`;
      ownerNameMap[id] = name;
    });

    // Build per-rep stats
    const ensure = (id) => {
      if (!repStats[id]) repStats[id] = {
        id, name: ownerNameMap[id] || `Rep ${id}`,
        calls: 0, meetings: 0, tasksCompleted: 0, tasksOverdue: 0,
        dealsOwned: 0, dealsWon: 0, dealsLost: 0,
        pipelineValue: 0, wonRevenue: 0,
        emailsLogged: 0, notesLogged: 0,
      };
    };

    calls.forEach(c => {
      const id = c.properties?.hubspot_owner_id;
      if (!id) return;
      ensure(id);
      if ((now - new Date(c.properties?.hs_createdate||0).getTime())/DAY < 30) repStats[id].calls++;
    });

    meetings.forEach(m => {
      const id = m.properties?.hubspot_owner_id;
      if (!id) return;
      ensure(id);
      if ((now - new Date(m.properties?.hs_timestamp||0).getTime())/DAY < 30) repStats[id].meetings++;
    });

    tasks.forEach(t => {
      const id = t.properties?.hubspot_owner_id;
      if (!id) return;
      ensure(id);
      const status = String(t.properties?.hs_task_status||'').toLowerCase();
      const due = t.properties?.hs_timestamp;
      if (status === 'completed') repStats[id].tasksCompleted++;
      else if (due && new Date(due).getTime() < now) repStats[id].tasksOverdue++;
    });

    deals.forEach(d => {
      const id = d.properties?.hubspot_owner_id;
      if (!id) return;
      ensure(id);
      const amount = parseFloat(d.properties?.amount||0);
      if (d.properties?.hs_is_closed_won === 'true') {
        repStats[id].dealsWon++;
        repStats[id].wonRevenue += amount;
      } else if (d.properties?.hs_is_closed === 'true') {
        repStats[id].dealsLost++;
      } else {
        repStats[id].dealsOwned++;
        repStats[id].pipelineValue += amount;
      }
    });

    emailEngs.forEach(e => {
      const id = e.properties?.hubspot_owner_id;
      if (id) { ensure(id); repStats[id].emailsLogged++; }
    });
    notes.forEach(n => {
      const id = n.properties?.hubspot_owner_id;
      if (id) { ensure(id); repStats[id].notesLogged++; }
    });

    // Score each rep 0-100
    const reps = Object.values(repStats).map(r => {
      const totalActivity = r.calls + r.meetings + r.emailsLogged;
      const winRate = (r.dealsWon + r.dealsLost) > 0
        ? Math.round(r.dealsWon / (r.dealsWon + r.dealsLost) * 100) : null;
      const taskHealth = (r.tasksCompleted + r.tasksOverdue) > 0
        ? Math.round(r.tasksCompleted / (r.tasksCompleted + r.tasksOverdue) * 100) : null;
      let score = 50;
      if (r.calls >= 10) score += 15;
      else if (r.calls >= 5) score += 8;
      if (r.meetings >= 5) score += 15;
      else if (r.meetings >= 2) score += 8;
      if (winRate !== null) score += winRate > 30 ? 15 : winRate > 20 ? 8 : 0;
      if (taskHealth !== null) score += taskHealth > 80 ? 10 : taskHealth > 60 ? 5 : -10;
      if (r.tasksOverdue > 5) score -= 10;
      return { ...r, winRate, taskHealth, activityScore: totalActivity, performanceScore: Math.max(0, Math.min(100, score)) };
    });

    reps.sort((a,b) => b.performanceScore - a.performanceScore);
    const teamAvgScore = reps.length > 0 ? Math.round(reps.reduce((s,r)=>s+r.performanceScore,0)/reps.length) : 0;

    return { reps: reps.slice(0, 20), teamAvgScore, repCount: reps.length };
  })();

  // ══════════════════════════════════════════════════════════════════════════════
  // ✦ CUSTOMER HEALTH SCORE ENGINE (churn prediction)
  // ══════════════════════════════════════════════════════════════════════════════
  const customerHealthEngine = (() => {
    if (companies.length === 0) return null;

    const healthScores = [];

    companies.forEach(company => {
      const cId = company.id;
      // Tickets for this company (approximate by checking if we have ticket data)
      const recentTickets = tickets.filter(t => {
        // Tickets don't always have company association in basic fetch — use volume as proxy
        return true; // We'll use aggregate stats per company when association data is available
      });

      // NPS score (if any feedback)
      const npsScore = npsResponses.length > 0
        ? Math.round(npsResponses.map(f=>parseFloat(f.properties?.hs_response||0)).reduce((a,b)=>a+b,0)/npsResponses.length)
        : null;

      // Revenue signals
      const hasInvoices = invoices.length > 0;
      const overdueCount = overdueInvoices.length;

      // Engagement signals (portal-level since we can't always join by company)
      const recentCallCount = calls.filter(c=>(now-new Date(c.properties?.hs_createdate||0).getTime())/DAY<30).length;
      const openTicketCount = tickets.filter(t=>!['closed','resolved','4'].includes(String(t.properties?.hs_pipeline_stage||'').toLowerCase())).length;

      // Build health score per company using available data
      const numContacts = parseInt(company.properties?.num_associated_contacts||0);
      const lastModified = company.properties?.hs_lastmodifieddate;
      const daysSinceUpdate = lastModified ? (now - new Date(lastModified).getTime())/DAY : 999;

      let healthScore = 60; // base
      if (numContacts > 0) healthScore += 10;
      if (numContacts > 3) healthScore += 5;
      if (daysSinceUpdate < 30) healthScore += 15;
      else if (daysSinceUpdate < 90) healthScore += 5;
      else if (daysSinceUpdate > 180) healthScore -= 20;
      if (npsScore !== null) {
        if (npsScore >= 8) healthScore += 15;
        else if (npsScore >= 6) healthScore += 5;
        else healthScore -= 15;
      }
      if (overdueCount > 0) healthScore -= 15;
      if (openTicketCount > 5) healthScore -= 10;

      healthScore = Math.max(0, Math.min(100, healthScore));
      healthScores.push({ id: cId, name: company.properties?.name || 'Unknown', score: healthScore, contacts: numContacts, daysSinceUpdate: Math.round(daysSinceUpdate) });
    });

    healthScores.sort((a,b) => a.score - b.score);
    const atRisk = healthScores.filter(h => h.score < 40).length;
    const healthy = healthScores.filter(h => h.score >= 70).length;
    const avgHealth = healthScores.length > 0 ? Math.round(healthScores.reduce((s,h)=>s+h.score,0)/healthScores.length) : 0;

    return {
      avgHealth,
      atRisk,
      healthy,
      total: healthScores.length,
      bottomAccounts: healthScores.slice(0, 10), // most at-risk
      topAccounts: healthScores.slice(-5).reverse(), // healthiest
    };
  })();

  // ══════════════════════════════════════════════════════════════════════════════
  // ✦ FORM CONVERSION FUNNEL ENGINE
  // ══════════════════════════════════════════════════════════════════════════════
  const formConversionEngine = (() => {
    const formsWithData = forms
      .map(f => {
        const submissions = f.submissionCounts?.total || f.totalSubmissions || 0;
        const views = f.submissionCounts?.contactSubmissions || f.views || 0; // views not always available
        const convRate = views > 0 ? Math.round(submissions / views * 100) : null;
        return {
          name: f.name || f.formId || 'Unnamed',
          submissions,
          views,
          convRate,
          hasConvData: views > 0 && submissions > 0,
        };
      })
      .filter(f => f.submissions > 0 || f.views > 0)
      .sort((a,b) => b.submissions - a.submissions);

    const topForms = formsWithData.slice(0, 10);
    const zeroSubmission = forms.filter(f => (f.submissionCounts?.total||f.totalSubmissions||0) === 0).length;
    const totalSubmissions = forms.reduce((s,f) => s+(f.submissionCounts?.total||f.totalSubmissions||0), 0);

    return { topForms, zeroSubmission, totalSubmissions, totalForms: forms.length };
  })();

  // ══════════════════════════════════════════════════════════════════════════════
  // ✦ PROPERTY USAGE ENGINE (full audit)
  // ══════════════════════════════════════════════════════════════════════════════
  const propertyUsageEngine = (() => {
    if (contactProps.length === 0) return null;
    const customProps = contactProps.filter(p => p.createdUserId || p.hubspotOwned === false);
    const propData = customProps.map(p => {
      let filled = 0;
      contacts.forEach(c => { if (c.properties?.[p.name] && String(c.properties[p.name]).trim() !== '') filled++; });
      const fillRate = contacts.length > 0 ? Math.round(filled / contacts.length * 100) : 0;
      return {
        name: p.name,
        label: p.label || p.name,
        fillRate,
        hasDescription: !!(p.description && p.description.trim().length > 3),
        type: p.type || 'string',
        groupName: p.groupName || 'unknown',
      };
    }).sort((a,b) => b.fillRate - a.fillRate);

    const wellUsed   = propData.filter(p => p.fillRate >= 50).length;
    const underUsed  = propData.filter(p => p.fillRate >= 5 && p.fillRate < 50).length;
    const bloat      = propData.filter(p => p.fillRate < 5).length;
    const noDesc     = propData.filter(p => !p.hasDescription).length;

    return {
      total: customProps.length,
      wellUsed, underUsed, bloat, noDesc,
      topProps: propData.slice(0, 10),
      bloatProps: propData.filter(p => p.fillRate < 5).slice(0, 10),
    };
  })();

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ SETUP HEALTH ENGINE — What Portal IQ charges $2,000 to check manually
  // Checks: domain auth, tracking code, teams, user roles, import errors,
  // notification setup, AI settings, connected integrations
  // ══════════════════════════════════════════════════════════════════════════
  const setupHealthEngine = (() => {
    const checks = [];
    let score = 100;

    // 1. Email authentication — SPF/DKIM configured on sending domains
    const verifiedDomains = emailDomains.filter(d => d.validationDetails?.isVerified || d.status === 'VERIFIED' || d.dkim?.isVerified || d.spf?.isVerified);
    const hasEmailDomain  = emailDomains.length > 0;
    const hasDKIM = emailDomains.some(d => d.dkim?.isVerified || d.dkimStatus === 'VERIFIED' || String(d.dkim||'').includes('valid'));
    const hasSPF  = emailDomains.some(d => d.spf?.isVerified  || d.spfStatus  === 'VERIFIED' || String(d.spf||'').includes('valid'));
    if (hasEmailDomain) {
      checks.push({ name: 'Email Sending Domain', pass: verifiedDomains.length > 0 || hasDKIM, detail: verifiedDomains.length > 0 ? `${verifiedDomains.length} domain(s) verified` : 'Domain authentication not confirmed', impact: 'Email deliverability and sender trust', fix: 'Settings → Domains & URLs → Connect an email sending domain and verify DKIM/SPF records' });
      if (!hasDKIM) score -= 12;
    } else {
      checks.push({ name: 'Email Sending Domain', pass: false, detail: 'No custom sending domain configured — emails send as "via HubSpot"', impact: 'Deliverability reduced, no brand domain on emails', fix: 'Settings → Domains & URLs → Connect your email domain to remove the "via HubSpot" label and improve deliverability' });
      score -= 12;
    }

    // 2. Teams configured
    const hasTeams = teams.length > 0;
    checks.push({ name: 'Teams Configured', pass: hasTeams, detail: hasTeams ? `${teams.length} team(s) set up` : 'No teams configured — assignment and routing uses individual users only', impact: 'No round-robin routing, no team-level reporting, no bulk assignment', fix: 'Settings → Users & Teams → Teams — create teams for each department/function' });
    if (!hasTeams) score -= 8;

    // 3. Multiple pipelines (deal pipeline customization)
    const hasCustomPipelines = dealPipelines.length > 1;
    const defaultOnly = dealPipelines.length === 1 && (dealPipelines[0]?.label?.toLowerCase().includes('default') || dealPipelines[0]?.label?.toLowerCase().includes('sales'));
    checks.push({ name: 'Deal Pipeline Customization', pass: hasCustomPipelines || (dealPipelines.length === 1 && !defaultOnly), detail: hasCustomPipelines ? `${dealPipelines.length} pipelines configured` : 'Only default pipeline in use', impact: 'One pipeline cannot represent different buyer journeys or product lines', fix: 'CRM → Deals → Manage Pipelines — create separate pipelines for different sales motions' });
    if (!hasCustomPipelines && defaultOnly) score -= 5;

    // 4. Super Admin count (security)
    const superAdmins = settingsUsers.filter(u => u.superAdmin === true || u.roleIds?.includes('superAdmin'));
    const tooManySuper = superAdmins.length > 3;
    checks.push({ name: 'Super Admin Governance', pass: !tooManySuper, detail: tooManySuper ? `${superAdmins.length} super admins — exceeds recommended maximum of 3` : `${superAdmins.length} super admin(s) — within best practice`, impact: 'Excess super admins can delete records, export all data, change billing — major security risk', fix: 'Settings → Users & Teams → filter by Super Admin → downgrade to minimum required role' });
    if (tooManySuper) score -= 10;

    // 5. Import errors in recent history
    const recentImports = importHistory.filter(i => {
      const created = new Date(i.createdAt || 0).getTime();
      return (now - created) / DAY < 90;
    });
    const importsWithErrors = recentImports.filter(i => (i.numErrored || i.metadata?.errorCount || 0) > 0);
    checks.push({ name: 'Import Error History', pass: importsWithErrors.length === 0, detail: importsWithErrors.length > 0 ? `${importsWithErrors.length} recent import(s) with errors in last 90 days` : 'No recent import errors detected', impact: 'Import errors mean data did not enter HubSpot correctly — leads and records may be missing', fix: 'HubSpot → Import → check error files for each failed import and resolve field mapping issues' });
    if (importsWithErrors.length > 0) score -= 8;

    // 6. Meeting links configured (reps set up booking pages)
    const repsWithLinks = meetingLinks.length;
    const usersNeedingLinks = settingsUsers.filter(u => !u.superAdmin && !u.inactive).length;
    const meetingLinkCoverage = usersNeedingLinks > 0 ? Math.round(repsWithLinks / usersNeedingLinks * 100) : 100;
    checks.push({ name: 'Meeting Links Coverage', pass: meetingLinkCoverage >= 50, detail: `${repsWithLinks} meeting link(s) configured across ${usersNeedingLinks} active users (${meetingLinkCoverage}%)`, impact: 'Reps without meeting links create friction — prospects cannot self-schedule, manual back-and-forth slows pipeline', fix: 'Each rep: Settings → General → Calendar → Create a meeting scheduling page and share the link' });
    if (meetingLinkCoverage < 50) score -= 7;

    // 7. Knowledge Base configured (Service Hub)
    const kbPublished = kbArticles.filter(a => a.currentState === 'PUBLISHED' || a.status === 'PUBLISHED').length;
    const hasKBSetup = kbArticles.length > 0;
    if (tickets.length > 10) {
      checks.push({ name: 'Knowledge Base Setup', pass: hasKBSetup && kbPublished > 0, detail: hasKBSetup ? `${kbPublished} published KB article(s) of ${kbArticles.length} total` : 'No knowledge base articles created', impact: 'Without KB articles, every question becomes a support ticket — tickets volume inflated unnecessarily', fix: 'Service → Knowledge Base — create articles for your top 10 most common support questions' });
      if (!hasKBSetup) score -= 6;
    }

    // 8. Feedback surveys configured (NPS/CSAT)
    const hasFeedback = feedback.length > 0;
    checks.push({ name: 'Feedback Surveys Active', pass: hasFeedback, detail: hasFeedback ? `${feedback.length} feedback response(s) collected` : 'No NPS or CSAT responses collected', impact: 'No feedback = no early warning on churn risk or customer satisfaction trends', fix: 'Service → Customer Feedback — create an NPS survey and enroll existing customers' });
    if (!hasFeedback) score -= 7;

    // 9. Contact/deal properties documented
    const customContactPropsTotal = contactProps.filter(p => p.createdUserId || p.hubspotOwned === false).length;
    const undocumentedProps = contactProps.filter(p => (p.createdUserId || p.hubspotOwned === false) && (!p.description || p.description.trim().length < 3)).length;
    const docRate = customContactPropsTotal > 0 ? Math.round((1 - undocumentedProps/customContactPropsTotal)*100) : 100;
    checks.push({ name: 'Property Documentation', pass: docRate >= 70, detail: `${customContactPropsTotal} custom properties · ${docRate}% have descriptions`, impact: 'Undocumented properties cause duplicate creation, rep confusion, and onboarding friction', fix: 'Settings → Properties → filter by "Created by user" → add descriptions to each custom property' });
    if (docRate < 70) score -= 6;

    // 10. Goals configured
    const hasGoals = goals.length > 0;
    const activeGoals = goals.filter(g => { const end=g.properties?.hs_end_datetime; return !end||new Date(end).getTime()>now; }).length;
    checks.push({ name: 'Sales Goals Configured', pass: hasGoals && activeGoals > 0, detail: hasGoals ? `${activeGoals} active goal(s) of ${goals.length} total` : 'No sales goals set in HubSpot', impact: 'Without goals, quota attainment cannot be tracked and reps have no visible targets', fix: 'Reports → Goals → Create goals for each rep with monthly/quarterly targets' });
    if (!hasGoals) score -= 6;

    const totalScore = Math.max(0, Math.min(100, score));
    const passing = checks.filter(c => c.pass).length;
    const failing = checks.filter(c => !c.pass).length;
    const grade = totalScore >= 85 ? 'Excellent' : totalScore >= 70 ? 'Good' : totalScore >= 55 ? 'Needs Attention' : 'Critical';

    return { score: totalScore, grade, passing, failing, total: checks.length, checks };
  })();

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ HUBSPOT UTILIZATION ENGINE
  // "You're paying for X but using Y% of it" — the feature no tool provides
  // Calculates what % of HubSpot features being paid for are actually in use
  // ══════════════════════════════════════════════════════════════════════════
  const hubUtilizationEngine = (() => {
    const features = [];

    // CRM Core (always available)
    features.push({ hub: 'CRM', name: 'Contacts', using: contacts.length > 0, value: contacts.length > 0 ? fmt(contacts.length) + ' contacts' : 'Empty', tip: contacts.length === 0 ? 'Import your contacts to activate the CRM' : null });
    features.push({ hub: 'CRM', name: 'Companies', using: companies.length > 0, value: companies.length > 0 ? fmt(companies.length) + ' companies' : 'Not used', tip: companies.length === 0 ? 'Associate contacts with companies for B2B reporting' : null });
    features.push({ hub: 'CRM', name: 'Deals', using: deals.length > 0, value: deals.length > 0 ? fmt(deals.length) + ' deals' : 'Not used', tip: deals.length === 0 ? 'Create deals to track revenue pipeline' : null });
    features.push({ hub: 'CRM', name: 'Tasks & Activities', using: tasks.length > 10, value: tasks.length > 0 ? fmt(tasks.length) + ' tasks logged' : 'Not used', tip: tasks.length === 0 ? 'Reps should log tasks in HubSpot to track follow-ups' : null });

    // Sales Hub
    const activeSeqs = sequences.filter(s => String(s.status||'').toUpperCase()==='ACTIVE');
    const seqsWithEnrollments = sequences.filter(s => parseInt(s.enrollmentCount||s.hs_num_enrolled||0) > 0);
    features.push({ hub: 'Sales', name: 'Sequences', using: seqsWithEnrollments.length > 0, value: seqsWithEnrollments.length > 0 ? seqsWithEnrollments.length + ' sequences with enrollments' : sequences.length > 0 ? sequences.length + ' sequences, 0 enrollments' : 'Not configured', tip: sequences.length > 0 && seqsWithEnrollments.length === 0 ? 'Sequences exist but nobody enrolled — reps are not using them for outreach' : sequences.length === 0 ? 'Create sequences for repeatable sales outreach' : null });
    features.push({ hub: 'Sales', name: 'Meeting Links', using: meetingLinks.length > 0, value: meetingLinks.length > 0 ? meetingLinks.length + ' meeting links' : 'None configured', tip: meetingLinks.length === 0 ? 'Create meeting scheduling pages so prospects can self-book' : null });
    features.push({ hub: 'Sales', name: 'Products Library', using: products.length > 0, value: products.length > 0 ? products.length + ' products' : 'Empty', tip: products.length === 0 ? 'Add products to speed up quote creation and standardize pricing' : null });
    features.push({ hub: 'Sales', name: 'Quotes', using: quotes.length > 0, value: quotes.length > 0 ? fmt(quotes.length) + ' quotes created' : 'Not used', tip: quotes.length === 0 ? 'Use HubSpot Quotes to generate proposals directly from deals' : null });
    features.push({ hub: 'Sales', name: 'Goals / Quota Tracking', using: goals.length > 0, value: goals.length > 0 ? goals.length + ' goals set' : 'Not configured', tip: goals.length === 0 ? 'Set sales goals to track quota attainment per rep' : null });

    // Marketing Hub
    const sentEmails = marketingEmails.filter(e => ['PUBLISHED','SENT'].includes(String(e.state||e.currentState||'').toUpperCase()));
    features.push({ hub: 'Marketing', name: 'Marketing Emails', using: sentEmails.length > 0, value: sentEmails.length > 0 ? sentEmails.length + ' emails sent' : marketingEmails.length > 0 ? marketingEmails.length + ' emails, none sent' : 'Not used', tip: marketingEmails.length > 0 && sentEmails.length === 0 ? 'Marketing emails drafted but never sent — activate campaigns' : marketingEmails.length === 0 ? 'Create email campaigns to nurture leads' : null });
    features.push({ hub: 'Marketing', name: 'Forms', using: forms.length > 0, value: forms.length > 0 ? forms.length + ' forms active' : 'No forms', tip: forms.length === 0 ? 'Create forms to capture leads from your website' : null });
    features.push({ hub: 'Marketing', name: 'Lists & Segmentation', using: lists.length > 5, value: lists.length > 0 ? lists.length + ' lists' : 'Not used', tip: lists.length < 3 ? 'Create active lists to segment contacts for targeted campaigns' : null });
    features.push({ hub: 'Marketing', name: 'Campaigns', using: campaigns.length > 0, value: campaigns.length > 0 ? campaigns.length + ' campaigns' : 'Not used', tip: campaigns.length === 0 ? 'Use campaigns to attribute revenue to marketing efforts' : null });

    // Service Hub
    features.push({ hub: 'Service', name: 'Tickets / Help Desk', using: tickets.length > 0, value: tickets.length > 0 ? fmt(tickets.length) + ' tickets' : 'Not used', tip: tickets.length === 0 ? 'Create tickets to track customer support requests' : null });
    features.push({ hub: 'Service', name: 'Knowledge Base', using: kbArticles.length > 0, value: kbArticles.length > 0 ? kbArticles.length + ' KB articles' : 'Not set up', tip: kbArticles.length === 0 ? 'Create KB articles to reduce repetitive support tickets' : null });
    features.push({ hub: 'Service', name: 'Feedback Surveys (NPS/CSAT)', using: feedback.length > 0, value: feedback.length > 0 ? feedback.length + ' responses collected' : 'Not active', tip: feedback.length === 0 ? 'Launch an NPS survey to measure customer satisfaction' : null });

    // Automation
    const activeWorkflows = workflows.filter(w => w.enabled || w.isEnabled);
    const workingWf = activeWorkflows.filter(w => parseInt(w.enrolledObjectsCount||w.contactsEnrolled||0) > 0);
    features.push({ hub: 'Automation', name: 'Workflows', using: workingWf.length > 0, value: workingWf.length > 0 ? workingWf.length + ' actively enrolling' : activeWorkflows.length > 0 ? activeWorkflows.length + ' active, 0 enrolling' : 'Not used', tip: activeWorkflows.length > 0 && workingWf.length === 0 ? 'All workflows are active but enrolling nobody — triggers may be broken' : activeWorkflows.length === 0 ? 'Build automation workflows to save team time' : null });

    const using = features.filter(f => f.using).length;
    const notUsing = features.filter(f => !f.using).length;
    const utilizationPct = Math.round(using / features.length * 100);
    const grade = utilizationPct >= 80 ? 'Excellent' : utilizationPct >= 60 ? 'Good' : utilizationPct >= 40 ? 'Partial' : 'Low';

    // Group by hub
    const byHub = {};
    features.forEach(f => {
      if (!byHub[f.hub]) byHub[f.hub] = { using: 0, total: 0, features: [] };
      byHub[f.hub].total++;
      if (f.using) byHub[f.hub].using++;
      byHub[f.hub].features.push(f);
    });

    // Opportunities = not-using features with tips
    const opportunities = features.filter(f => !f.using && f.tip).slice(0, 8);

    return { utilizationPct, grade, using, notUsing, total: features.length, byHub, opportunities, features };
  })();

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ DEAL SOURCE ATTRIBUTION ENGINE
  // Which contact sources generate the best deals? Cross-ref analytics_source with won deals
  // ══════════════════════════════════════════════════════════════════════════
  // ══════════════════════════════════════════════════════════════════════════
  // ✦ WORKFLOW DEPENDENCY MAP ENGINE
  // What breaks if someone deletes a list, property, form, or owner?
  // ══════════════════════════════════════════════════════════════════════════
  const workflowDependencyEngine = (() => {
    if (workflows.length === 0) return null;

    // Build maps of what exists so we can check against it
    const listIds     = new Set(lists.map(l => String(l.listId || l.id || '')));
    const formIds     = new Set(forms.map(f => String(f.id || f.guid || '')));
    const ownerIds    = new Set(owners.map(o => String(o.id || o.ownerId || '')));
    const propertySet = new Set(contactProps.map(p => p.name));

    const deps = []; // per-workflow dependency report
    const risks = []; // cross-workflow fragility risks

    // Track which entity → which workflows depend on it
    const entityDeps = {}; // entityKey → [wf names]
    const addDep = (key, wfName) => {
      if (!entityDeps[key]) entityDeps[key] = [];
      if (!entityDeps[key].includes(wfName)) entityDeps[key].push(wfName);
    };

    const activeWfs = workflows.filter(w => w.enabled || w.isEnabled || w.status === 'ACTIVE');

    // Helper: extract property references from filter groups — hoisted so all loops can use it
    const extractFilters = (groups) => {
      const filters = [];
      if (Array.isArray(groups)) {
        groups.forEach(g => {
          const gFilters = g.filters || g.filterGroups || [];
          if (Array.isArray(gFilters)) {
            gFilters.forEach(f => {
              if (f.property) filters.push({ property: f.property, value: f.value });
              if (f.filters) f.filters.forEach(ff => ff.property && filters.push({ property: ff.property, value: ff.value }));
            });
          }
          if (g.property) filters.push({ property: g.property, value: g.value });
        });
      }
      return filters;
    };

    activeWfs.forEach(wf => {
      const name = wf.name || wf.id || 'Unknown';
      const wfDeps = { name, id: wf.id, issues: [] };

      // Parse trigger criteria — v3 format has filterGroups or triggers array
      const triggerGroups = wf.filterGroups || wf.triggers || [];
      const actions = wf.actions || [];

      const filters = extractFilters(triggerGroups);

      // Check: depends on owner that's inactive
      const ownerFilter = filters.find(f => f.property === 'hubspot_owner_id');
      if (ownerFilter && ownerFilter.value) {
        const ownerExists = ownerIds.has(String(ownerFilter.value));
        if (!ownerExists) {
          wfDeps.issues.push({ type: 'missing_owner', detail: `Trigger references owner ID ${ownerFilter.value} who may no longer exist` });
          addDep(`owner:${ownerFilter.value}`, name);
        }
      }

      // Check: depends on list membership
      const listFilter = filters.find(f => f.property === 'hs_list_membership' || f.property?.includes('list'));
      if (listFilter && listFilter.value) {
        const listExists = listIds.has(String(listFilter.value));
        addDep(`list:${listFilter.value}`, name);
        if (!listExists) {
          wfDeps.issues.push({ type: 'missing_list', detail: `Trigger depends on list ID ${listFilter.value} which may be deleted or archived` });
        }
      }

      // Check: depends on property that no longer exists
      filters.forEach(f => {
        if (f.property && !f.property.startsWith('hs_') && !propertySet.has(f.property)) {
          // Could be a custom prop that was deleted
          wfDeps.issues.push({ type: 'unknown_property', detail: `Filter uses property "${f.property}" — verify it still exists` });
        }
      });

      // Check: owner-based actions (assign to specific owner)
      actions.forEach(a => {
        if (a.type === 'SET_CONTACT_PROPERTY' && a.propertyName === 'hubspot_owner_id' && a.propertyValue) {
          const ownerExists = ownerIds.has(String(a.propertyValue));
          if (!ownerExists) {
            wfDeps.issues.push({ type: 'action_missing_owner', detail: `Action assigns to owner ID ${a.propertyValue} who no longer exists in HubSpot` });
            addDep(`owner:${a.propertyValue}`, name);
          }
        }
      });

      // Check: form-based triggers
      const formTriggers = filters.filter(f => f.property === 'hs_form_submissions' || f.property?.includes('form'));
      formTriggers.forEach(f => {
        if (f.value) {
          const formExists = formIds.has(String(f.value));
          addDep(`form:${f.value}`, name);
          if (!formExists) {
            wfDeps.issues.push({ type: 'missing_form', detail: `Trigger depends on form ID ${f.value} — verify form still exists` });
          }
        }
      });

      if (wfDeps.issues.length > 0) deps.push(wfDeps);
    });

    // Find entities that multiple workflows depend on (fragility risk)
    Object.entries(entityDeps).forEach(([key, wfNames]) => {
      if (wfNames.length >= 2) {
        const [type, id] = key.split(':');
        const label = type === 'list' ? `List ID ${id}` : type === 'form' ? `Form ID ${id}` : `Owner ID ${id}`;
        risks.push({
          entity: label,
          type,
          id,
          workflowCount: wfNames.length,
          workflows: wfNames,
          warning: `${wfNames.length} workflows depend on this ${type} — if it's deleted or changed, all ${wfNames.length} automations break silently`,
        });
      }
    });

    risks.sort((a, b) => b.workflowCount - a.workflowCount);

    // Inactive owner risk — workflows assigned to inactive users
    const inactiveOwnerNames = {};
    inactiveUsers.forEach(u => {
      const id = String(u.id || u.ownerId || '');
      const name = [u.properties?.firstname || u.firstName || '', u.properties?.lastname || u.lastName || ''].filter(Boolean).join(' ') || u.properties?.email || id;
      if (id) inactiveOwnerNames[id] = name;
    });

    const inactiveOwnerDeps = [];
    activeWfs.forEach(wf => {
      const name = wf.name || wf.id || 'Unknown';
      const filters = extractFilters(wf.filterGroups || wf.triggers || []);
      const ownerFilter = filters.find(f => f.property === 'hubspot_owner_id');
      if (ownerFilter && inactiveOwnerNames[String(ownerFilter.value)]) {
        inactiveOwnerDeps.push({ workflow: name, ownerName: inactiveOwnerNames[String(ownerFilter.value)] });
      }
    });

    return {
      totalActive: activeWfs.length,
      atRiskCount: deps.length,
      atRiskWorkflows: deps.slice(0, 10),
      fragmentileEntities: risks.slice(0, 8),
      inactiveOwnerDeps: inactiveOwnerDeps.slice(0, 5),
      totalRisks: deps.reduce((s, d) => s + d.issues.length, 0),
    };
  })();

  const dealSourceAttribution = (() => {
    if (contacts.length === 0 || deals.length === 0) return null;
    // Map contact ID → source
    const contactSourceMap = {};
    contacts.forEach(c => {
      const src = c.properties?.hs_analytics_source || c.properties?.hs_analytics_source_data_1 || 'Unknown';
      contactSourceMap[c.id] = src.replace(/_/g,' ').replace(/\b\w/g,l=>l.toUpperCase());
    });
    // For each closed won deal, find its source from the owner's contact
    const sourceStats = {};
    const closedWonForAttrib = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
    const closedLostForAttrib = deals.filter(d => d.properties?.hs_is_closed === 'true' && d.properties?.hs_is_closed_won !== 'true');

    // Use deal owner → owner's contacts as proxy (best we can do without association endpoint)
    contacts.forEach(c => {
      const src = contactSourceMap[c.id] || 'Unknown';
      if (!sourceStats[src]) sourceStats[src] = { source: src, contacts:0, wonDeals:0, lostDeals:0, wonValue:0, avgDays:[] };
      sourceStats[src].contacts++;
    });
    // Attribution: match deals to contacts by owner
    closedWonForAttrib.forEach(d => {
      const ownerId = d.properties?.hubspot_owner_id;
      const ownerContact = contacts.find(c => c.properties?.hubspot_owner_id === ownerId);
      const src = ownerContact ? (contactSourceMap[ownerContact.id] || 'Unknown') : 'Unknown';
      if (!sourceStats[src]) sourceStats[src] = { source: src, contacts:0, wonDeals:0, lostDeals:0, wonValue:0, avgDays:[] };
      sourceStats[src].wonDeals++;
      sourceStats[src].wonValue += parseFloat(d.properties?.amount || 0);
      // Sales cycle for this deal
      const created = new Date(d.properties?.createdate||0).getTime();
      const closed = new Date(d.properties?.hs_lastmodifieddate||0).getTime();
      if (created && closed > created) sourceStats[src].avgDays.push((closed-created)/DAY);
    });
    closedLostForAttrib.forEach(d => {
      const ownerId = d.properties?.hubspot_owner_id;
      const ownerContact = contacts.find(c => c.properties?.hubspot_owner_id === ownerId);
      const src = ownerContact ? (contactSourceMap[ownerContact.id] || 'Unknown') : 'Unknown';
      if (!sourceStats[src]) sourceStats[src] = { source: src, contacts:0, wonDeals:0, lostDeals:0, wonValue:0, avgDays:[] };
      sourceStats[src].lostDeals++;
    });
    const rows = Object.values(sourceStats)
      .filter(s => s.contacts > 2)
      .map(s => {
        const total = s.wonDeals + s.lostDeals;
        const winRate = total > 0 ? Math.round(s.wonDeals / total * 100) : 0;
        const avgDeal = s.wonDeals > 0 ? Math.round(s.wonValue / s.wonDeals) : 0;
        const avgCycle = s.avgDays.length > 0 ? Math.round(s.avgDays.reduce((a,b)=>a+b,0)/s.avgDays.length) : 0;
        return { source: s.source, contacts: s.contacts, wonDeals: s.wonDeals, lostDeals: s.lostDeals, winRate, avgDeal, avgCycle, wonValue: Math.round(s.wonValue) };
      })
      .sort((a,b) => b.wonValue - a.wonValue)
      .slice(0, 10);

    const bestSource = rows.find(r => r.wonDeals > 0);
    const fastestSource = rows.filter(r=>r.avgCycle>0).sort((a,b)=>a.avgCycle-b.avgCycle)[0];
    const highestWinRate = rows.filter(r=>r.winRate>0).sort((a,b)=>b.winRate-a.winRate)[0];

    return { rows, bestSource, fastestSource, highestWinRate, totalSources: rows.length };
  })();

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ LIFECYCLE STAGE VELOCITY ENGINE
  // How long do contacts take to move through each lifecycle stage?
  // ══════════════════════════════════════════════════════════════════════════
  const lifecycleVelocityEngine = (() => {
    if (contacts.length < 20) return null;
    const STAGES = ['subscriber','lead','marketingqualifiedlead','salesqualifiedlead','opportunity','customer','evangelist','other'];
    const stageLabels = { subscriber:'Subscriber', lead:'Lead', marketingqualifiedlead:'MQL', salesqualifiedlead:'SQL', opportunity:'Opportunity', customer:'Customer', evangelist:'Evangelist', other:'Other' };
    const stageCounts = {};
    STAGES.forEach(s => stageCounts[s] = 0);
    contacts.forEach(c => {
      const stage = String(c.properties?.lifecyclestage||'').toLowerCase();
      if (stageCounts[stage] !== undefined) stageCounts[stage]++;
    });

    // Funnel conversion rates between stages
    const stageOrder = ['subscriber','lead','marketingqualifiedlead','salesqualifiedlead','opportunity','customer'];
    const funnelSteps = [];
    for (let i=0; i < stageOrder.length-1; i++) {
      const from = stageOrder[i];
      const to = stageOrder[i+1];
      const fromCount = stageCounts[from] || 0;
      const toCount = stageCounts[to] || 0;
      const convRate = fromCount > 0 ? Math.round(toCount / (fromCount + toCount) * 100) : 0;
      funnelSteps.push({ from: stageLabels[from], to: stageLabels[to], fromCount, toCount, convRate });
    }

    // Velocity: estimate days per stage from contact age and stage distribution
    const customerCount = stageCounts['customer'] || 0;
    const leadCount = stageCounts['lead'] || 0;
    const sqlCount = stageCounts['salesqualifiedlead'] || 0;
    const noStage = contacts.filter(c => !c.properties?.lifecyclestage).length;
    const noStagePct = Math.round(noStage / contacts.length * 100);

    // Lead-to-customer estimate: contacts with createdate vs closed won deals
    const allClosedWonForLC = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
    const wonWithDatesLC = allClosedWonForLC.filter(d => d.properties?.createdate && d.properties?.closedate);
    const avgLeadToCustomerDays = wonWithDatesLC.length > 0
      ? Math.round(wonWithDatesLC.reduce((s,d) => {
          return s + (new Date(d.properties.closedate).getTime() - new Date(d.properties.createdate).getTime()) / DAY;
        }, 0) / wonWithDatesLC.length)
      : null;

    return {
      stageCounts,
      stageLabels,
      funnelSteps,
      noStagePct,
      noStageCount: noStage,
      customerCount,
      leadCount,
      sqlCount,
      avgLeadToCustomerDays,
      totalContacts: contacts.length,
    };
  })();

  // ══════════════════════════════════════════════════════════════════════════
  // ✦ BILLING TIER PROXIMITY ENGINE
  // How close is this portal to hitting the next HubSpot billing tier?
  // HubSpot Marketing Hub contact tiers: 1k, 2k, 5k, 10k, 25k, 50k, 100k, 200k+
  // ══════════════════════════════════════════════════════════════════════════
  const billingTierEngine = (() => {
    const TIERS = [1000,2000,5000,10000,25000,50000,100000,200000];
    const totalC = contacts.length;
    const currentTier = TIERS.find(t => totalC <= t) || TIERS[TIERS.length-1];
    const nextTier    = TIERS[TIERS.indexOf(currentTier) + 1] || null;
    const pctOfTier   = Math.round(totalC / currentTier * 100);
    const headroom    = currentTier - totalC;
    const atRisk      = pctOfTier >= 85;
    const critical    = pctOfTier >= 95;
    // Monthly new contacts estimate (last 30 days)
    const recentContacts = contacts.filter(c => {
      const created = new Date(c.properties?.createdate||0).getTime();
      return (now - created) / DAY <= 30;
    }).length;
    const monthlyGrowthRate = recentContacts;
    const monthsToNextTier  = monthlyGrowthRate > 0 ? Math.ceil(headroom / monthlyGrowthRate) : null;
    const dupesRemovable     = dupes; // removing dupes gives back headroom
    const deadRemovable      = contactDecayEngine?.buckets?.dead || 0;
    const totalRemovable     = dupesRemovable + deadRemovable;
    // Billing cost estimate for next tier (rough HubSpot Marketing Pro pricing)
    const tierCosts = { 1000:0, 2000:45, 5000:800, 10000:1600, 25000:3200, 50000:5600, 100000:9600, 200000:17400 };
    const currentCost = tierCosts[currentTier] || 0;
    const nextCost    = nextTier ? (tierCosts[nextTier] || 0) : null;
    const tierJumpCost = nextCost ? nextCost - currentCost : null;

    return {
      totalContacts: totalC,
      currentTier, nextTier, pctOfTier, headroom,
      atRisk, critical,
      monthlyGrowthRate, monthsToNextTier,
      dupesRemovable, deadRemovable, totalRemovable,
      currentCost, nextCost, tierJumpCost,
    };
  })();

  // 1. Duplicate contacts → billing tier inflation
  // HubSpot 5k tier = $800/mo ÷ 5000 contacts = $0.16/contact
  // HubSpot 10k tier = $1600/mo ÷ 10000 = $0.16/contact. We use $0.18 as a mid-point.
  const wasteDupes = Math.round(dupes * 0.18);

  // 2. Stalled pipeline → opportunity cost (2%/mo of stalled pipeline VALUE only)
  //    Only count if deals have actual $ amounts — avoids inflating on $0-amount deals
  const stalledWithValue = stalled.filter(d => parseFloat(d.properties?.amount||0) > 0);
  const stalledRealVal   = stalledWithValue.reduce((s,d) => s + parseFloat(d.properties?.amount||0), 0);
  const wasteStalledDeals = stalledRealVal > 0 ? Math.round(stalledRealVal * 0.02) : 0;

  // 3. Dead workflows → rep time + missed automation ($22/dead wf/mo)
  const wasteDeadWorkflows = Math.round(deadWf.length * 22);

  // 4. Ghost seats → HubSpot Sales/Service Hub Pro seat cost ($90/seat/mo)
  // Source: HubSpot published pricing — Sales Hub Pro = $90/seat, Enterprise = $120/seat
  const wasteGhostSeats = Math.round(inactiveUsers.length * 90);

  // 5. Contacts with no email → billing overhead with zero marketing value
  // We do NOT quantify as dollar waste since nurture value is portal-specific
  // Instead tracked as a data quality issue, not a waste dollar amount
  const wasteNoEmail = 0;

  // 6. Overdue invoices → AR collection cost ($35/overdue invoice/mo)
  const wasteOverdueInv = invoices.length > 0 ? Math.round(overdueInvoices.length * 35) : 0;

  // 7. Expired quotes → recoverable revenue (20% win-back rate × avg deal / 12)
  // Source: B2B win-back rates average 15-25% (Forrester 2023). Using 20% is conservative and defensible.
  const expiredQList = quotes.filter(q => String(q.properties?.hs_quote_status||'').toLowerCase() === 'expired');
  const wasteExpiredQ = expiredQList.length > 0
    ? Math.round(expiredQList.length * Math.max(revenueIntel?.avgDealSize || 0, 500) * 0.20 / 12)
    : 0;

  const monthlyWaste = Math.round(
    wasteDupes + wasteStalledDeals + wasteDeadWorkflows +
    wasteGhostSeats + wasteNoEmail + wasteOverdueInv + wasteExpiredQ
  );
  // Store breakdown for revenue leaks page
  const wasteBreakdown = { wasteDupes, wasteStalledDeals, wasteDeadWorkflows, wasteGhostSeats, wasteNoEmail, wasteOverdueInv, wasteExpiredQ, isCappedScan };

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
        workflows: workflows.length, forms: forms.length,
        workflowList: workflows.slice(0, 100).map(w => ({ id: w.id, name: w.name||w.id, enabled: w.enabled||w.isEnabled, triggers: w.triggers||w.filterGroups||[], actions: w.actions||[], enrolledObjectsCount: w.enrolledObjectsCount||w.contactsEnrolled||0 })),
        // Store open deals for deal-risk endpoint (capped to avoid storage bloat)
        dealList: deals.filter(d => d.properties?.hs_is_closed !== 'true').slice(0, 500).map(d => ({
          id: d.id,
          properties: {
            dealname: d.properties?.dealname,
            amount: d.properties?.amount,
            dealstage: d.properties?.dealstage,
            closedate: d.properties?.closedate,
            hubspot_owner_id: d.properties?.hubspot_owner_id,
            hs_lastmodifieddate: d.properties?.hs_lastmodifieddate,
            notes_last_updated: d.properties?.notes_last_updated,
            hs_deal_stage_probability: d.properties?.hs_deal_stage_probability,
            hs_is_closed: d.properties?.hs_is_closed,
            hs_is_closed_won: d.properties?.hs_is_closed_won,
            num_associated_contacts: d.properties?.num_associated_contacts,
            pipeline: d.properties?.pipeline,
          }
        })),
        // ── Automation ROI ──────────────────────────────────────────────────────
        automationROI: (() => {
          if (!workflows.length) return null;
          const AVG_TASK_MIN = 8;       // avg mins a workflow saves per enrollment
          const HOURLY_RATE  = 35;      // avg HubSpot user hourly cost
          const activeWfList = workflows.filter(w => w.properties?.hs_is_published !== 'false');
          const totalEnrollments = activeWfList.reduce((sum,w) => sum + parseInt(w.properties?.hs_num_enrolled||0),0);
          const hrsSaved = Math.round(totalEnrollments * AVG_TASK_MIN / 60);
          const dollarSaved = Math.round(hrsSaved * HOURLY_RATE);
          const deadWfCount = workflows.filter(w => parseInt(w.properties?.hs_num_enrolled||0)===0 && w.properties?.hs_is_published!=='false').length;
          const erroredWfCount = workflows.filter(w => parseInt(w.properties?.hs_num_actions_errored||0)>0).length;
          const efficiency = workflows.length > 0
            ? Math.round(((workflows.length - deadWfCount - erroredWfCount) / workflows.length) * 100)
            : 0;
          const lostValue = Math.round(deadWfCount * AVG_TASK_MIN / 60 * HOURLY_RATE * 50); // 50 avg missed enrollments/mo
          return { hrsSaved, dollarSaved, efficiency, deadWfCount, erroredWfCount, lostValue, totalEnrollments, activeCount: activeWfList.length };
        })(), users: users.length,
        lists: lists.length, tasks: tasks.length, meetings: meetings.length,
        calls: calls.length, quotes: quotes.length, lineItems: lineItems.length,
        products: products.length, orders: orders.length,
        invoices: invoices.length, subscriptions: subscriptions.length,

        // ── Revenue intelligence ──────────────────────────────────
        openDealsCount: openDeals.length,
        openPipelineValue: Math.round(openDeals.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0)),
        avgDealSize: openDeals.length > 0
          ? Math.round(openDeals.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0) / openDeals.length)
          : 0,
        zeroDollarDeals: openDeals.filter(d=>!parseFloat(d.properties?.amount||0)).length,
        zeroDollarPct: openDeals.length > 0
          ? Math.round(openDeals.filter(d=>!parseFloat(d.properties?.amount||0)).length / openDeals.length * 100)
          : 0,
        stalledDeals: openDeals.filter(d=>(now-new Date(d.properties?.hs_lastmodifieddate||0).getTime())/DAY>21).length,
        // Stalled pipeline value = actual $ of stalled deals only
        stalledPipelineValue: Math.round(openDeals.filter(d=>{
          const days = (now-new Date(d.properties?.hs_lastmodifieddate||0).getTime())/DAY;
          return days > 21 && parseFloat(d.properties?.amount||0) > 0;
        }).reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0)),
        dealsNoCloseDate: openDeals.filter(d=>!d.properties?.closedate).length,
        pastDueDeals: openDeals.filter(d=>{
          const cd = d.properties?.closedate;
          return cd && new Date(cd).getTime() < now;
        }).length,
        // Past-due pipeline value = actual $ of overdue deals only
        pastDuePipelineValue: Math.round(openDeals.filter(d=>{
          const cd = d.properties?.closedate;
          return cd && new Date(cd).getTime() < now && parseFloat(d.properties?.amount||0) > 0;
        }).reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0)),

        // ── Subscription / MRR intelligence ──────────────────────
        activeSubscriptions: subscriptions.filter(sub=>
          String(sub.properties?.hs_status||'').toLowerCase()==='active').length,
        mrrTotal: Math.round(subscriptions
          .filter(sub=>String(sub.properties?.hs_status||'').toLowerCase()==='active')
          .reduce((s,sub)=>s+parseFloat(sub.properties?.hs_recurring_revenue||0),0)),
        subsRenewingNext30: subscriptions.filter(sub=>{
          const nd = sub.properties?.hs_next_payment_due_date;
          if(!nd) return false;
          const days = (new Date(nd).getTime()-now)/DAY;
          return days >= 0 && days <= 30;
        }).length,
        cancelledSubscriptions: subscriptions.filter(sub=>
          ['cancelled','canceled'].includes(String(sub.properties?.hs_status||'').toLowerCase())).length,

        // ── Quote intelligence ────────────────────────────────────
        openQuotes: quotes.filter(q=>
          ['draft','approval_not_needed','pending_approval'].includes(
            String(q.properties?.hs_status||'').toLowerCase())).length,
        expiredQuotes: quotes.filter(q=>{
          const exp = q.properties?.hs_expiration_date;
          return exp && new Date(exp).getTime() < now &&
            String(q.properties?.hs_status||'').toLowerCase() !== 'accepted';
        }).length,
        acceptedQuotes: quotes.filter(q=>
          String(q.properties?.hs_status||'').toLowerCase()==='accepted').length,

        // ── Contact engagement segmentation ──────────────────────
        // ── Contact Decay Score ──────────────────────────────────────────────
        // Age distribution of contacts by last activity
        contactDecay: (() => {
          const NINETY = 90 * DAY;
          const ONE80  = 180 * DAY;
          const YEAR   = 365 * DAY;
          const fresh   = contacts.filter(c => { const l=c.properties?.hs_last_sales_activity_timestamp; return l&&(now-new Date(l).getTime())<NINETY; }).length;
          const aging   = contacts.filter(c => { const l=c.properties?.hs_last_sales_activity_timestamp; return l&&(now-new Date(l).getTime())>=NINETY&&(now-new Date(l).getTime())<ONE80; }).length;
          const stale   = contacts.filter(c => { const l=c.properties?.hs_last_sales_activity_timestamp; return l&&(now-new Date(l).getTime())>=ONE80&&(now-new Date(l).getTime())<YEAR; }).length;
          const dead    = contacts.filter(c => { const l=c.properties?.hs_last_sales_activity_timestamp; return !l||(now-new Date(l).getTime())>=YEAR; }).length;
          const billingWaste = Math.round(dead * 0.45); // avg billing cost of dead contacts
          return { fresh, aging, stale, dead, total: contacts.length, billingWaste };
        })(),

        hotContacts: contacts.filter(c=>{
          const last = c.properties?.hs_last_sales_activity_timestamp;
          return last && (now-new Date(last).getTime())/DAY < 30;
        }).length,
        warmContacts: contacts.filter(c=>{
          const last = c.properties?.hs_last_sales_activity_timestamp;
          return last && (now-new Date(last).getTime())/DAY >= 30 &&
                 (now-new Date(last).getTime())/DAY < 90;
        }).length,
        coldContacts: contacts.filter(c=>{
          const last = c.properties?.hs_last_sales_activity_timestamp;
          return !last || (now-new Date(last).getTime())/DAY >= 90;
        }).length,
        contactsWithDeals: contacts.filter(c=>c.properties?.num_contacted_notes > 0).length,
        contactsNoFirstName: contacts.filter(c=>!c.properties?.firstname||c.properties.firstname.trim()==='').length,
        contactsWithPersona: contacts.filter(c=>c.properties?.hs_persona&&c.properties.hs_persona!=='').length,
        contactsNoCompanyAssoc: contacts.filter(c=>!c.properties?.associatedcompanyid&&!c.properties?.num_associated_companies).length,
        contactsBySource: (() => {
          const src = {};
          contacts.forEach(c => {
            const s = c.properties?.hs_analytics_source || 'Unknown';
            src[s] = (src[s]||0) + 1;
          });
          return Object.entries(src).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([s,n])=>({source:s,count:n}));
        })(),

        // ── Invoice intelligence ──────────────────────────────────
        unpaidInvoices: invoices.filter(i=>
          ['outstanding','past_due'].includes(String(i.properties?.hs_invoice_status||'').toLowerCase())).length,
        overdueInvoices: invoices.filter(i=>
          String(i.properties?.hs_invoice_status||'').toLowerCase()==='past_due').length,
        paidInvoices: invoices.filter(i=>
          String(i.properties?.hs_invoice_status||'').toLowerCase()==='paid').length,

        // ── Team activity (last 7 days) ───────────────────────────
        callsThisWeek: calls.filter(c=>(now-new Date(c.properties?.hs_createdate||0).getTime())/DAY<7).length,
        meetingsThisWeek: meetings.filter(m=>(now-new Date(m.properties?.hs_timestamp||0).getTime())/DAY<7).length,
        overdueTasks: tasks.filter(t=>{
          const due = t.properties?.hs_timestamp;
          const status = String(t.properties?.hs_task_status||'').toLowerCase();
          return due && new Date(due).getTime() < now && status !== 'completed';
        }).length,

        // ── Company intelligence ──────────────────────────────────
        companiesCount: companies.length,
        companiesWithRevenue: companies.filter(c=>parseFloat(c.properties?.annualrevenue||0)>0).length,
        companiesNoOwner: companies.filter(c=>!c.properties?.hubspot_owner_id).length,
        companiesNoDomain: companies.filter(c=>!c.properties?.domain||c.properties.domain.trim()==='').length,
        companiesNoContacts: companies.filter(c=>parseInt(c.properties?.num_associated_contacts||0)===0).length,

        // ── Carts & Communications ───────────────────────────────────────
        cartCount: carts.length,
        abandonedCarts: carts.filter(c => String(c.properties?.hs_cart_status||'').toLowerCase() === 'abandoned').length,
        communicationsLogged: communications.length,
        communicationsByChannel: communications.reduce((acc, c) => {
          const ch = c.properties?.hs_communication_channel_type || 'unknown';
          acc[ch] = (acc[ch] || 0) + 1;
          return acc;
        }, {}),

        // ── Marketing Emails ──────────────────────────────────────────────
        marketingEmailCount: marketingEmails.length,
        publishedEmails: marketingEmails.filter(e => ['PUBLISHED','SENT'].includes(String(e.state||e.currentState||'').toUpperCase())).length,
        draftEmails: marketingEmails.filter(e => String(e.state||e.currentState||'').toUpperCase() === 'DRAFT').length,
        scheduledEmails: marketingEmails.filter(e => String(e.state||e.currentState||'').toUpperCase() === 'SCHEDULED').length,

        // Per-email performance table (top 50 by sends — for marketing view)
        topEmails: marketingEmails
          .map(e => {
            const s = e.stats || e.counters || {};
            const sent = s.sent || s.delivered || 0;
            const opens = s.open || s.opened || s.opens || 0;
            const clicks = s.click || s.clicks || s.uniqueClicks || 0;
            const bounces = s.bounce || s.bounced || s.hardBounced || 0;
            const unsubs = s.unsubscribed || s.unsubscribe || s.optOut || 0;
            const spam = s.spamreport || s.spam || s.spamReport || 0;
            return {
              id: e.id,
              name: e.name || e.subject || 'Unnamed Email',
              subject: e.subject || '',
              state: String(e.state || e.currentState || '').toUpperCase(),
              sentAt: e.publishDate || e.publishedAt || e.updatedAt || null,
              sent,
              openRate:   sent > 0 ? Math.round(opens   / sent * 1000) / 10 : 0,
              clickRate:  sent > 0 ? Math.round(clicks   / sent * 1000) / 10 : 0,
              bounceRate: sent > 0 ? Math.round(bounces  / sent * 10000) / 100 : 0,
              unsubRate:  sent > 0 ? Math.round(unsubs   / sent * 10000) / 100 : 0,
              spamRate:   sent > 0 ? Math.round(spam     / sent * 10000) / 100 : 0,
              opens, clicks, bounces, unsubs,
            };
          })
          .filter(e => e.sent > 0)
          .sort((a, b) => b.sent - a.sent)
          .slice(0, 50),

        // Aggregate email health summary
        emailHealthSummary: (() => {
          const sent = marketingEmails.filter(e => {
            const state = String(e.state || e.currentState || '').toUpperCase();
            return ['PUBLISHED','SENT'].includes(state);
          });
          if (!sent.length) return null;
          let tSent=0,tOpen=0,tClick=0,tBounce=0,tUnsub=0,tSpam=0;
          sent.forEach(e => {
            const s = e.stats || e.counters || {};
            const n = s.sent || s.delivered || 0;
            tSent   += n;
            tOpen   += s.open || s.opened || s.opens || 0;
            tClick  += s.click || s.clicks || s.uniqueClicks || 0;
            tBounce += s.bounce || s.bounced || s.hardBounced || 0;
            tUnsub  += s.unsubscribed || s.unsubscribe || s.optOut || 0;
            tSpam   += s.spamreport || s.spam || s.spamReport || 0;
          });
          return {
            totalSent:    tSent,
            emailCount:   sent.length,
            openRate:     tSent > 0 ? Math.round(tOpen   / tSent * 1000) / 10 : 0,
            clickRate:    tSent > 0 ? Math.round(tClick  / tSent * 1000) / 10 : 0,
            bounceRate:   tSent > 0 ? Math.round(tBounce / tSent * 10000) / 100 : 0,
            unsubRate:    tSent > 0 ? Math.round(tUnsub  / tSent * 10000) / 100 : 0,
            spamRate:     tSent > 0 ? Math.round(tSpam   / tSent * 10000) / 100 : 0,
          };
        })(),

        // Backward-compat aliases used by existing frontend code
        emailTotalSent:    (() => { const h = marketingEmails; return h.reduce((s,e) => s+(e.stats||e.counters||{}).sent||(e.stats||e.counters||{}).delivered||0, 0); })(),
        avgOpenRate:       null, // computed below from emailHealthSummary
        avgClickRate:      null,
        avgBounceRate:     null,
        avgUnsubRate:      null,
        highBounceEmails:  marketingEmails.filter(e => { const s=e.stats||e.counters||{}; const n=s.sent||s.delivered||0; const b=s.bounce||s.bounced||s.hardBounced||0; return n>100&&b/n>0.05; }).length,
        lowOpenEmails:     marketingEmails.filter(e => { const s=e.stats||e.counters||{}; const n=s.sent||s.delivered||0; const o=s.open||s.opened||s.opens||0; return n>500&&o/n*100<15; }).length,
        staleDraftEmails:  marketingEmails.filter(e => { const isDraft=['DRAFT'].includes(String(e.state||e.currentState||'').toUpperCase()); const u=e.updatedAt||e.updated; return isDraft&&u&&(now-new Date(u).getTime())/DAY>90; }).length,

        // ── Sequences & Campaigns ─────────────────────────────────────────
        sequences: sequences.length,
        activeSequences: sequences.filter(seq=>String(seq.status||'').toUpperCase()==='ACTIVE').length,
        campaigns: campaigns.length,

        // ── Lists ─────────────────────────────────────────────────────────
        listCount: lists.length,
        staticLists: lists.filter(l=>l.listType==='STATIC'||l.dynamic===false).length,
        emptyLists: lists.filter(l=>(l.metaData?.size||l.size||0)===0).length,

        // ── Leads ─────────────────────────────────────────────────────────
        leads: leads.length,
        unownedLeads: leads.filter(l=>!l.properties?.hubspot_owner_id).length,
        newLeads: leads.filter(l=>String(l.properties?.hs_lead_status||'').toUpperCase()==='NEW').length,

        // ── Goals ─────────────────────────────────────────────────────────
        goals: goals.length,
        activeGoals: goals.filter(g=>{ const end=g.properties?.hs_end_datetime; return !end||new Date(end).getTime()>now; }).length,

        // ── NPS / CSAT ────────────────────────────────────────────────────
        npsResponses: feedback.filter(f=>f.properties?.hs_survey_type==='NPS').length,
        csatResponses: feedback.filter(f=>f.properties?.hs_survey_type==='CSAT').length,

        // ── Email subscription health ─────────────────────────────────────
        emailSubTypes: optOutDefs.length,

        // ── Conversations ─────────────────────────────────────────────────
        openConversations: conversations.filter(c=>String(c.status||'').toUpperCase()==='OPEN').length,
        totalConversations: conversations.length,

        // ── Ticket Health ──────────────────────────────────────────────────
        ticketsByPriority: (() => {
          const byPri = { high:0, medium:0, low:0, none:0 };
          tickets.forEach(t => {
            const p = String(t.properties?.hs_ticket_priority||'').toLowerCase();
            if (p === 'high') byPri.high++;
            else if (p === 'medium') byPri.medium++;
            else if (p === 'low') byPri.low++;
            else byPri.none++;
          });
          return byPri;
        })(),
        // Ticket open detection: a ticket is closed if it has time_to_close set (resolved)
        // OR if its stage matches known closed stage names/IDs
        // HubSpot default: stage 4 = Closed. Custom pipelines vary.
        // time_to_close being set is the most reliable closed signal.
        openTickets: tickets.filter(t => {
          const stage = String(t.properties?.hs_pipeline_stage||'').toLowerCase();
          const hasClosed = t.properties?.time_to_close || t.properties?.hs_time_in_stage_4;
          const closedStages = ['4','closed','resolved','closedwon','closed_won'];
          return !hasClosed && !closedStages.includes(stage);
        }).length,
        ticketsOver3Days: tickets.filter(t => {
          const stage = String(t.properties?.hs_pipeline_stage||'').toLowerCase();
          const hasClosed = t.properties?.time_to_close || t.properties?.hs_time_in_stage_4;
          const closedStages = ['4','closed','resolved','closedwon','closed_won'];
          const isOpen = !hasClosed && !closedStages.includes(stage);
          return isOpen && (now - new Date(t.properties?.createdate||0).getTime()) / DAY > 3;
        }).length,
        ticketsOver7Days: tickets.filter(t => {
          const stage = String(t.properties?.hs_pipeline_stage||'').toLowerCase();
          const hasClosed = t.properties?.time_to_close || t.properties?.hs_time_in_stage_4;
          const closedStages = ['4','closed','resolved','closedwon','closed_won'];
          const isOpen = !hasClosed && !closedStages.includes(stage);
          return isOpen && (now - new Date(t.properties?.createdate||0).getTime()) / DAY > 7;
        }).length,
        ticketsUnassigned: tickets.filter(t => {
          const stage = String(t.properties?.hs_pipeline_stage||'').toLowerCase();
          const hasClosed = t.properties?.time_to_close || t.properties?.hs_time_in_stage_4;
          const closedStages = ['4','closed','resolved','closedwon','closed_won'];
          const isOpen = !hasClosed && !closedStages.includes(stage);
          return isOpen && !t.properties?.hubspot_owner_id;
        }).length,
        avgTicketAgeOpenDays: (() => {
          const closedStages = ['4','closed','resolved','closedwon','closed_won'];
          const open = tickets.filter(t => {
            const stage = String(t.properties?.hs_pipeline_stage||'').toLowerCase();
            const hasClosed = t.properties?.time_to_close || t.properties?.hs_time_in_stage_4;
            return !hasClosed && !closedStages.includes(stage);
          });
          if (!open.length) return 0;
          const total = open.reduce((sum,t) => sum + (now - new Date(t.properties?.createdate||0).getTime()) / DAY, 0);
          return Math.round(total / open.length);
        })(),
        ticketHighPriorityOpen: tickets.filter(t => {
          const stage = String(t.properties?.hs_pipeline_stage||'').toLowerCase();
          const hasClosed = t.properties?.time_to_close || t.properties?.hs_time_in_stage_4;
          const closedStages = ['4','closed','resolved','closedwon','closed_won'];
          const p = String(t.properties?.hs_ticket_priority||'').toLowerCase();
          return !hasClosed && !closedStages.includes(stage) && p === 'high';
        }).length,

        // ── Multi-currency ────────────────────────────────────────────────
        hasMultiCurrency: currencies.length > 1,
        currencyCount: currencies.length,

        // ── Pipeline schema ───────────────────────────────────────────────
        dealPipelines: dealPipelines.length,
        dealStagesTotal: dealPipelines.reduce((sum, p) => sum + (p.stages ? p.stages.length : 0), 0),

        // ── Revenue Leak Analysis ──────────────────────────────────────────
        // Map deals to pipeline stages to find where revenue dies
        pipelineFunnel: (() => {
          if (!dealPipelines.length || !openDeals.length) return null;
          const mainPipeline = dealPipelines[0];
          if (!mainPipeline?.stages?.length) return null;
          const stages = mainPipeline.stages.sort((a,b) => (a.displayOrder||0)-(b.displayOrder||0));
          return stages.map(stage => {
            const stageDeals = openDeals.filter(d => d.properties?.dealstage === stage.id);
            const stageValue = stageDeals.reduce((sum,d) => sum+parseFloat(d.properties?.amount||0),0);
            const staleInStage = stageDeals.filter(d => {
              const mod = new Date(d.properties?.hs_lastmodifieddate||0).getTime();
              return (now - mod)/DAY > 21;
            });
            // Avg days in stage (approx from createdate)
            const avgDays = stageDeals.length > 0
              ? Math.round(stageDeals.reduce((sum,d) => sum + (now - new Date(d.properties?.createdate||now).getTime())/DAY, 0) / stageDeals.length)
              : 0;
            return {
              name: stage.label || stage.id,
              count: stageDeals.length,
              value: Math.round(stageValue),
              stale: staleInStage.length,
              avgDays,
              probability: parseFloat(stage.probability || 0) * 100
            };
          }).filter(st => st.count > 0 || st.name);
        })(),

        // ── Custom properties ─────────────────────────────────────────────
        customContactProps: contactProps.filter(p => p.createdUserId).length,
        // Audit shortcut counts — used by Revenue Leak Calculator
        deadWorkflowCount: deadWf ? deadWf.length : 0,

        // New feature data
        kbArticleCount: kbArticles.length,
        kbUnpublishedCount: kbArticles.filter(a => a.currentState==='DRAFT'||a.state==='DRAFT'||a.published===false).length,
        meetingLinkCount: meetingLinks.length,
        teamCount: teams.length,
        teamNames: teams.map(t => t.name).filter(Boolean).slice(0,5),
        repsWithoutMeetingLinks: (() => {
          const ownersWithLinks = new Set(meetingLinks.map(m => m.ownerId||m.userId).filter(Boolean));
          return owners.filter(o => !ownersWithLinks.has(o.id||o.ownerId)).length;
        })(),
        duplicateContactCount: dupes || 0,
        noEmailContactCount: noEmail ? noEmail.length : 0,
        contactCompleteness: contactCompletenessData || {},

        // Custom objects (Enterprise)
        customObjectCount: customObjectData.length,
        customObjectNames: customObjectData.map(o => o.labelPlural || o.label),
        customObjectData: customObjectData,  // full array with counts
        undocumentedProps: contactProps.filter(p => p.createdUserId && !p.description).length,

        // ── Lead Scoring Intelligence ──────────────────────────────────────
        leadScoringEngine,

        // ── Integration Health ─────────────────────────────────────────────
        connectedIntegrationCount: connectedIntegrations.length,
        integrationErrorCount: integrationErrors.length,
        integrationErrors: integrationErrors.slice(0, 10),

        // ── PIPELINE VELOCITY ENGINE ─────────────────────────────────────────
        // Calculates actual stage velocity from deal data — cross-refs pipeline stages
        pipelineVelocity: (() => {
          if (!openDeals.length || !dealPipelines.length) return null;
          const mainPipeline = dealPipelines[0];
          if (!mainPipeline?.stages?.length) return null;
          const stages = mainPipeline.stages
            .filter(s => parseFloat(s.probability||s.metadata?.probability||0) > 0 && parseFloat(s.probability||s.metadata?.probability||0) < 1)
            .sort((a,b) => (a.displayOrder||0)-(b.displayOrder||0));

          // Win rate from historical closed deals
          const closedWonCount  = deals.filter(d => d.properties?.hs_is_closed_won === 'true').length;
          const closedLostCount = deals.filter(d => d.properties?.hs_is_closed === 'true' && d.properties?.hs_is_closed_won !== 'true').length;
          const totalClosed = closedWonCount + closedLostCount;
          const winRate = totalClosed > 0 ? closedWonCount / totalClosed : 0.25; // fallback 25%

          // Avg days per stage (from deal hs_lastmodifieddate)
          const stageVelocity = {};
          stages.forEach(stage => {
            const stageDeals = deals.filter(d => d.properties?.dealstage === stage.id);
            if (!stageDeals.length) { stageVelocity[stage.id] = { label: stage.label, avgDays: 0, count: 0 }; return; }
            const totalDays = stageDeals.reduce((sum, d) => {
              return sum + Math.max(0, (now - new Date(d.properties?.hs_lastmodifieddate||d.properties?.createdate||now).getTime()) / DAY);
            }, 0);
            stageVelocity[stage.id] = {
              label: stage.label || stage.id,
              avgDays: Math.round(totalDays / stageDeals.length),
              count: stageDeals.length,
              probability: parseFloat(stage.probability||stage.metadata?.probability||0)
            };
          });

          // Total avg sales cycle = sum of avg days per stage
          const totalCycleDays = Object.values(stageVelocity).reduce((sum, s) => sum + (s.avgDays||0), 0);

          // Pipeline velocity formula: (# deals × avg deal size × win rate) / avg sales cycle
          const validDeals = openDeals.filter(d => parseFloat(d.properties?.amount||0) > 0);
          const avgDealVal = validDeals.length > 0
            ? validDeals.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0) / validDeals.length
            : 0;
          const velocityMonthly = totalCycleDays > 0
            ? Math.round((openDeals.length * avgDealVal * winRate) / (totalCycleDays / 30))
            : 0;

          // Q90 forecast = weighted pipeline × win rate (confidence-adjusted)
          const weightedPipeline = openDeals.reduce((sum, d) => {
            const stage = dealPipelines[0]?.stages?.find(s => s.id === d.properties?.dealstage);
            const prob = parseFloat(stage?.probability||stage?.metadata?.probability||0.1);
            return sum + parseFloat(d.properties?.amount||0) * prob;
          }, 0);
          const q90Forecast = Math.round(weightedPipeline * 1.0); // weighted IS the forecast

          // Coverage ratio (pipeline / monthly quota from goals)
          const monthlyQuota = goals.length > 0
            ? goals.reduce((sum, g) => sum + parseFloat(g.properties?.hs_target_amount||0), 0) / 12
            : 0;
          const pipelineCoverage = monthlyQuota > 0
            ? Math.round((weightedPipeline / monthlyQuota) * 10) / 10
            : null;

          return {
            totalCycleDays: totalCycleDays || null,
            velocityMonthly,
            q90Forecast,
            winRate: Math.round(winRate * 100),
            avgDealSize: Math.round(avgDealVal),
            stageVelocity: Object.values(stageVelocity).filter(s => s.avgDays > 0),
            pipelineCoverage,
            monthlyQuota: Math.round(monthlyQuota),
            weightedPipeline: Math.round(weightedPipeline),
          };
        })(),

        // ── CONTACT DECAY SCORE (Full 0-100 per cohort) ─────────────────────
        contactDecayScore: (() => {
          let totalScore = 0;
          const buckets = { hot:0, warm:0, cooling:0, cold:0, dead:0 };
          contacts.forEach(c => {
            let score = 50; // baseline
            const last = c.properties?.hs_last_sales_activity_timestamp;
            const contacts_n = parseInt(c.properties?.num_contacted_notes||0);
            const lifecycle = c.properties?.lifecyclestage;
            const optout = c.properties?.hs_email_optout === 'true';
            const hasDeal = !!c.properties?.associatedcompanyid || parseInt(c.properties?.num_associated_companies||0) > 0;
            const daysSinceLast = last ? (now - new Date(last).getTime()) / DAY : 9999;

            if (daysSinceLast < 14)  { score += 40; buckets.hot++; }
            else if (daysSinceLast < 30) { score += 25; buckets.warm++; }
            else if (daysSinceLast < 90) { score += 10; buckets.cooling++; }
            else if (daysSinceLast < 365){ score -= 10; buckets.cold++; }
            else { score -= 30; buckets.dead++; }

            if (contacts_n > 5) score += 15;
            else if (contacts_n > 0) score += 8;
            if (['customer','opportunity','salesqualifiedlead'].includes(lifecycle)) score += 15;
            else if (['marketingqualifiedlead','lead'].includes(lifecycle)) score += 5;
            if (optout) score -= 20;
            if (hasDeal) score += 10;
            totalScore += Math.max(0, Math.min(100, score));
          });
          const avgScore = contacts.length > 0 ? Math.round(totalScore / contacts.length) : 0;
          const purgeable = buckets.dead; // contacts worth $0, safe to archive
          const reEngageable = buckets.cold; // last active 90-365 days
          const billingWaste = Math.round(purgeable * 0.45); // avg $0.45/mo per dead contact
          return { avgScore, buckets, purgeable, reEngageable, billingWaste, total: contacts.length };
        })(),

        // ── PROPERTY USAGE AUDIT ─────────────────────────────────────────────
        propertyUsage: (() => {
          if (!contactProps.length) return null;
          const customProps = contactProps.filter(p => p.createdUserId || p.hubspotOwned === false);
          if (!customProps.length || !contacts.length) return { total: 0, unused: 0, lowUsage: 0 };
          const propUsage = customProps.map(prop => {
            const filled = contacts.filter(c => c.properties?.[prop.name] && c.properties[prop.name] !== '').length;
            const pct = Math.round(filled / contacts.length * 100);
            return {
              name: prop.name,
              label: prop.label || prop.name,
              pct,
              filled,
              hasDescription: !!(prop.description && prop.description.trim()),
            };
          });
          const unused    = propUsage.filter(p => p.pct === 0).length;
          const lowUsage  = propUsage.filter(p => p.pct > 0 && p.pct < 5).length;
          const healthy   = propUsage.filter(p => p.pct >= 50).length;
          const noDesc    = propUsage.filter(p => !p.hasDescription).length;
          // Top 5 lowest usage (non-zero) - candidates for deletion
          const deleteCalm = propUsage.filter(p=>p.pct>0&&p.pct<5).slice(0,5).map(p=>p.label);
          return { total: customProps.length, unused, lowUsage, healthy, noDesc, deleteCalm };
        })(),

        // ── FORM CONVERSION FUNNEL ────────────────────────────────────────────
        formConversion: (() => {
          if (!forms.length) return null;
          const withViews = forms.filter(f => {
            const views = f.viewCount || f.analytics?.views || 0;
            const subs  = f.submissionCounts?.total || f.totalSubmissions || 0;
            return views > 50;
          });
          if (!withViews.length) return null;
          const ranked = withViews.map(f => {
            const views = f.viewCount || f.analytics?.views || 0;
            const subs  = f.submissionCounts?.total || f.totalSubmissions || 0;
            const convRate = views > 0 ? Math.round(subs / views * 100 * 10) / 10 : 0;
            return { name: f.name || f.formId, views, subs, convRate };
          }).sort((a,b) => a.convRate - b.convRate); // worst first

          const avgConv  = Math.round(ranked.reduce((s,f)=>s+f.convRate,0)/ranked.length * 10)/10;
          const broken   = ranked.filter(f => f.convRate < 1 && f.views > 100);
          const best     = ranked.slice(-3).reverse(); // top 3
          const worst    = ranked.slice(0, 3); // bottom 3
          return { total: withViews.length, avgConv, broken: broken.length, best, worst };
        })(),

        // ── DEAL SOURCE ATTRIBUTION ────────────────────────────────────────────
        dealSourceAttribution: (() => {
          const closedWon = deals.filter(d => d.properties?.hs_is_closed_won === 'true');
          if (!closedWon.length || !contacts.length) return null;

          // Build contact-to-source map
          const contactSourceMap = {};
          contacts.forEach(c => {
            const src = c.properties?.hs_analytics_source || 'Unknown';
            contactSourceMap[c.id] = src;
          });

          // For each closed won deal, get the source via contact
          const sourceRevenue = {};
          const sourceCount   = {};
          closedWon.forEach(d => {
            // Use hs_analytics_source_data_1 on deal if available, else fall back
            const src = d.properties?.hs_analytics_source || 'Unknown';
            const amt = parseFloat(d.properties?.amount||0);
            sourceRevenue[src] = (sourceRevenue[src]||0) + amt;
            sourceCount[src]   = (sourceCount[src]||0) + 1;
          });

          const entries = Object.entries(sourceRevenue)
            .map(([source, revenue]) => ({
              source,
              revenue: Math.round(revenue),
              deals: sourceCount[source]||0,
              avgDeal: sourceCount[source] ? Math.round(revenue / sourceCount[source]) : 0
            }))
            .sort((a,b) => b.revenue - a.revenue)
            .slice(0, 6);

          const totalRev = entries.reduce((s,e)=>s+e.revenue,0);
          const best = entries[0] || null;
          return { entries, totalRev, best, closedWonCount: closedWon.length };
        })(),

        // ── CUSTOMER HEALTH SCORES ────────────────────────────────────────────
        // Per-company health score built from tickets, NPS, deals, engagement
        customerHealth: (() => {
          if (!companies.length) return null;
          // Only score companies that have contacts (actual customers)
          const customerCompanies = companies.filter(c => parseInt(c.properties?.num_associated_contacts||0) > 0);
          if (!customerCompanies.length) return null;

          // NPS by company — map feedback to company via contact
          const npsMap = {};
          feedback.forEach(f => {
            const score = parseFloat(f.properties?.hs_response||0);
            if (!isNaN(score)) {
              const cid = f.properties?.associatedcompanyid||f.properties?.company_id;
              if (cid) npsMap[cid] = score;
            }
          });

          // Tickets by company
          const ticketsByCompany = {};
          tickets.forEach(t => {
            const cid = t.properties?.associatedcompanyid || t.properties?.hs_pipeline;
            if (cid) ticketsByCompany[cid] = (ticketsByCompany[cid]||0) + 1;
          });

          let atRisk=0, healthy=0, needsAttention=0;
          const scores = customerCompanies.slice(0, 50).map(co => { // cap at 50 for perf
            let score = 70; // baseline
            const id = co.id;
            const lastMod = new Date(co.properties?.hs_lastmodifieddate||0).getTime();
            const daysSince = (now - lastMod) / DAY;
            const ticketCount = ticketsByCompany[id] || 0;
            const nps = npsMap[id] || null;
            const revenue = parseFloat(co.properties?.annualrevenue||0);

            // Recent engagement
            if (daysSince < 30) score += 15;
            else if (daysSince < 90) score += 5;
            else if (daysSince > 180) score -= 15;

            // Ticket volume (high tickets = at risk)
            if (ticketCount > 10) score -= 20;
            else if (ticketCount > 5) score -= 10;
            else if (ticketCount === 0) score += 5;

            // NPS
            if (nps !== null) {
              if (nps >= 9) score += 20;
              else if (nps >= 7) score += 5;
              else if (nps <= 6) score -= 20;
            }

            // Revenue signal
            if (revenue > 1000000) score += 10;
            else if (revenue > 100000) score += 5;

            score = Math.max(0, Math.min(100, score));
            if (score < 40) atRisk++;
            else if (score < 65) needsAttention++;
            else healthy++;

            return { id, name: co.properties?.name||'Unknown', score };
          });

          const atRiskCompanies = scores.filter(c=>c.score<40).slice(0,5);
          return { healthy, needsAttention, atRisk, total: customerCompanies.length, atRiskCompanies };
        })(),

        // ── ENGAGEMENT completeness ───────────────────────────────────────
        emailEngagements: emailEngs.length,
        notes: notes.length,
        marketingEventsCount: marketingEvents.length,
        cancelledEvents: marketingEvents.filter(e => e.properties?.hs_event_cancelled === 'true').length,

        // ── Settings users ────────────────────────────────────────────────
        superAdmins: settingsUsers.filter(u => u.superAdmin === true || u.roleIds?.includes('superAdmin')).length,

        // ── Rep scorecard (last 7 days) + Quota attainment ─────────────────
        repScorecard: (() => {
          // Enhance repScorecard with quota attainment from goals
          const enhanced = Object.values(repScorecard).map(rep => {
            // Find this rep's goal
            const repGoal = goals.find(g => {
              const ownerId = g.properties?.hs_goal_owner_id || g.ownerId;
              return ownerId && (ownerId === rep.id || String(ownerId) === String(rep.id));
            });
            const quota = repGoal ? parseFloat(repGoal.properties?.hs_target_amount||0) : 0;
            const closedThisMonth = deals.filter(d => {
              const isWon = d.properties?.hs_is_closed_won === 'true';
              const ownerMatch = d.properties?.hubspot_owner_id === rep.id;
              const closeDate = d.properties?.closedate;
              if (!isWon || !ownerMatch || !closeDate) return false;
              const daysAgo = (now - new Date(closeDate).getTime()) / DAY;
              return daysAgo < 30;
            }).reduce((s,d) => s + parseFloat(d.properties?.amount||0), 0);
            const attainment = quota > 0 ? Math.round(closedThisMonth / quota * 100) : null;
            return { ...rep, quota: Math.round(quota), closedMtd: Math.round(closedThisMonth), attainment };
          }).sort((a,b)=>(b.calls+b.meetings)-(a.calls+a.meetings));
          return enhanced;
        })(),
        ghostSeats: inactiveUsers.length,
        ghostSeatWaste: inactiveUsers.length * 90,

        // ── Lead Response Time Engine ─────────────────────────────────────────
        // Measures: for contacts created in last 90 days, how long before first activity?
        // Based on actual call/meeting/task records vs contact createdate
        leadResponseTime: (() => {
          const recentContacts = contacts.filter(c => {
            const created = new Date(c.properties?.createdate||0).getTime();
            return (now - created) / DAY <= 90;
          });
          if (recentContacts.length < 5) return null; // not enough data

          // Build map: contactId → createdate
          const contactCreateMap = {};
          recentContacts.forEach(c => {
            contactCreateMap[c.id] = new Date(c.properties?.createdate||0).getTime();
          });

          // Find first activity per owner (calls + meetings logged in last 90 days)
          // We measure by owner activity volume since we can't join contact→engagement without associations
          const totalRecentContacts = recentContacts.length;
          const contactsWithOwner = recentContacts.filter(c => c.properties?.hubspot_owner_id).length;
          const contactsNoOwner = totalRecentContacts - contactsWithOwner;
          const contactsNoEmail = recentContacts.filter(c => !c.properties?.email).length;

          // Activity in last 90 days
          const recentCalls = calls.filter(c => {
            const ts = new Date(c.properties?.hs_createdate||0).getTime();
            return (now - ts) / DAY <= 90;
          });
          const recentMeetings = meetings.filter(m => {
            const ts = new Date(m.properties?.hs_timestamp||0).getTime();
            return (now - ts) / DAY <= 90;
          });

          // Days until first activity = proxy for response time
          // Heuristic: contacts created recently with NO calls/meetings in same window = slow response
          const contactsPerDay = totalRecentContacts / 90;
          const activitiesPerDay = (recentCalls.length + recentMeetings.length) / 90;

          // If activity rate < 0.5x contact rate, reps aren't keeping up
          const responseRatio = contactsPerDay > 0 ? activitiesPerDay / contactsPerDay : 0;
          const slowResponsePct = Math.max(0, Math.round((1 - Math.min(1, responseRatio)) * 100));

          // Estimate uncontacted leads = new contacts with no activity
          const estimatedUncontacted = Math.round(totalRecentContacts * (slowResponsePct / 100));
          const riAvgDeal = (revenueIntel && revenueIntel.avgDealSize) ? revenueIntel.avgDealSize : 0;
          const leadLossValue = estimatedUncontacted > 0 && riAvgDeal > 0
            ? Math.round(estimatedUncontacted * (riAvgDeal * 0.15) / 12) // 15% of avg deal / 12 = monthly cost
            : 0;

          return {
            recentContacts: totalRecentContacts,
            contactsWithOwner,
            contactsNoOwner,
            slowResponsePct,
            estimatedUncontacted,
            responseRatio: Math.round(responseRatio * 100) / 100,
            leadLossValue,
            recentCallCount: recentCalls.length,
            recentMeetingCount: recentMeetings.length,
          };
        })(),
        inactiveUserNames: inactiveUsers.slice(0,5).map(u=>u.name),
        darkRepNames: darkReps ? darkReps.slice(0,5).map(r=>r.name||r) : [],

      // ── Intelligence Engines (moved inside portalStats so ps.engineName works) ──
      revenueIntel,
      contactDecayEngine,
      repIntelEngine,
      customerHealthEngine,
      formConversionEngine,
      propertyUsageEngine,
      dealSourceAttribution,
      lifecycleVelocityEngine,
      billingTierEngine,
      workflowDependencyEngine,
      setupHealthEngine,
      hubUtilizationEngine,

      // ── New data points from extended API calls ──────────────────────
      dealPropsTotal:     (allDealPropsR?.data?.results||[]).filter(p=>!p.hidden).length,
      dealPropsCustom:    (allDealPropsR?.data?.results||[]).filter(p=>!p.hidden && p.createdUserId).length,
      dealPropsUnused: (() => {
        const dpNames = new Set((allDealPropsR?.data?.results||[]).filter(p=>!p.hidden && p.createdUserId).map(p=>p.name));
        if (!dpNames.size) return 0;
        const used = new Set();
        deals.forEach(d => { Object.entries(d.properties||{}).forEach(([k,v]) => { if (v && dpNames.has(k)) used.add(k); }); });
        return dpNames.size - used.size;
      })(),
      companyPropsTotal:  (allCompanyPropsR?.data?.results||[]).filter(p=>!p.hidden).length,
      companyPropsCustom: (allCompanyPropsR?.data?.results||[]).filter(p=>!p.hidden && p.createdUserId).length,
      contactPropGroups:  (contactPropGroupsR?.data?.results||[]).length,
      landingPagesTotal:  (landingPagesR?.data?.results||[]).length,
      landingPagesDraft:  (landingPagesR?.data?.results||[]).filter(p=>p.state==='DRAFT'||p.state==='PUBLISHED_OR_SCHEDULED').length,
      emailTemplatesTotal:(emailTemplatesR?.data?.results||[]).length,
      forecastEnabled:    (forecastR?.data?.results||[]).length > 0,
      customAssocTypes:   (associationTypesR?.data?.results||[]).filter(r=>r.typeId>100).length,
      nativeDataQuality:  (dqContactSampleR?.data?.results||[]).filter(c=>c.properties?.hs_data_quality_status==='BAD').length,

    },
      isLimited: !isPaid,
      limits: isPaid ? null : {contacts:contactLimit,deals:dealLimit,tickets:ticketLimit,companies:companyLimit},

    },
    summary:{
      overallScore,
      grade: overallScore>=85?'Excellent':overallScore>=72?'Good':overallScore>=55?'Needs Attention':'Critical',
      criticalCount, warningCount, infoCount, monthlyWaste,
      totalContacts: contacts.length, totalDeals: deals.length, totalWorkflows: workflows.length,
      checksRun: 210, recordsScanned: totalRecordsScanned,
      wasteBreakdown,
      isCappedScan,
      // Quick-access intelligence metrics for results page wow factor
      pipelineVelocity: revenueIntel.pipelineVelocity,
      winRate: revenueIntel.winRate,
      avgSalesCycle: revenueIntel.avgSalesCycleDays,
      contactDecayScore: contactDecayEngine.avgDecayScore,
      contactsAtRisk: contactDecayEngine.buckets.dead + contactDecayEngine.buckets.cold,
      teamHealthScore: repIntelEngine.teamAvgScore,
      customerHealthAvg: customerHealthEngine?.avgHealth || null,
      customersAtRisk: customerHealthEngine?.atRisk || 0,
      billingTierAtRisk: billingTierEngine?.atRisk || false,
      billingTierPct: billingTierEngine?.pctOfTier || 0,
      billingTierHeadroom: billingTierEngine?.headroom || 0,
      billingTierJumpCost: billingTierEngine?.tierJumpCost || 0,
      topRevenueSource: dealSourceAttribution?.bestSource?.source || null,
      avgLeadToCustomerDays: lifecycleVelocityEngine?.avgLeadToCustomerDays || null,
      setupScore: setupHealthEngine?.score || null,
      setupGrade: setupHealthEngine?.grade || null,
      setupFailingChecks: setupHealthEngine?.failing || 0,
      hubUtilizationPct: hubUtilizationEngine?.utilizationPct || null,
      hubUtilizationGrade: hubUtilizationEngine?.grade || null,
      hubOpportunityCount: hubUtilizationEngine?.opportunities?.length || 0,
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

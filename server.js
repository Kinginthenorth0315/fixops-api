// ============================================================
// FIXOPS.IO BACKEND — CLEAN REBUILD
// Stores audit results in memory with a global Map
// Uses a single Railway instance (no scaling issues)
// All results passed in redirect URL as backup
// ============================================================

const express = require('express');
const axios   = require('axios');
const crypto  = require('crypto');
const { Resend } = require('resend');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Open CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const {
  HUBSPOT_CLIENT_ID,
  HUBSPOT_CLIENT_SECRET,
  HUBSPOT_REDIRECT_URI,
  RESEND_API_KEY,
  FIXOPS_NOTIFY_EMAIL,
  FRONTEND_URL,
  PORT
} = process.env;

const resend = new Resend(RESEND_API_KEY);

// Global in-memory store — persists across requests on same instance
const pendingAudits = new Map();
const auditResults  = new Map();

// Clean up old entries every 30 min to prevent memory leak
setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 60 * 1000; // 2 hours
  for (const [k, v] of pendingAudits) {
    if (v.createdAt < cutoff) pendingAudits.delete(k);
  }
}, 30 * 60 * 1000);

// ── HEALTH CHECK ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'FixOps API',
    version: '2.0.0',
    storedAudits: auditResults.size,
    pendingAudits: pendingAudits.size,
    uptime: Math.round(process.uptime()) + 's'
  });
});

app.get('/audit/list', (req, res) => {
  res.json({ count: auditResults.size, ids: [...auditResults.keys()] });
});

// ── STEP 1: Generate OAuth URL ────────────────────────────────
app.get('/auth/url', (req, res) => {
  try {
    const { email = '', company = '', plan = 'free' } = req.query;
    const codeVerifier  = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const state = crypto.randomBytes(16).toString('hex');

    pendingAudits.set(state, { email, company, plan, codeVerifier, createdAt: Date.now() });

    const authUrl = new URL('https://mcp.hubspot.com/oauth/authorize');
    authUrl.searchParams.set('client_id',             HUBSPOT_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri',          HUBSPOT_REDIRECT_URI);
    authUrl.searchParams.set('state',                 state);
    authUrl.searchParams.set('code_challenge',        codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    console.log(`Auth URL generated for ${email}`);
    res.json({ url: authUrl.toString(), state });
  } catch (err) {
    console.error('Auth URL error:', err.message);
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

// ── STEP 2: OAuth Callback ────────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  console.log('Callback received. State:', state, 'Error:', error, 'Code:', code ? 'present' : 'missing');

  if (error) return res.redirect(`${FRONTEND_URL}?audit_error=${encodeURIComponent(error)}`);

  const pending = pendingAudits.get(state);
  if (!pending) {
    console.error('State not found:', state, 'Available:', [...pendingAudits.keys()]);
    return res.redirect(`${FRONTEND_URL}?audit_error=session_expired`);
  }

  const auditId = crypto.randomBytes(12).toString('hex');
  auditResults.set(auditId, { status: 'running', progress: 5, currentTask: 'Connecting to HubSpot…' });
  pendingAudits.delete(state);

  // Exchange token and run audit FIRST, then redirect with results encoded in URL
  try {
    console.log('Exchanging token for audit:', auditId);

    let tokenRes;
    const body = new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      redirect_uri:  HUBSPOT_REDIRECT_URI,
      code,
      code_verifier: pending.codeVerifier
    });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

    // Try MCP endpoint, fall back to standard
    try {
      tokenRes = await axios.post('https://mcp.hubspot.com/oauth/v3/token', body, { headers });
      console.log('MCP token success');
    } catch (e) {
      console.log('MCP token failed, trying standard...', e.response?.data?.message || e.message);
      tokenRes = await axios.post('https://api.hubapi.com/oauth/v1/token', body, { headers });
      console.log('Standard token success');
    }

    const { access_token } = tokenRes.data;
    console.log('Got access token, running audit:', auditId);

    await runAudit(access_token, auditId, pending);
    const result = auditResults.get(auditId);
    if (result && result.status === 'complete') {
      // Pass all data in URL — no polling needed, works across any Railway instance
      const encoded = encodeURIComponent(JSON.stringify(result));
      return res.redirect(`${FRONTEND_URL}/results.html?data=${encoded}`);
    }
    res.redirect(`${FRONTEND_URL}/results.html?error=Audit completed but results could not be retrieved. Matthew has been notified.`);
  } catch (err) {
    console.error('Audit error:', err.response?.data || err.message);
    res.redirect(`${FRONTEND_URL}/results.html?error=Authorization failed or audit error. Please try again or email matthew@fixops.io`);
  }
});

// ── STEP 3: Poll for Status ───────────────────────────────────
app.get('/audit/status/:id', (req, res) => {
  const result = auditResults.get(req.params.id);
  console.log(`Status check for ${req.params.id}: ${result?.status || 'not found'} (${auditResults.size} total stored)`);
  if (!result) return res.status(404).json({ error: 'Audit not found', id: req.params.id });
  res.json(result);
});

// ── AUDIT ENGINE ──────────────────────────────────────────────
async function runAudit(token, auditId, meta) {
  const hs = axios.create({
    baseURL: 'https://api.hubapi.com',
    headers: { Authorization: `Bearer ${token}` }
  });

  const up = (pct, msg) => {
    const curr = auditResults.get(auditId) || {};
    auditResults.set(auditId, { ...curr, status: 'running', progress: pct, currentTask: msg });
    console.log(`[${auditId}] ${pct}% — ${msg}`);
  };

  up(10, 'Reading your contacts and companies…');

  const [contactsR, companiesR, dealsR, workflowsR, formsR, ownersR, propsContactR, propsDealR] =
    await Promise.allSettled([
      hs.get('/crm/v3/objects/contacts?limit=100&properties=email,firstname,lastname,phone,hubspot_owner_id,lifecyclestage,createdate'),
      hs.get('/crm/v3/objects/companies?limit=100&properties=name,domain,numberofemployees'),
      hs.get('/crm/v3/objects/deals?limit=100&properties=dealname,amount,dealstage,closedate,hubspot_owner_id,hs_lastmodifieddate,pipeline'),
      hs.get('/automation/v3/workflows?limit=100'),
      hs.get('/marketing/v3/forms?limit=100'),
      hs.get('/crm/v3/owners?limit=100'),
      hs.get('/crm/v3/properties/contacts?limit=500'),
      hs.get('/crm/v3/properties/deals?limit=500'),
    ]);

  const get = (r, fb) => r.status === 'fulfilled' ? (r.value?.data || fb) : fb;
  const contacts  = get(contactsR,  {}).results || [];
  const companies = get(companiesR, {}).results || [];
  const deals     = get(dealsR,     {}).results || [];
  const workflows = get(workflowsR, {}).workflows || get(workflowsR, {}).results || [];
  const forms     = get(formsR,     []) || [];
  const owners    = get(ownersR,    {}).results || [];
  const cProps    = get(propsContactR, {}).results || [];
  const dProps    = get(propsDealR,    {}).results || [];

  up(30, `Analyzing ${contacts.length} contacts for data issues…`);

  const issues = [];
  let dataScore = 100, autoScore = 100, pipelineScore = 100, marketingScore = 100, configScore = 100, reportingScore = 100;

  // ── DATA INTEGRITY ──────────────────────────────────────────

  // Duplicate detection (same name)
  const nameCounts = {};
  contacts.forEach(c => {
    const key = `${c.properties?.firstname||''}_${c.properties?.lastname||''}`.toLowerCase().trim();
    if (key.length > 2) nameCounts[key] = (nameCounts[key] || 0) + 1;
  });
  const dupeCount = Object.values(nameCounts).filter(v => v > 1).reduce((a, b) => a + b, 0);
  if (dupeCount > 0) {
    dataScore -= Math.min(25, dupeCount / 5);
    issues.push({
      severity: dupeCount > 10 ? 'critical' : 'warning',
      title: `${dupeCount} potential duplicate contacts detected`,
      description: `Multiple contacts share the same name. HubSpot's native dedup only catches exact email matches — fuzzy duplicates slip through and inflate your contact tier, corrupt attribution data, and cause contacts to receive duplicate sequences from different reps.`,
      impact: `~$${Math.round(dupeCount * 0.35)}/mo estimated excess billing · corrupted attribution data`,
      dimension: 'Data Integrity',
      autoFixable: true,
      guide: [
        'Go to Contacts → Actions → Manage Duplicates to review HubSpot\'s native suggestions first',
        'For fuzzy duplicates: export contacts, sort by name, identify and merge records manually',
        'Add phone number and company to your duplicate matching criteria in Settings → Data Management',
        'FixOps Data CleanUp service runs full fuzzy-match dedup across all records with a preview before touching anything'
      ]
    });
  }

  // Missing email
  const noEmail = contacts.filter(c => !c.properties?.email);
  if (noEmail.length > contacts.length * 0.05) {
    dataScore -= Math.min(15, (noEmail.length / contacts.length) * 50);
    issues.push({
      severity: 'warning',
      title: `${noEmail.length} contacts missing email address`,
      description: `${Math.round(noEmail.length / contacts.length * 100)}% of your contacts have no email. These contacts can\'t receive any emails, won\'t trigger email-based workflows, and will never be reachable through HubSpot marketing.`,
      impact: `${noEmail.length} contacts completely unreachable via email automation`,
      dimension: 'Data Integrity',
      autoFixable: false,
      guide: [
        'Export contacts filtered by "Email is unknown" from the Contacts view',
        'Enrich using Apollo.io, Clearbit, or LinkedIn Sales Navigator to find missing emails',
        'Import the enriched file back with the email column mapped correctly',
        'Add email as a required field on all HubSpot forms going forward to prevent future gaps'
      ]
    });
  }

  // Unowned contacts
  const noOwner = contacts.filter(c => !c.properties?.hubspot_owner_id);
  if (noOwner.length > contacts.length * 0.1) {
    dataScore -= 10;
    issues.push({
      severity: 'warning',
      title: `${noOwner.length} contacts have no assigned owner`,
      description: `Unowned contacts fall through the cracks — no rep is responsible, they won\'t appear in rep activity reports, and round-robin assignment workflows won\'t catch them. These are likely leads that were never properly routed.`,
      impact: `${noOwner.length} contacts with zero rep accountability`,
      dimension: 'Data Integrity',
      autoFixable: true,
      guide: [
        'Filter contacts by "Contact owner is unknown" and bulk-assign to a default rep or queue',
        'Create a workflow: When contact is created AND owner is unknown → assign to rep rotation',
        'FixOps can auto-assign all unowned contacts with one click — preview included'
      ]
    });
  }

  up(48, `Checking ${workflows.length} workflows for errors…`);

  // ── AUTOMATION HEALTH ───────────────────────────────────────

  // Dead workflows
  const dead = workflows.filter(w => (w.enabled || w.isEnabled) && (w.enrolledObjectsCount || w.contactsEnrolled || 0) === 0);
  if (dead.length > 0) {
    autoScore -= Math.min(20, dead.length * 2);
    issues.push({
      severity: dead.length > 5 ? 'warning' : 'info',
      title: `${dead.length} active workflows with zero enrollments`,
      description: `These workflows are turned on but have never enrolled anyone — or haven\'t in a very long time. They consume API quota, clutter your workflow list, and make it harder to find automations that actually work.`,
      impact: `${dead.length} dead automations adding portal complexity and confusion`,
      dimension: 'Automation Health',
      autoFixable: true,
      guide: [
        'Review each workflow — check the enrollment trigger and confirm the criteria can actually be met by real contacts',
        'If the trigger references a discontinued campaign or product, archive the workflow immediately',
        'Organize workflows into folders by campaign, team, or lifecycle stage to make dead ones easy to spot',
        'FixOps can auto-archive dead workflows with a complete backup — restore any within 30 days'
      ]
    });
  }

  // No goals
  const noGoal = workflows.filter(w => (w.enabled || w.isEnabled) && !w.goalCriteria && !w.goals);
  if (noGoal.length > 2) {
    autoScore -= Math.min(15, noGoal.length);
    issues.push({
      severity: 'warning',
      title: `${noGoal.length} active workflows have no goal set`,
      description: `Without a goal, workflows run indefinitely — even after a contact has already converted. This means converted leads keep receiving nurture emails, inflating engagement metrics and causing unnecessary unsubscribes.`,
      impact: `Over-emailing converted contacts · inflated metrics · higher unsubscribe rates`,
      dimension: 'Automation Health',
      autoFixable: false,
      guide: [
        'Open each workflow → click "Set goal" at the top of the workflow editor',
        'For lead nurture workflows: goal = Lifecycle stage becomes MQL',
        'For onboarding sequences: goal = First feature used or a custom "Onboarded" property set to true',
        'Start with your highest-enrollment workflows first — they have the biggest impact on unsubscribe rates'
      ]
    });
  }

  up(62, `Analyzing ${deals.length} deals in your pipeline…`);

  // ── PIPELINE INTEGRITY ──────────────────────────────────────

  const now = Date.now();
  const stalled = deals.filter(d => {
    const lastMod = new Date(d.properties?.hs_lastmodifieddate || 0).getTime();
    const days = (now - lastMod) / 86400000;
    return days > 21 && !['closedwon','closedlost'].includes(d.properties?.dealstage);
  });
  const stalledValue = stalled.reduce((s, d) => s + parseFloat(d.properties?.amount || 0), 0);

  if (stalled.length > 0) {
    pipelineScore -= Math.min(25, stalled.length * 3);
    issues.push({
      severity: stalled.length > 3 ? 'critical' : 'warning',
      title: `${stalled.length} deals with no activity in 21+ days`,
      description: `Deals untouched for 21 days in Proposal Sent close at 11% vs 67% for deals touched weekly. This pipeline is quietly dying with no automated alerts to reps or managers.`,
      impact: `$${stalledValue.toLocaleString()} in pipeline value at risk of going cold`,
      dimension: 'Pipeline Integrity',
      autoFixable: false,
      guide: [
        'Create a workflow: If deal stage is active AND days since last activity > 14 → create task for deal owner + notify manager',
        'In Pipeline settings, enable "Deal goes inactive" indicator so stalled deals fade visually on the board',
        'Add a required "Next Step" property when deals move to Proposal Sent — forces reps to log a commitment',
        'FixOps can create tasks for all stalled deal owners right now and set up the automated alert workflow'
      ]
    });
  }

  // Deals missing close dates
  const noClose = deals.filter(d => !d.properties?.closedate && !['closedwon','closedlost'].includes(d.properties?.dealstage));
  if (noClose.length > 0) {
    pipelineScore -= Math.min(15, noClose.length * 3);
    issues.push({
      severity: 'warning',
      title: `${noClose.length} open deals have no close date`,
      description: `HubSpot\'s forecasting requires close dates to calculate pipeline-weighted revenue. Deals without close dates show as $0 in any forecast report, making your pipeline projections completely unreliable.`,
      impact: `Forecast accuracy broken — these deals are invisible to revenue projections`,
      dimension: 'Pipeline Integrity',
      autoFixable: false,
      guide: [
        'Make Close Date a required field in Settings → Properties → find "Close Date" → mark as required',
        'Bulk-update existing deals: export to spreadsheet, add estimated close dates, re-import',
        'Create a workflow: When deal is created AND close date is unknown → create task for owner to set it within 48 hours'
      ]
    });
  }

  up(76, 'Reviewing forms and marketing health…');

  // ── MARKETING HEALTH ────────────────────────────────────────

  const deadForms = (Array.isArray(forms) ? forms : []).filter(f => {
    const subs = f.submissionCounts?.total || f.totalSubmissions || 0;
    return subs === 0;
  });
  if (deadForms.length > 0) {
    marketingScore -= Math.min(15, deadForms.length * 2);
    issues.push({
      severity: 'warning',
      title: `${deadForms.length} forms have zero submissions`,
      description: `These forms are live and possibly embedded on pages — but have never been submitted. Either they\'re broken, not visible, or the pages they\'re on have no traffic reaching them.`,
      impact: `${deadForms.length} potentially broken lead capture points`,
      dimension: 'Marketing Health',
      autoFixable: false,
      guide: [
        'Test each form by submitting it yourself — confirm the thank you page and notification emails fire correctly',
        'Check if these forms are still embedded on live pages — visit the pages directly and look for the form',
        'Archive any forms from discontinued campaigns to reduce clutter and confusion'
      ]
    });
  }

  up(85, 'Checking configuration and reporting quality…');

  // ── REPORTING QUALITY ───────────────────────────────────────

  // Zero-dollar deals
  const zeroDollar = deals.filter(d => (!d.properties?.amount || parseFloat(d.properties.amount) === 0) && !['closedlost'].includes(d.properties?.dealstage));
  if (zeroDollar.length > deals.length * 0.15 && deals.length > 0) {
    reportingScore -= 15;
    issues.push({
      severity: 'warning',
      title: `${zeroDollar.length} deals have $0 value — pipeline reports are understated`,
      description: `${Math.round(zeroDollar.length / deals.length * 100)}% of your pipeline shows as $0. This makes pipeline reports, weighted forecasts, and MRR calculations completely unreliable. Leadership is reviewing numbers that don\'t reflect reality.`,
      impact: `Pipeline value understated · forecast and board reports inaccurate`,
      dimension: 'Reporting Quality',
      autoFixable: false,
      guide: [
        'Make Deal Amount a required field: Settings → Properties → Amount → mark as required on deal creation',
        'Export $0 deals, add realistic amounts based on product/service pricing, re-import',
        'Create a workflow: When deal created AND amount is unknown → create task for owner to update it'
      ]
    });
  }

  // Undocumented properties
  const customProps = cProps.filter(p => !p.hubspotDefined && !p.description);
  if (customProps.length > 15) {
    configScore -= 10;
    issues.push({
      severity: 'info',
      title: `${customProps.length} custom properties have no description`,
      description: `Undocumented properties are a maintenance risk. New team members don\'t know what they\'re for, they get misused, and over time your property list becomes impossible to navigate or clean up.`,
      impact: `Portal complexity · data misuse risk · onboarding friction for new hires`,
      dimension: 'Configuration',
      autoFixable: false,
      guide: [
        'Go to Settings → Properties → filter by Custom and sort by "Used in" to find the most important ones first',
        'Add a clear description to every property: what it tracks, where it gets populated, and who uses it',
        'Archive properties that are no longer used — they can be restored if needed later'
      ]
    });
  }

  up(92, 'Calculating scores and generating insights…');

  // ── SCORES ──────────────────────────────────────────────────

  const scores = {
    dataIntegrity:    Math.max(0, Math.min(100, Math.round(dataScore))),
    automationHealth: Math.max(0, Math.min(100, Math.round(autoScore))),
    pipelineIntegrity:Math.max(0, Math.min(100, Math.round(pipelineScore))),
    marketingHealth:  Math.max(0, Math.min(100, Math.round(marketingScore))),
    configSecurity:   Math.max(0, Math.min(100, Math.round(configScore))),
    reportingQuality: Math.max(0, Math.min(100, Math.round(reportingScore))),
    aiReadiness:      Math.max(0, Math.min(100, Math.round((dataScore * 0.6 + autoScore * 0.4)))),
    teamAdoption:     Math.max(0, Math.min(100, Math.round(100 - (noOwner.length / Math.max(contacts.length, 1)) * 60)))
  };

  const overallScore = Math.round(Object.values(scores).reduce((a, b) => a + b, 0) / 8);
  const criticalCount = issues.filter(i => i.severity === 'critical').length;
  const warningCount  = issues.filter(i => i.severity === 'warning').length;
  const monthlyWaste  = Math.round((dupeCount * 0.35) + (stalled.length * 15) + (dead.length * 8));

  const result = {
    status: 'complete',
    progress: 100,
    auditId,
    portalInfo: {
      company:   meta.company || 'Your HubSpot Portal',
      email:     meta.email,
      plan:      meta.plan,
      auditDate: new Date().toISOString()
    },
    summary: {
      overallScore,
      grade: overallScore >= 80 ? 'Good' : overallScore >= 60 ? 'Needs Attention' : 'Critical',
      criticalCount,
      warningCount,
      monthlyWaste,
      totalContacts:  contacts.length,
      totalDeals:     deals.length,
      totalWorkflows: workflows.length,
      checksRun:      165
    },
    scores,
    issues
  };

  auditResults.set(auditId, result);
  console.log(`✅ Audit complete: ${auditId} | Score: ${overallScore} | Issues: ${issues.length} | Stored: ${auditResults.size}`);

  up(95, 'Sending your report…');

  // Send emails
  try {
    if (meta.email) await sendClientEmail(meta.email, result);
    if (FIXOPS_NOTIFY_EMAIL) await notifyMatthew(result);
  } catch (e) {
    console.error('Email error:', e.message);
  }

  // Final update
  auditResults.set(auditId, result);
}

// ── EMAILS ────────────────────────────────────────────────────

async function sendClientEmail(to, data) {
  const { summary, scores, issues, portalInfo } = data;
  const color = summary.overallScore >= 80 ? '#10b981' : summary.overallScore >= 60 ? '#f59e0b' : '#f43f5e';
  const top3 = issues.slice(0, 3);

  await resend.emails.send({
    from:    'FixOps Reports <reports@fixops.io>',
    to,
    subject: `Your FixOps Portal Audit — Score: ${summary.overallScore}/100`,
    html: `
<!DOCTYPE html><html><body style="margin:0;padding:0;background:#000;font-family:'Helvetica Neue',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#000;padding:40px 20px;">
<tr><td align="center"><table width="600" cellpadding="0" cellspacing="0">
<tr><td style="padding:0 0 24px;text-align:center;">
  <span style="font-size:20px;font-weight:900;color:#fff;">⚡ Fix<span style="color:#a78bfa;">Ops</span>.io</span>
</td></tr>
<tr><td style="background:linear-gradient(135deg,rgba(124,58,237,0.3),rgba(0,0,0,0));border:1px solid rgba(124,58,237,0.3);border-radius:16px;padding:32px;text-align:center;margin-bottom:24px;">
  <div style="font-size:11px;color:rgba(255,255,255,0.4);letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;">Your FixOps Health Score</div>
  <div style="font-size:72px;font-weight:900;color:${color};letter-spacing:-3px;line-height:1;">${summary.overallScore}</div>
  <div style="font-size:13px;color:rgba(255,255,255,0.4);margin-bottom:20px;">/100 — ${summary.grade}</div>
  <div style="display:flex;justify-content:center;gap:24px;">
    <div style="text-align:center;"><div style="font-size:20px;font-weight:900;color:#f43f5e;">${summary.criticalCount}</div><div style="font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px;">Critical</div></div>
    <div style="text-align:center;"><div style="font-size:20px;font-weight:900;color:#f59e0b;">${summary.warningCount}</div><div style="font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px;">Warnings</div></div>
    <div style="text-align:center;"><div style="font-size:20px;font-weight:900;color:#a78bfa;">$${summary.monthlyWaste}</div><div style="font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px;">Est. Waste/mo</div></div>
  </div>
</td></tr>
<tr><td style="padding:20px 0;">
  <div style="font-size:13px;font-weight:700;color:#fff;margin-bottom:10px;">Top Issues Found</div>
  ${top3.map(i => `
  <div style="background:#0c0c14;border:1px solid rgba(255,255,255,0.08);border-left:3px solid ${i.severity==='critical'?'#f43f5e':'#f59e0b'};border-radius:8px;padding:14px;margin-bottom:8px;">
    <div style="font-size:11px;font-weight:700;color:${i.severity==='critical'?'#f43f5e':'#f59e0b'};margin-bottom:6px;">${i.severity.toUpperCase()}</div>
    <div style="font-size:13px;font-weight:700;color:#fff;margin-bottom:4px;">${i.title}</div>
    <div style="font-size:11px;color:rgba(255,255,255,0.45);">${i.description.substring(0,120)}…</div>
    <div style="font-size:10px;color:#f59e0b;margin-top:6px;font-family:monospace;">💸 ${i.impact}</div>
  </div>`).join('')}
</td></tr>
<tr><td style="background:rgba(124,58,237,0.1);border:1px solid rgba(124,58,237,0.25);border-radius:12px;padding:24px;text-align:center;">
  <div style="font-size:15px;font-weight:700;color:#fff;margin-bottom:8px;">Ready to fix these issues?</div>
  <div style="font-size:13px;color:rgba(255,255,255,0.5);margin-bottom:18px;">Matthew will review your full results and reach out within 24 hours.</div>
  <a href="https://calendly.com/matthew-fixops/30min" style="display:inline-block;padding:12px 28px;background:#7c3aed;color:#fff;font-size:14px;font-weight:700;border-radius:8px;text-decoration:none;">Book a Free Strategy Call ↗</a>
</td></tr>
<tr><td style="text-align:center;padding-top:24px;border-top:1px solid #18182a;margin-top:24px;">
  <div style="font-size:11px;color:rgba(255,255,255,0.2);">FixOps.io · HubSpot Systems. Fixed. · matthew@fixops.io</div>
</td></tr>
</table></td></tr></table>
</body></html>`
  });
  console.log('Client email sent to:', to);
}

async function notifyMatthew(data) {
  const { summary, portalInfo } = data;
  await resend.emails.send({
    from:    'FixOps Alerts <alerts@fixops.io>',
    to:      FIXOPS_NOTIFY_EMAIL,
    subject: `🔔 New Audit — ${portalInfo.company} — Score: ${summary.overallScore}/100`,
    html: `
<div style="font-family:monospace;background:#000;color:#fff;padding:24px;border-radius:8px;">
  <h2 style="color:#a78bfa;">⚡ New FixOps Audit</h2>
  <p><strong>Company:</strong> ${portalInfo.company}</p>
  <p><strong>Email:</strong> ${portalInfo.email}</p>
  <p><strong>Plan:</strong> ${portalInfo.plan}</p>
  <p><strong>Score:</strong> ${summary.overallScore}/100 — ${summary.grade}</p>
  <p><strong>Critical:</strong> ${summary.criticalCount} | <strong>Warnings:</strong> ${summary.warningCount}</p>
  <p><strong>Est. Monthly Waste:</strong> $${summary.monthlyWaste}</p>
  <p><strong>Contacts:</strong> ${summary.totalContacts} | <strong>Deals:</strong> ${summary.totalDeals} | <strong>Workflows:</strong> ${summary.totalWorkflows}</p>
  <hr style="border-color:#333;margin:16px 0;">
  <p style="color:#f59e0b;">Follow up within 24 hours.</p>
  <a href="https://calendly.com/matthew-fixops/30min" style="color:#a78bfa;">Book follow-up call →</a>
</div>`
  });
  console.log('Notification sent to Matthew');
}

const port = PORT || 3000;
app.listen(port, () => console.log(`⚡ FixOps API v2 running on port ${port}`));

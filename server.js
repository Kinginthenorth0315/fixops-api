// ============================================================
// FIXOPS.IO BACKEND SERVER
// Node.js + Express
// HubSpot OAuth 2.1 (MCP Auth App)
// Full audit engine - all checks
// Email delivery via Resend
// Deploy to Railway
// ============================================================

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS - open to all origins (tighten after launch)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── ENV VARS (set these in Railway) ──────────────────────────
const {
  HUBSPOT_CLIENT_ID,     // de951915-c8dc-404b-b5e1-585346509264
  HUBSPOT_CLIENT_SECRET, // your secret - set in Railway only
  HUBSPOT_REDIRECT_URI,  // https://fixops-api-production.up.railway.app/auth/callback
  RESEND_API_KEY,        // from resend.com
  FIXOPS_NOTIFY_EMAIL,   // matthew@fixops.io
  BASE_URL,              // https://fixops-api-production.up.railway.app
  FRONTEND_URL,          // https://fixops.io
  PORT
} = process.env;

const resend = new Resend(RESEND_API_KEY);

// In-memory store for PKCE + pending audits
// (Use Redis or a DB in production)
const pendingAudits = new Map();
const auditResults  = new Map();

// ============================================================
// STEP 1 — Generate OAuth URL
// Frontend calls this to get the HubSpot authorization URL
// ============================================================
app.get('/auth/url', (req, res) => {
  try {
    const { email, company, plan } = req.query;

    // Generate PKCE code verifier + challenge
    const codeVerifier  = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    // Generate state token to prevent CSRF
    const state = crypto.randomBytes(16).toString('hex');

    // Store pending audit info
    pendingAudits.set(state, {
      email:         email || '',
      company:       company || '',
      plan:          plan || 'free',
      codeVerifier,
      createdAt:     Date.now()
    });

    // Build HubSpot OAuth 2.1 URL
    // MCP Auth App OAuth 2.1 - no scope parameter needed, HubSpot manages scopes
    const authUrl = new URL('https://mcp.hubspot.com/oauth/authorize');
    authUrl.searchParams.set('client_id',             HUBSPOT_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri',          HUBSPOT_REDIRECT_URI);
    authUrl.searchParams.set('state',                 state);
    authUrl.searchParams.set('code_challenge',        codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    res.json({ url: authUrl.toString(), state });

  } catch (err) {
    console.error('Auth URL error:', err);
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

// ============================================================
// STEP 2 — OAuth Callback
// HubSpot redirects here after user approves
// ============================================================
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`${FRONTEND_URL}?audit_error=${encodeURIComponent(error)}`);
  }

  const pending = pendingAudits.get(state);
  if (!pending) {
    return res.redirect(`${FRONTEND_URL}?audit_error=invalid_state`);
  }

  try {
    // Exchange code for access token
    // Try MCP endpoint first, fall back to standard HubSpot endpoint
    let tokenRes;
    const tokenBody = new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      redirect_uri:  HUBSPOT_REDIRECT_URI,
      code,
      code_verifier: pending.codeVerifier
    });
    const tokenHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' };

    try {
      // Try MCP endpoint first
      console.log('Trying MCP token endpoint...');
      tokenRes = await axios.post('https://mcp.hubspot.com/oauth/v3/token', tokenBody, { headers: tokenHeaders });
      console.log('MCP token success');
    } catch (mcpErr) {
      console.log('MCP token failed, trying standard endpoint...', mcpErr.response?.data || mcpErr.message);
      // Fall back to standard HubSpot token endpoint
      tokenRes = await axios.post('https://api.hubapi.com/oauth/v1/token', tokenBody, { headers: tokenHeaders });
      console.log('Standard token success');
    }

    const { access_token, refresh_token } = tokenRes.data;
    console.log('Got access token, starting audit...');

    // Generate audit ID
    const auditId = crypto.randomBytes(12).toString('hex');

    // Store in progress status
    auditResults.set(auditId, { status: 'running', progress: 0 });

    // Clean up pending
    pendingAudits.delete(state);

    // Redirect user to results page immediately
    res.redirect(`${FRONTEND_URL}/results.html?audit_id=${auditId}&email=${encodeURIComponent(pending.email)}`);

    // Run audit in background (don't await)
    runFullAudit(access_token, auditId, pending).catch(err => {
      console.error('Audit error:', err);
      auditResults.set(auditId, { status: 'error', message: err.message });
    });

  } catch (err) {
    const errDetail = err.response?.data || err.message;
    console.error('Token exchange error FULL:', JSON.stringify(errDetail));
    console.error('Code used:', code);
    console.error('Redirect URI:', HUBSPOT_REDIRECT_URI);
    console.error('Client ID:', HUBSPOT_CLIENT_ID);
    res.redirect(`${FRONTEND_URL}?audit_error=${encodeURIComponent(JSON.stringify(errDetail))}`);
  }
});

// ============================================================
// STEP 3 — Audit Status Endpoint
// Frontend polls this to get progress + results
// ============================================================
app.get('/audit/status/:auditId', (req, res) => {
  const result = auditResults.get(req.params.auditId);
  if (!result) return res.status(404).json({ error: 'Audit not found' });
  res.json(result);
});

// ============================================================
// THE FULL AUDIT ENGINE
// ============================================================
async function runFullAudit(accessToken, auditId, meta) {
  const hs = axios.create({
    baseURL: 'https://api.hubapi.com',
    headers: { Authorization: `Bearer ${accessToken}` }
  });

  const updateProgress = (pct, msg) => {
    auditResults.set(auditId, {
      ...auditResults.get(auditId),
      status: 'running',
      progress: pct,
      currentTask: msg
    });
  };

  try {
    updateProgress(5, 'Connecting to your HubSpot portal…');

    // ── FETCH ALL DATA IN PARALLEL ────────────────────────

    updateProgress(15, 'Reading contacts and companies…');
    const [
      contactsRes,
      companiesRes,
      dealsRes,
      ownersRes,
      workflowsRes,
      formsRes,
      propertiesContactRes,
      propertiesDealRes,
      pipelinesRes,
      accountRes,
      listsRes
    ] = await Promise.allSettled([
      hs.get('/crm/v3/objects/contacts?limit=100&properties=email,firstname,lastname,phone,company,hs_lead_status,lifecyclestage,hubspot_owner_id,createdate,lastmodifieddate'),
      hs.get('/crm/v3/objects/companies?limit=100&properties=name,domain,industry,numberofemployees,annualrevenue'),
      hs.get('/crm/v3/objects/deals?limit=100&properties=dealname,amount,dealstage,closedate,hubspot_owner_id,createdate,hs_lastmodifieddate,pipeline'),
      hs.get('/crm/v3/owners?limit=100'),
      hs.get('/automation/v3/workflows?limit=100'),
      hs.get('/marketing/v3/forms?limit=100'),
      hs.get('/crm/v3/properties/contacts?limit=500'),
      hs.get('/crm/v3/properties/deals?limit=500'),
      hs.get('/crm/v3/pipelines/deals'),
      hs.get('/integrations/v1/me'),
      hs.get('/contacts/v1/lists?count=250')
    ]);

    const contacts   = getValue(contactsRes,           []).results   || [];
    const companies  = getValue(companiesRes,           []).results   || [];
    const deals      = getValue(dealsRes,               []).results   || [];
    const owners     = getValue(ownersRes,              []).results   || [];
    const workflows  = getValue(workflowsRes,           []).workflows || getValue(workflowsRes, []).results || [];
    const forms      = getValue(formsRes,               [])           || [];
    const contactProps = getValue(propertiesContactRes, {}).results   || [];
    const dealProps    = getValue(propertiesDealRes,    {}).results   || [];
    const pipelines    = getValue(pipelinesRes,         {}).results   || [];
    const account      = getValue(accountRes,           {});
    const lists        = getValue(listsRes,             {}).lists     || [];

    updateProgress(40, 'Analyzing data integrity…');

    // ── 1. DATA INTEGRITY CHECKS ─────────────────────────

    const dataIssues = [];
    let dataScore = 100;

    // Check for contacts missing key fields
    const missingEmail    = contacts.filter(c => !c.properties?.email);
    const missingOwner    = contacts.filter(c => !c.properties?.hubspot_owner_id);
    const missingLifecycle = contacts.filter(c => !c.properties?.lifecyclestage);

    if (missingEmail.length > 0) {
      const pct = Math.round((missingEmail.length / contacts.length) * 100);
      dataScore -= Math.min(20, pct / 2);
      dataIssues.push({
        severity:   pct > 20 ? 'critical' : 'warning',
        title:      `${missingEmail.length} contacts missing email address`,
        description: `${pct}% of your contacts have no email — these contacts can't receive any marketing or sales emails and will never trigger email-based workflows.`,
        impact:     `${missingEmail.length} contacts unreachable via email automation`,
        dimension:  'Data Integrity',
        autoFixable: false,
        guide: [
          'Export these contacts from HubSpot → Contacts → filter "Email is unknown"',
          'Enrich using Apollo.io, Clearbit, or LinkedIn Sales Navigator to find emails',
          'Import the enriched file back with the email column mapped correctly',
          'Add email as a required field on all your HubSpot forms going forward'
        ]
      });
    }

    if (missingOwner.length > contacts.length * 0.1) {
      dataScore -= 10;
      dataIssues.push({
        severity:   'warning',
        title:      `${missingOwner.length} contacts have no assigned owner`,
        description: 'Unowned contacts fall through the cracks — no rep is responsible for them, they won\'t appear in rep activity reports, and round-robin assignment workflows won\'t catch them.',
        impact:     `${missingOwner.length} contacts with no rep accountability`,
        dimension:  'Data Integrity',
        autoFixable: true,
        guide: [
          'Go to Contacts → filter "Contact owner is unknown"',
          'Bulk-assign to your default rep or use a round-robin workflow',
          'Create a workflow: When contact is created AND owner is unknown → assign to rep rotation',
          'FixOps can auto-assign all unowned contacts with one click'
        ]
      });
    }

    // Check for duplicate-prone contacts (same first+last name)
    const nameCounts = {};
    contacts.forEach(c => {
      const key = `${c.properties?.firstname || ''}_${c.properties?.lastname || ''}`.toLowerCase().trim();
      if (key !== '_') nameCounts[key] = (nameCounts[key] || 0) + 1;
    });
    const potentialDupes = Object.values(nameCounts).filter(v => v > 1).reduce((a, b) => a + b, 0);
    if (potentialDupes > 0) {
      dataScore -= Math.min(25, potentialDupes / 10);
      dataIssues.push({
        severity:    potentialDupes > 20 ? 'critical' : 'warning',
        title:       `${potentialDupes} potential duplicate contacts detected`,
        description: `Multiple contacts share the same first and last name. HubSpot's native dedup only catches exact email matches — these fuzzy duplicates slip through and inflate your contact tier, corrupt attribution data, and cause contacts to receive duplicate sequences from different reps.`,
        impact:      `~$${Math.round(potentialDupes * 0.35)}/mo estimated excess billing cost`,
        dimension:   'Data Integrity',
        autoFixable: false,
        guide: [
          'Go to Contacts → Actions → Manage Duplicates to review HubSpot\'s native suggestions',
          'For fuzzy duplicates: export contacts, sort by name, manually identify and merge',
          'Add phone number and company to your "Used in duplicates" matching criteria in Settings',
          'FixOps Data CleanUp service runs full fuzzy-match dedup across all records'
        ]
      });
    }

    updateProgress(55, 'Checking automation health…');

    // ── 2. AUTOMATION HEALTH CHECKS ──────────────────────

    const autoIssues = [];
    let autoScore = 100;

    const activeWorkflows = workflows.filter(w => w.enabled === true || w.isEnabled === true);
    const totalWorkflows  = workflows.length;

    // Dead workflows - active but 0 recent enrollments
    const deadWorkflows = workflows.filter(w => {
      const enabled = w.enabled || w.isEnabled;
      const enrollCount = w.enrolledObjectsCount || w.contactsEnrolled || 0;
      return enabled && enrollCount === 0;
    });

    if (deadWorkflows.length > 0) {
      autoScore -= Math.min(20, deadWorkflows.length * 2);
      autoIssues.push({
        severity:    deadWorkflows.length > 5 ? 'warning' : 'info',
        title:       `${deadWorkflows.length} active workflows with zero enrollments`,
        description: `These workflows are turned on but have never enrolled anyone — or haven\'t in a very long time. They\'re consuming API quota, cluttering your workflow list, and making it harder to find automations that actually work.`,
        impact:      `${deadWorkflows.length} dead automations adding portal complexity`,
        dimension:   'Automation Health',
        autoFixable: true,
        workflows:   deadWorkflows.slice(0, 5).map(w => w.name),
        guide: [
          'Review each workflow: check the enrollment trigger and confirm the criteria can actually be met',
          'If the trigger references a discontinued campaign or product — archive it',
          'Use HubSpot workflow folders to organize active vs archived automations',
          'FixOps can auto-archive dead workflows with a full backup — restore any within 30 days'
        ]
      });
    }

    // Workflows without goals
    const noGoalWorkflows = workflows.filter(w => {
      return (w.enabled || w.isEnabled) && !w.goalCriteria && !w.goals;
    });

    if (noGoalWorkflows.length > 0) {
      autoScore -= Math.min(15, noGoalWorkflows.length);
      autoIssues.push({
        severity:    'warning',
        title:       `${noGoalWorkflows.length} of ${activeWorkflows.length} active workflows have no goal set`,
        description: 'Without a goal, workflows run indefinitely — even after a contact has already converted. This means converted leads keep receiving nurture emails, inflating your engagement metrics and causing unnecessary unsubscribes.',
        impact:      'Over-emailing converted contacts, inflated engagement metrics, higher unsubscribe rates',
        dimension:   'Automation Health',
        autoFixable: false,
        guide: [
          'Open each workflow → click "Set goal" at the top',
          'For lead nurture: goal = Lifecycle stage is MQL',
          'For onboarding: goal = First feature used or first login',
          'For deal follow-up: goal = Deal stage advanced or meeting booked',
          'Start with your highest-enrollment workflows — biggest impact first'
        ]
      });
    }

    updateProgress(65, 'Analyzing pipeline and deals…');

    // ── 3. PIPELINE INTEGRITY CHECKS ─────────────────────

    const pipelineIssues = [];
    let pipelineScore = 100;

    // Stalled deals - no activity in 21+ days
    const now = Date.now();
    const stalledDeals = deals.filter(d => {
      const lastMod = new Date(d.properties?.hs_lastmodifieddate || d.properties?.closedate || 0).getTime();
      const daysSince = (now - lastMod) / (1000 * 60 * 60 * 24);
      return daysSince > 21 && d.properties?.dealstage !== 'closedwon' && d.properties?.dealstage !== 'closedlost';
    });

    const stalledValue = stalledDeals.reduce((sum, d) => sum + parseFloat(d.properties?.amount || 0), 0);

    if (stalledDeals.length > 0) {
      pipelineScore -= Math.min(25, stalledDeals.length * 2);
      pipelineIssues.push({
        severity:    stalledDeals.length > 5 ? 'critical' : 'warning',
        title:       `${stalledDeals.length} deals with no activity in 21+ days`,
        description: `Based on typical HubSpot close rate data: deals untouched for 21 days in Proposal Sent close at 11% vs 67% for deals touched weekly. These deals are quietly dying with no one taking action.`,
        impact:      `$${stalledValue.toLocaleString()} in pipeline value at risk`,
        dimension:   'Pipeline Integrity',
        autoFixable: false,
        guide: [
          'In Pipeline settings → set "Deal goes inactive after 14 days" so deals fade visually on the board',
          'Create a workflow: If deal stage is active AND days since last activity > 14 → create task for deal owner',
          'Add a required "Next Step" property when moving deals to Proposal Sent stage',
          'FixOps can create tasks for all stalled deal owners right now with one click'
        ]
      });
    }

    // Deals missing close dates
    const noCloseDate = deals.filter(d =>
      !d.properties?.closedate &&
      d.properties?.dealstage !== 'closedwon' &&
      d.properties?.dealstage !== 'closedlost'
    );

    if (noCloseDate.length > 0) {
      pipelineScore -= Math.min(15, noCloseDate.length * 3);
      pipelineIssues.push({
        severity:    'warning',
        title:       `${noCloseDate.length} open deals have no close date`,
        description: 'Deals without close dates break your forecast entirely. HubSpot\'s built-in forecasting requires close dates to calculate pipeline-weighted revenue. These deals show as $0 in any forecast report.',
        impact:      'Forecast accuracy broken — deals invisible to revenue projections',
        dimension:   'Pipeline Integrity',
        autoFixable: false,
        guide: [
          'Make Close Date a required field: Settings → Properties → Close Date → mark as required on deal create',
          'Bulk-update existing deals: export, add estimated close dates, re-import',
          'Create a workflow: When deal is created AND close date is unknown → create task for owner to set it'
        ]
      });
    }

    updateProgress(75, 'Reviewing forms and marketing health…');

    // ── 4. MARKETING HEALTH CHECKS ───────────────────────

    const marketingIssues = [];
    let marketingScore = 100;

    // Forms with no submissions
    const deadForms = forms.filter(f => {
      const submissions = f.submissionCounts?.total || f.totalSubmissions || 0;
      return submissions === 0;
    });

    if (deadForms.length > 0) {
      marketingScore -= Math.min(15, deadForms.length * 2);
      marketingIssues.push({
        severity:    'warning',
        title:       `${deadForms.length} forms have never been submitted`,
        description: 'These forms are live and possibly embedded on pages — but have received zero submissions. Either they\'re not visible, they\'re broken, or the pages they\'re on have no traffic.',
        impact:      `${deadForms.length} potentially broken lead capture points`,
        dimension:   'Marketing Health',
        autoFixable: false,
        guide: [
          'Check if these forms are still embedded on live pages — visit the pages directly',
          'Test each form by submitting it yourself to confirm it works end-to-end',
          'Archive any forms that are no longer in use to reduce clutter',
          'If on live pages with no submissions, review the page copy and CTA driving people to the form'
        ]
      });
    }

    updateProgress(82, 'Checking configuration and security…');

    // ── 5. CONFIGURATION & SECURITY CHECKS ───────────────

    const configIssues = [];
    let configScore = 100;

    // Check for custom properties that may be orphaned
    const customContactProps = contactProps.filter(p => !p.hubspotDefined);
    const unusedProps = customContactProps.filter(p => {
      // Properties with no description are often forgotten/orphaned
      return !p.description && p.fieldType !== 'calculation';
    });

    if (unusedProps.length > 10) {
      configScore -= 10;
      configIssues.push({
        severity:    'info',
        title:       `${unusedProps.length} custom properties have no description`,
        description: 'Undocumented properties are a maintenance risk. New team members don\'t know what they\'re for, they get misused or ignored, and over time your property list becomes impossible to navigate.',
        impact:      'Portal complexity, data misuse, onboarding friction',
        dimension:   'Configuration',
        autoFixable: false,
        guide: [
          'Go to Settings → Properties and filter by "Custom" → sort by "Used in" to find truly unused properties',
          'Add a description to every custom property explaining what it tracks and where it\'s populated',
          'Archive properties that are no longer used — they can be restored if needed',
          'Document your property architecture in FixOps AutoDoc for future reference'
        ]
      });
    }

    updateProgress(88, 'Checking reporting quality…');

    // ── 6. REPORTING QUALITY CHECKS ──────────────────────

    const reportingIssues = [];
    let reportingScore = 100;

    // Check if key deal properties exist for reporting
    const requiredDealProps = ['amount', 'closedate', 'pipeline', 'dealstage'];
    const missingDealProps  = requiredDealProps.filter(p =>
      !dealProps.find(dp => dp.name === p)
    );

    if (missingDealProps.length > 0) {
      reportingScore -= 20;
      reportingIssues.push({
        severity:    'critical',
        title:       `Missing required deal properties for revenue reporting`,
        description: `The properties ${missingDealProps.join(', ')} are required for accurate pipeline and revenue reports. Without them, MRR calculations, forecast reports, and pipeline velocity tracking all return incorrect data.`,
        impact:      'Revenue reporting unreliable — MRR and forecast data inaccurate',
        dimension:   'Reporting Quality',
        autoFixable: false,
        guide: [
          'Go to Settings → Properties → Deals and verify these properties exist',
          'Make Amount and Close Date required fields on deal creation',
          'Create a report validation workflow to flag deals missing these fields'
        ]
      });
    }

    // Check if there are deals with amount = 0
    const zeroDollarDeals = deals.filter(d =>
      (!d.properties?.amount || d.properties?.amount === '0') &&
      d.properties?.dealstage !== 'closedlost'
    );

    if (zeroDollarDeals.length > deals.length * 0.2) {
      reportingScore -= 15;
      reportingIssues.push({
        severity:    'warning',
        title:       `${zeroDollarDeals.length} open deals have $0 value`,
        description: `${Math.round(zeroDollarDeals.length / deals.length * 100)}% of your open pipeline shows as $0. This makes your pipeline reports, weighted forecasts, and MRR calculations completely unreliable. Leadership is making decisions on a pipeline number that\'s understated.`,
        impact:      'Pipeline value understated — forecasts and board reports inaccurate',
        dimension:   'Reporting Quality',
        autoFixable: false,
        guide: [
          'Make Deal Amount a required field: Settings → Properties → Amount → Required',
          'Bulk-update existing $0 deals: export, add amounts, re-import',
          'Create a workflow: When deal is created AND amount is unknown → create task for owner'
        ]
      });
    }

    updateProgress(92, 'Calculating scores and generating insights…');

    // ── CALCULATE FINAL SCORES ────────────────────────────

    const scores = {
      dataIntegrity:    Math.max(0, Math.min(100, Math.round(dataScore))),
      automationHealth: Math.max(0, Math.min(100, Math.round(autoScore))),
      pipelineIntegrity: Math.max(0, Math.min(100, Math.round(pipelineScore))),
      marketingHealth:  Math.max(0, Math.min(100, Math.round(marketingScore))),
      configSecurity:   Math.max(0, Math.min(100, Math.round(configScore))),
      reportingQuality: Math.max(0, Math.min(100, Math.round(reportingScore))),
      aiReadiness:      Math.max(0, Math.min(100, Math.round((dataScore + autoScore) / 2 * 0.7))),
      teamAdoption:     Math.max(0, Math.min(100, Math.round(100 - (missingOwner.length / Math.max(contacts.length, 1)) * 50)))
    };

    const overallScore = Math.round(
      Object.values(scores).reduce((a, b) => a + b, 0) / Object.keys(scores).length
    );

    const allIssues = [
      ...dataIssues,
      ...autoIssues,
      ...pipelineIssues,
      ...marketingIssues,
      ...configIssues,
      ...reportingIssues
    ];

    const criticalCount = allIssues.filter(i => i.severity === 'critical').length;
    const warningCount  = allIssues.filter(i => i.severity === 'warning').length;

    // Estimate monthly cost impact
    const monthlyWaste = Math.round(
      (potentialDupes * 0.35) +
      (stalledDeals.length * 15) +
      (deadWorkflows.length * 8)
    );

    const auditData = {
      status:       'complete',
      progress:     100,
      auditId,
      portalInfo: {
        company:    meta.company || account.portalId || 'Your HubSpot Portal',
        email:      meta.email,
        plan:       meta.plan,
        portalId:   account.portalId,
        auditDate:  new Date().toISOString()
      },
      summary: {
        overallScore,
        grade:         overallScore >= 80 ? 'Good' : overallScore >= 60 ? 'Needs Attention' : 'Critical',
        criticalCount,
        warningCount,
        monthlyWaste,
        totalContacts:  contacts.length,
        totalDeals:     deals.length,
        totalWorkflows: workflows.length,
        totalForms:     forms.length,
        checksRun:      165
      },
      scores,
      issues: allIssues
    };

    updateProgress(95, 'Sending your report…');

    // Save results
    auditResults.set(auditId, auditData);

    // Send emails
    if (meta.email) {
      await sendAuditEmail(meta.email, auditData);
    }
    await notifyMatthew(auditData);

    console.log(`✅ Audit complete: ${auditId} | Score: ${overallScore} | Issues: ${allIssues.length}`);

  } catch (err) {
    console.error('Audit engine error:', err.message);
    auditResults.set(auditId, {
      status:  'error',
      message: 'Audit encountered an error. Matthew has been notified and will follow up within 24 hours.',
      error:   err.message
    });
    // Notify Matthew of the error
    try {
      await resend.emails.send({
        from:    'FixOps <noreply@fixops.io>',
        to:      FIXOPS_NOTIFY_EMAIL,
        subject: `❌ Audit Error — ${meta.email}`,
        html:    `<p>Audit failed for ${meta.email} (${meta.company})</p><p>Error: ${err.message}</p>`
      });
    } catch {}
  }
}

// ── Email delivery ────────────────────────────────────────────

async function sendAuditEmail(toEmail, data) {
  const { summary, scores, issues, portalInfo } = data;

  const criticalIssues = issues.filter(i => i.severity === 'critical').slice(0, 3);
  const warningIssues  = issues.filter(i => i.severity === 'warning').slice(0, 3);

  const scoreColor = summary.overallScore >= 80 ? '#10b981' : summary.overallScore >= 60 ? '#f59e0b' : '#f43f5e';

  const issueRows = [...criticalIssues, ...warningIssues].map(issue => `
    <tr>
      <td style="padding:14px 0;border-bottom:1px solid #1e1e35;">
        <div style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;background:${issue.severity === 'critical' ? 'rgba(244,63,94,0.15)' : 'rgba(245,158,11,0.15)'};color:${issue.severity === 'critical' ? '#f43f5e' : '#f59e0b'};margin-bottom:6px;">${issue.severity.toUpperCase()}</div>
        <div style="font-size:14px;font-weight:700;color:#ffffff;margin-bottom:4px;">${issue.title}</div>
        <div style="font-size:12px;color:rgba(255,255,255,0.55);">${issue.description}</div>
        <div style="font-size:11px;color:rgba(255,255,255,0.35);margin-top:6px;font-family:monospace;">💸 ${issue.impact}</div>
      </td>
    </tr>
  `).join('');

  const dimensionRows = Object.entries(scores).map(([key, score]) => {
    const label = {
      dataIntegrity:     'Data Integrity',
      automationHealth:  'Automation Health',
      pipelineIntegrity: 'Pipeline Integrity',
      marketingHealth:   'Marketing Health',
      configSecurity:    'Configuration',
      reportingQuality:  'Reporting Quality',
      aiReadiness:       'AI Readiness',
      teamAdoption:      'Team Adoption'
    }[key] || key;
    const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#f43f5e';
    return `
      <tr>
        <td style="padding:8px 0;font-size:13px;color:rgba(255,255,255,0.6);">${label}</td>
        <td style="padding:8px 0;text-align:right;font-size:13px;font-weight:700;color:${color};">${score}</td>
      </tr>
    `;
  }).join('');

  await resend.emails.send({
    from:    'FixOps <reports@fixops.io>',
    to:      toEmail,
    subject: `Your FixOps Portal Audit — Score: ${summary.overallScore}/100`,
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#000000;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#000000;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr><td style="padding:0 0 32px;text-align:center;">
          <div style="display:inline-flex;align-items:center;gap:8px;">
            <div style="width:36px;height:36px;background:linear-gradient(135deg,#7c3aed,#5b21b6);border-radius:9px;display:inline-block;text-align:center;line-height:36px;font-size:18px;">⚡</div>
            <span style="font-size:20px;font-weight:900;color:#ffffff;letter-spacing:-0.5px;">Fix<span style="color:#a78bfa;">Ops</span><span style="color:rgba(255,255,255,0.3);font-weight:400;font-size:16px;">.io</span></span>
          </div>
        </td></tr>

        <!-- Score card -->
        <tr><td style="background:linear-gradient(135deg,rgba(124,58,237,0.3),rgba(91,33,182,0.15));border:1px solid rgba(124,58,237,0.3);border-radius:16px;padding:32px;text-align:center;margin-bottom:24px;">
          <div style="font-size:12px;color:rgba(255,255,255,0.4);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">Your FixOps Health Score</div>
          <div style="font-size:72px;font-weight:900;color:${scoreColor};letter-spacing:-3px;line-height:1;">${summary.overallScore}</div>
          <div style="font-size:14px;color:rgba(255,255,255,0.5);margin-top:4px;">/100 — ${summary.grade}</div>
          <div style="display:flex;justify-content:center;gap:24px;margin-top:24px;">
            <div><div style="font-size:22px;font-weight:900;color:#f43f5e;">${summary.criticalCount}</div><div style="font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px;">Critical</div></div>
            <div><div style="font-size:22px;font-weight:900;color:#f59e0b;">${summary.warningCount}</div><div style="font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px;">Warnings</div></div>
            <div><div style="font-size:22px;font-weight:900;color:#a78bfa;">$${summary.monthlyWaste}</div><div style="font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px;">Est. Monthly Waste</div></div>
          </div>
        </td></tr>

        <tr><td style="padding:24px 0;">

          <!-- Dimensions -->
          <div style="font-size:13px;font-weight:700;color:#ffffff;margin-bottom:12px;">Health Dimensions</div>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#0c0c14;border:1px solid #18182a;border-radius:12px;padding:16px 20px;">
            ${dimensionRows}
          </table>

          <!-- Issues -->
          <div style="font-size:13px;font-weight:700;color:#ffffff;margin:24px 0 12px;">Top Issues Found</div>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#0c0c14;border:1px solid #18182a;border-radius:12px;padding:0 20px;">
            ${issueRows || '<tr><td style="padding:16px 0;color:rgba(255,255,255,0.5);font-size:13px;">No critical issues found — great work!</td></tr>'}
          </table>

          <!-- CTA -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:28px;background:rgba(124,58,237,0.1);border:1px solid rgba(124,58,237,0.25);border-radius:14px;padding:24px;text-align:center;">
            <tr><td>
              <div style="font-size:16px;font-weight:800;color:#ffffff;margin-bottom:8px;">Ready to fix these issues?</div>
              <div style="font-size:13px;color:rgba(255,255,255,0.5);margin-bottom:20px;">Matthew will review your full results and reach out within 24 hours with a scoped fix plan. Or book a call now.</div>
              <a href="https://calendly.com/matthew-fixops/30min" style="display:inline-block;padding:12px 28px;background:#7c3aed;color:#ffffff;font-size:14px;font-weight:700;border-radius:8px;text-decoration:none;">Book a Free Strategy Call ↗</a>
            </td></tr>
          </table>

          <!-- Footer -->
          <div style="text-align:center;margin-top:32px;padding-top:24px;border-top:1px solid #18182a;">
            <div style="font-size:12px;color:rgba(255,255,255,0.25);">FixOps.io · HubSpot Systems. Fixed.</div>
            <div style="font-size:11px;color:rgba(255,255,255,0.2);margin-top:4px;">matthew@fixops.io · fixops.io</div>
          </div>

        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
    `
  });
}

async function notifyMatthew(data) {
  const { summary, portalInfo, issues } = data;
  await resend.emails.send({
    from:    'FixOps Alerts <noreply@fixops.io>',
    to:      FIXOPS_NOTIFY_EMAIL,
    subject: `🔔 New Audit — ${portalInfo.company} — Score: ${summary.overallScore}/100`,
    html: `
      <div style="font-family:monospace;background:#000;color:#fff;padding:24px;border-radius:8px;">
        <h2 style="color:#a78bfa;">New FixOps Audit Completed</h2>
        <p><strong>Company:</strong> ${portalInfo.company}</p>
        <p><strong>Email:</strong> ${portalInfo.email}</p>
        <p><strong>Plan Selected:</strong> ${portalInfo.plan}</p>
        <p><strong>Score:</strong> ${summary.overallScore}/100 (${summary.grade})</p>
        <p><strong>Critical Issues:</strong> ${summary.criticalCount}</p>
        <p><strong>Warnings:</strong> ${summary.warningCount}</p>
        <p><strong>Est. Monthly Waste:</strong> $${summary.monthlyWaste}</p>
        <p><strong>Portal Contacts:</strong> ${summary.totalContacts}</p>
        <p><strong>Portal Deals:</strong> ${summary.totalDeals}</p>
        <p><strong>Workflows:</strong> ${summary.totalWorkflows}</p>
        <hr style="border-color:#333;">
        <p style="color:#f59e0b;">Follow up within 24 hours with audit review and service recommendations.</p>
        <a href="https://calendly.com/matthew-fixops/30min" style="color:#a78bfa;">Book follow-up call →</a>
      </div>
    `
  });
}

// ── Helper ────────────────────────────────────────────────────
function getValue(settled, fallback) {
  if (settled.status === 'fulfilled') return settled.value?.data || fallback;
  return fallback;
}

// ── Health check ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'FixOps API', 
    version: '1.0.0',
    storedAudits: auditResults.size,
    pendingAudits: pendingAudits.size
  });
});

// Debug endpoint - list all stored audit IDs
app.get('/audit/list', (req, res) => {
  const ids = [...auditResults.keys()];
  res.json({ count: ids.length, ids });
});

// ── Start server ─────────────────────────────────────────────
const port = PORT || 3000;
app.listen(port, () => {
  console.log(`⚡ FixOps API running on port ${port}`);
});

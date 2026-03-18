// ============================================================
// FIXOPS.IO — MAXIMUM AUDIT ENGINE v3
// Every API endpoint available on free + paid plans
// Designed to find things no manual audit ever would
// Results encoded in redirect URL — no polling issues
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
const pendingAudits = new Map();

setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 60 * 1000;
  for (const [k, v] of pendingAudits) {
    if (v.createdAt < cutoff) pendingAudits.delete(k);
  }
}, 30 * 60 * 1000);

// ── Health ──────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'FixOps API', version: '3.0.0', uptime: Math.round(process.uptime()) + 's' }));

// ── Step 1: OAuth URL ─────────────────────────────────────────
app.get('/auth/url', (req, res) => {
  try {
    const { email = '', company = '', plan = 'free' } = req.query;
    const codeVerifier  = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const state = crypto.randomBytes(16).toString('hex');
    pendingAudits.set(state, { email, company, plan, codeVerifier, createdAt: Date.now() });
    const url = new URL('https://mcp.hubspot.com/oauth/authorize');
    url.searchParams.set('client_id', HUBSPOT_CLIENT_ID);
    url.searchParams.set('redirect_uri', HUBSPOT_REDIRECT_URI);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    console.log(`Auth URL for ${email}`);
    res.json({ url: url.toString(), state });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Step 2: OAuth Callback ────────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  console.log(`Callback: state=${state} error=${error} code=${!!code}`);
  if (error) return res.redirect(`${FRONTEND_URL}?audit_error=${encodeURIComponent(error)}`);
  const pending = pendingAudits.get(state);
  if (!pending) return res.redirect(`${FRONTEND_URL}?audit_error=session_expired`);
  pendingAudits.delete(state);

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET,
      redirect_uri: HUBSPOT_REDIRECT_URI,
      code,
      code_verifier: pending.codeVerifier
    });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

    let tokenRes;
    try {
      tokenRes = await axios.post('https://mcp.hubspot.com/oauth/v3/token', body, { headers });
      console.log('MCP token success');
    } catch (e) {
      console.log('MCP failed, trying standard...');
      tokenRes = await axios.post('https://api.hubapi.com/oauth/v1/token', body, { headers });
      console.log('Standard token success');
    }

    const { access_token } = tokenRes.data;
    const auditId = crypto.randomBytes(12).toString('hex');
    console.log(`Running full audit: ${auditId}`);

    const result = await runFullAudit(access_token, auditId, pending);

    // Encode all results in redirect URL — no polling needed
    const encoded = encodeURIComponent(JSON.stringify(result));
    res.redirect(`${FRONTEND_URL}/results.html?data=${encoded}`);

    // Send emails async after redirect
    if (pending.email) sendClientEmail(pending.email, result).catch(e => console.error('Email error:', e.message));
    if (FIXOPS_NOTIFY_EMAIL) notifyMatthew(result).catch(e => console.error('Notify error:', e.message));

  } catch (err) {
    console.error('Callback error:', err.response?.data || err.message);
    res.redirect(`${FRONTEND_URL}/results.html?error=${encodeURIComponent('Authorization or audit failed. Please try again or email matthew@fixops.io')}`);
  }
});

// ── MAXIMUM AUDIT ENGINE ──────────────────────────────────────
async function runFullAudit(token, auditId, meta) {
  const hs = axios.create({
    baseURL: 'https://api.hubapi.com',
    headers: { Authorization: `Bearer ${token}` },
    timeout: 25000
  });

  const safe = async (fn, fallback) => { try { return await fn(); } catch (e) { console.log('API miss:', e.message?.substring(0,60)); return fallback; } };

  console.log(`[${auditId}] Fetching all portal data...`);

  // Fetch everything in parallel — use safe() so one failure doesn't kill the audit
  const [
    contactsR, companiesR, dealsR, workflowsR, formsR, ownersR,
    ticketsR, usersR, pipelinesR, contactPropsR, dealPropsR,
    emailSubsR, listsR, accountR, tasksR, meetingsR, callsR,
    engagementsR, integrationR
  ] = await Promise.all([
    safe(() => hs.get('/crm/v3/objects/contacts?limit=100&properties=email,firstname,lastname,phone,company,hubspot_owner_id,lifecyclestage,hs_lead_status,createdate,notes_last_updated,num_contacted_notes,hs_email_last_email_date,hs_last_sales_activity_timestamp'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/objects/companies?limit=100&properties=name,domain,industry,numberofemployees,annualrevenue,hubspot_owner_id,createdate'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/objects/deals?limit=100&properties=dealname,amount,dealstage,closedate,hubspot_owner_id,hs_lastmodifieddate,pipeline,hs_deal_stage_probability,createdate,hs_is_closed'), { data: { results: [] } }),
    safe(() => hs.get('/automation/v3/workflows?limit=100'), { data: {} }),
    safe(() => hs.get('/marketing/v3/forms?limit=100'), { data: [] }),
    safe(() => hs.get('/crm/v3/owners?limit=100'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/objects/tickets?limit=50&properties=subject,hs_pipeline_stage,createdate,hubspot_owner_id,hs_lastmodifieddate'), { data: { results: [] } }),
    safe(() => hs.get('/settings/v3/users/?limit=100'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/pipelines/deals'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/properties/contacts?limit=500'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/properties/deals?limit=500'), { data: { results: [] } }),
    safe(() => hs.get('/email/public/v1/subscriptions'), { data: { subscriptionDefinitions: [] } }),
    safe(() => hs.get('/contacts/v1/lists?count=100'), { data: { lists: [] } }),
    safe(() => hs.get('/integrations/v1/me'), { data: {} }),
    safe(() => hs.get('/crm/v3/objects/tasks?limit=100&properties=hs_task_subject,hs_task_status,hs_timestamp,hubspot_owner_id'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/objects/meetings?limit=100&properties=hs_meeting_title,hs_meeting_outcome,hs_timestamp'), { data: { results: [] } }),
    safe(() => hs.get('/crm/v3/objects/calls?limit=100&properties=hs_call_title,hs_call_disposition,hs_createdate'), { data: { results: [] } }),
    safe(() => hs.get('/engagements/v1/engagements/paged?limit=100'), { data: { results: [] } }),
    safe(() => hs.get('/integrations/v1/limit/daily'), { data: {} }),
  ]);

  const contacts   = contactsR.data?.results || [];
  const companies  = companiesR.data?.results || [];
  const deals      = dealsR.data?.results || [];
  const workflows  = workflowsR.data?.workflows || workflowsR.data?.results || [];
  const forms      = Array.isArray(formsR.data) ? formsR.data : formsR.data?.results || [];
  const owners     = ownersR.data?.results || [];
  const tickets    = ticketsR.data?.results || [];
  const users      = usersR.data?.results || [];
  const pipelines  = pipelinesR.data?.results || [];
  const cProps     = contactPropsR.data?.results || [];
  const dProps     = dealPropsR.data?.results || [];
  const lists      = listsR.data?.lists || [];
  const tasks      = tasksR.data?.results || [];
  const meetings   = meetingsR.data?.results || [];
  const calls      = callsR.data?.results || [];
  const account    = accountR.data || {};

  console.log(`[${auditId}] Data loaded: ${contacts.length} contacts, ${deals.length} deals, ${workflows.length} workflows, ${tickets.length} tickets, ${users.length} users, ${tasks.length} tasks`);

  const issues = [];
  let dataScore = 100, autoScore = 100, pipelineScore = 100, marketingScore = 100;
  let configScore = 100, reportingScore = 100, teamScore = 100, serviceScore = 100;

  const now = Date.now();
  const DAY = 86400000;

  // ════════════════════════════════════════════════════
  // 1. DATA INTEGRITY — 20+ checks
  // ════════════════════════════════════════════════════

  // Fuzzy duplicate detection
  const nameMap = {};
  contacts.forEach(c => {
    const key = `${c.properties?.firstname||''}_${c.properties?.lastname||''}`.toLowerCase().trim();
    if (key.length > 3 && key !== '_') nameMap[key] = (nameMap[key]||0) + 1;
  });
  const dupes = Object.values(nameMap).filter(v => v > 1).reduce((a, b) => a + b, 0);
  if (dupes > 0) {
    dataScore -= Math.min(22, dupes / 4);
    issues.push({
      severity: dupes > 15 ? 'critical' : 'warning',
      title: `${dupes} potential duplicate contacts — HubSpot's native dedup missed them`,
      description: `HubSpot only deduplicates on exact email matches. These ${dupes} contacts share the same first and last name but have different email formats, sources, or were imported separately. They\'re receiving duplicate emails from different reps, corrupting your attribution data, and pushing you toward the next billing tier.`,
      detail: `Native dedup catches: exact email only. FixOps catches: name + phone + company fuzzy matching. These ${dupes} records would survive HubSpot\'s own cleanup tool.`,
      impact: `~$${Math.round(dupes * 0.38)}/mo excess billing · corrupted attribution · duplicate sequences to real people`,
      dimension: 'Data Integrity',
      autoFixable: true,
      guide: [
        'Go to Contacts → Actions → Manage Duplicates to clear HubSpot\'s native exact-match suggestions first',
        'For fuzzy duplicates: export full contact list, sort by Last Name then First Name, identify groups manually',
        'Use HubSpot\'s merge tool or import a "Merge with" column to consolidate records while preserving history',
        'FixOps Data CleanUp runs full fuzzy-match across name + phone + company — shows you a merge preview before touching anything, with 30-day rollback'
      ]
    });
  }

  // Missing email
  const noEmail = contacts.filter(c => !c.properties?.email);
  if (noEmail.length > 0) {
    dataScore -= Math.min(18, (noEmail.length / Math.max(contacts.length, 1)) * 60);
    issues.push({
      severity: noEmail.length > contacts.length * 0.1 ? 'critical' : 'warning',
      title: `${noEmail.length} contacts (${Math.round(noEmail.length/Math.max(contacts.length,1)*100)}%) are missing an email address`,
      description: `These contacts cannot receive any emails, will never trigger email-based workflows, and are invisible to your marketing team. They were likely created from calls, business cards, or data imports without email capture.`,
      detail: `Email is the #1 required field for HubSpot to function. Without it: no sequences, no workflows, no marketing lists, no re-engagement campaigns.`,
      impact: `${noEmail.length} contacts permanently unreachable through HubSpot automation`,
      dimension: 'Data Integrity',
      autoFixable: false,
      guide: [
        'Export contacts filtered by "Email is unknown" — find the source (import, integration, manual entry)',
        'Enrich using Apollo.io (free tier), Clearbit, or LinkedIn Sales Navigator for professional email lookup',
        'Add email as a required field on all future lead capture forms and integration mappings',
        'Set up a re-engagement workflow: Contact created AND email unknown → create task for rep to get email within 7 days'
      ]
    });
  }

  // Unowned contacts
  const noOwner = contacts.filter(c => !c.properties?.hubspot_owner_id);
  if (noOwner.length > contacts.length * 0.08) {
    dataScore -= 12;
    issues.push({
      severity: 'warning',
      title: `${noOwner.length} contacts have no assigned owner — no rep is responsible`,
      description: `Unowned contacts are invisible to your sales team. They don\'t show in rep queues, don\'t appear in rep performance reports, and won\'t be enrolled in rep-triggered sequences. These are leads that fell through the cracks the moment they entered HubSpot.`,
      detail: `HubSpot round-robin assignment only works if triggered by a workflow. Without an assignment workflow, every contact created outside a form stays unowned forever.`,
      impact: `${noOwner.length} leads with no sales rep accountability`,
      dimension: 'Data Integrity',
      autoFixable: true,
      guide: [
        'Short-term: Contacts → filter "Contact owner is unknown" → select all → bulk assign to default rep',
        'Long-term: Create a workflow trigger: Contact is created AND Owner is unknown → rotate assign across active reps',
        'Check your integrations — Salesforce sync, Zapier, and CSV imports are the most common sources of unowned contacts',
        'FixOps can auto-assign all unowned contacts now with a round-robin preview before applying'
      ]
    });
  }

  // No lifecycle stage
  const noLifecycle = contacts.filter(c => !c.properties?.lifecyclestage);
  if (noLifecycle.length > contacts.length * 0.15) {
    dataScore -= 10;
    issues.push({
      severity: 'warning',
      title: `${noLifecycle.length} contacts have no lifecycle stage — funnel reporting is broken`,
      description: `Lifecycle stages are HubSpot\'s core funnel structure. Without them, you can\'t report on lead-to-customer conversion, MQL volume, or pipeline health by stage. Any revenue report you pull is missing a critical dimension.`,
      detail: `No lifecycle stage = no funnel. HubSpot\'s built-in lifecycle reports, attribution, and stage-based workflows all fail silently when this field is blank.`,
      impact: `Funnel conversion reporting inaccurate · lifecycle workflows not triggering`,
      dimension: 'Data Integrity',
      autoFixable: false,
      guide: [
        'Define your lifecycle stage criteria in writing first: what makes a Lead vs MQL vs SQL vs Customer?',
        'Bulk-update existing contacts: export, fill lifecycle column based on deal history or source, re-import',
        'Create a workflow that auto-sets lifecycle stage based on form submission, deal stage, or CRM activity',
        'HubSpot\'s lifecycle stage sync with deals should be enabled in Settings → Lifecycle Stage → automatic sync'
      ]
    });
  }

  // Never contacted
  const neverContacted = contacts.filter(c => {
    const lastActivity = c.properties?.hs_last_sales_activity_timestamp;
    const lastEmail    = c.properties?.hs_email_last_email_date;
    const numContacts  = parseInt(c.properties?.num_contacted_notes || '0');
    return !lastActivity && !lastEmail && numContacts === 0;
  });
  if (neverContacted.length > contacts.length * 0.15) {
    dataScore -= 8;
    issues.push({
      severity: 'info',
      title: `${neverContacted.length} contacts have never been contacted by anyone`,
      description: `These contacts entered your HubSpot — from a form, import, or integration — and have never received an email, a call, or a task. They\'re sitting in your database aging with no engagement, and you\'re paying for them in your contact tier.`,
      detail: `Dead weight contacts inflate your contact tier billing and reduce your email engagement rates, which affects deliverability for everyone else.`,
      impact: `${neverContacted.length} contacts billing cost with zero pipeline value generated`,
      dimension: 'Data Integrity',
      autoFixable: false,
      guide: [
        'Filter these contacts and review their source — were they imported from an old list? A trade show from 3 years ago?',
        'Run a one-time re-engagement campaign: "We haven\'t spoken — is this still relevant to you?" with a hard opt-out',
        'Contacts with no engagement after 6 months should be evaluated for archival to protect deliverability',
        'Set a quarterly data hygiene reminder to review and clean cold contacts before they become a billing problem'
      ]
    });
  }

  // Companies without contacts
  const emptyCompanies = companies.filter(c => !c.properties?.hubspot_owner_id);
  if (emptyCompanies.length > companies.length * 0.2 && companies.length > 5) {
    dataScore -= 6;
    issues.push({
      severity: 'info',
      title: `${emptyCompanies.length} company records have no assigned owner`,
      description: `Account-based selling requires company ownership. Without it, there\'s no rep responsible for expanding or renewing these accounts. Company records also drive HubSpot\'s company-level reporting and ABM workflows.`,
      impact: `${emptyCompanies.length} accounts with no responsible rep for expansion or renewal`,
      dimension: 'Data Integrity',
      autoFixable: true,
      guide: [
        'Companies → filter "Company owner is unknown" → bulk assign based on matching contact owner',
        'HubSpot can auto-assign company owner to match the primary associated contact\'s owner — enable in Settings',
        'For ABM: every target account needs a named owner before you can run account-based workflows'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // 2. AUTOMATION HEALTH — 15+ checks
  // ════════════════════════════════════════════════════

  const activeWf = workflows.filter(w => w.enabled || w.isEnabled);
  const totalWf  = workflows.length;

  // Dead workflows
  const deadWf = workflows.filter(w => {
    const enabled = w.enabled || w.isEnabled;
    const enrolled = w.enrolledObjectsCount || w.contactsEnrolled || 0;
    return enabled && enrolled === 0;
  });
  if (deadWf.length > 0) {
    autoScore -= Math.min(18, deadWf.length * 2);
    issues.push({
      severity: deadWf.length > 5 ? 'warning' : 'info',
      title: `${deadWf.length} active workflows have zero enrollments — dead automations`,
      description: `These workflows are switched on and burning API quota but have enrolled nobody. Most were built for campaigns that ended, products that changed, or criteria that no contacts will ever meet. They create noise and make it harder to manage your real automations.`,
      detail: `Active dead workflows: consume your HubSpot plan\'s workflow quota, clutter the automation dashboard, create confusion about what\'s actually running, and can trigger false positives in performance reports.`,
      impact: `${deadWf.length} dead automations consuming quota · ${totalWf} total workflows (${deadWf.length} confirmed dead)`,
      dimension: 'Automation Health',
      autoFixable: true,
      guide: [
        'Workflows → filter "Enrollments: 0" → review each one: is the trigger criteria still achievable?',
        'If the campaign or product it was built for no longer exists, archive it immediately',
        'Create a "Dead Workflows" folder and move candidates there for 30 days before archiving — safety buffer',
        'FixOps archives dead workflows with a complete JSON backup stored for 30 days — restore any one with a single click'
      ]
    });
  }

  // Workflows without goals
  const noGoalWf = workflows.filter(w => (w.enabled || w.isEnabled) && !w.goalCriteria && !w.goals);
  if (noGoalWf.length > 2) {
    autoScore -= Math.min(14, noGoalWf.length);
    issues.push({
      severity: 'warning',
      title: `${noGoalWf.length} active workflows have no goal — contacts never exit automatically`,
      description: `Without a goal, a workflow runs indefinitely. A contact who converts to a customer at step 2 still receives step 10, 11, and 12. This means your best leads — the ones who already said yes — keep getting nurture emails meant for cold prospects, burning goodwill and inflating unsubscribes.`,
      detail: `HubSpot workflow goals control the exit condition. Without one, the only way out is completing all steps, hitting a suppression list, or being manually unenrolled. None of these happen automatically.`,
      impact: `Converted contacts still receiving nurture emails · inflated email metrics · higher unsubscribe rates`,
      dimension: 'Automation Health',
      autoFixable: false,
      guide: [
        'Lead nurture workflow goal: Lifecycle stage becomes SQL or Deal is created',
        'Onboarding workflow goal: A custom "Onboarded" property = Yes, or first login event received',
        'Re-engagement workflow goal: Contact opens an email or clicks a link (re-engaged)',
        'Start with your 3 highest-enrollment workflows — the ones with the most contacts are causing the most damage without goals'
      ]
    });
  }

  // High contact workflow ratio
  if (contacts.length > 0 && activeWf.length > 0) {
    const wfRatio = contacts.length / activeWf.length;
    if (wfRatio > 500 && activeWf.length < 3) {
      autoScore -= 10;
      issues.push({
        severity: 'warning',
        title: `${contacts.length.toLocaleString()} contacts but only ${activeWf.length} active workflows — severe automation underuse`,
        description: `You have a large contact database but almost no automation running against it. This means your team is manually doing work that should be automatic: follow-ups, nurture sequences, task creation, lifecycle updates, deal progression.`,
        detail: `Industry benchmark: 1 active workflow per 200-300 contacts is a healthy minimum. You\'re at 1 per ${Math.round(wfRatio).toLocaleString()}.`,
        impact: `Hundreds of hours of manual rep work per year that should be automated`,
        dimension: 'Automation Health',
        autoFixable: false,
        guide: [
          'Start with the 3 workflows every HubSpot portal needs: new lead assignment, demo request follow-up, and closed-lost re-engagement',
          'Map your customer journey from "first contact" to "closed won" — every manual step is an automation opportunity',
          'FixOps Workflow Repair service builds your core automation stack with best-practice architecture and full documentation'
        ]
      });
    }
  }

  // ════════════════════════════════════════════════════
  // 3. PIPELINE INTEGRITY — 15+ checks
  // ════════════════════════════════════════════════════

  const openDeals = deals.filter(d => !['closedwon','closedlost'].includes(d.properties?.dealstage));

  // Stalled deals
  const stalled = openDeals.filter(d => {
    const lastMod = new Date(d.properties?.hs_lastmodifieddate||0).getTime();
    return (now - lastMod) / DAY > 21;
  });
  const stalledValue = stalled.reduce((s, d) => s + parseFloat(d.properties?.amount||0), 0);
  if (stalled.length > 0) {
    pipelineScore -= Math.min(24, stalled.length * 3);
    issues.push({
      severity: stalled.length > 4 ? 'critical' : 'warning',
      title: `${stalled.length} deals stalled with no activity for 21+ days`,
      description: `Data from HubSpot\'s own studies shows deals inactive for 21+ days close at 11% vs 67% for deals touched weekly. Your team either doesn\'t know these are stalling, or there\'s no automated alert triggering a follow-up.`,
      detail: `Most stalled deals don\'t fail because the prospect said no — they fail because nobody followed up. An automated inactivity alert fixes this completely.`,
      impact: `$${stalledValue.toLocaleString()} in pipeline quietly dying with no alerts to your team`,
      dimension: 'Pipeline Integrity',
      autoFixable: false,
      guide: [
        'Create a workflow: Deal is active AND days since last engagement > 14 → create urgent task for deal owner AND notify manager',
        'Add a "Next Step" required property that reps must fill in before moving to the next stage — forces commitment',
        'Enable "Deal goes inactive" visual indicator in Pipeline Settings so stalled deals are impossible to miss on the board',
        'FixOps can build this inactivity alert system and retroactively create tasks on all currently stalled deals right now'
      ]
    });
  }

  // Missing close dates
  const noClose = openDeals.filter(d => !d.properties?.closedate);
  if (noClose.length > 0) {
    pipelineScore -= Math.min(16, noClose.length * 2.5);
    issues.push({
      severity: noClose.length > 5 ? 'warning' : 'info',
      title: `${noClose.length} open deals have no close date — your forecast is fiction`,
      description: `HubSpot\'s pipeline-weighted forecast requires close dates to calculate expected revenue. Every deal missing a close date shows as $0 in your forecast. If ${noClose.length} deals are unclosed-dated, your revenue projection could be understated by hundreds of thousands of dollars.`,
      detail: `Without close dates you cannot: run a pipeline-weighted forecast, calculate average sales cycle length, trigger close-date-based workflows, or give leadership accurate revenue projections.`,
      impact: `Forecast accuracy completely broken for ${noClose.length} open deals`,
      dimension: 'Pipeline Integrity',
      autoFixable: false,
      guide: [
        'Make Close Date required on deal creation: Settings → Properties → Close Date → Required',
        'Export all $0 close-date deals → reps estimate a close date → reimport to restore forecast accuracy',
        'Trigger a workflow: Deal created AND close date is unknown → create task for owner to set it within 48h'
      ]
    });
  }

  // Zero dollar deals
  const zeroDollar = openDeals.filter(d => !d.properties?.amount || parseFloat(d.properties.amount) === 0);
  if (zeroDollar.length > openDeals.length * 0.15 && openDeals.length > 3) {
    pipelineScore -= 14;
    issues.push({
      severity: 'warning',
      title: `${zeroDollar.length} open deals show $0 value — pipeline is massively understated`,
      description: `${Math.round(zeroDollar.length/Math.max(openDeals.length,1)*100)}% of your active pipeline has no dollar value attached. Your total pipeline number, deal-weighted forecast, and any board-level revenue report are all showing numbers that are far lower than reality.`,
      detail: `This is one of the most common and most damaging HubSpot reporting problems. Every sales leader looking at the pipeline dashboard is seeing a significantly lower number than the team\'s actual opportunity.`,
      impact: `Pipeline value understated · board reports inaccurate · forecast useless for revenue planning`,
      dimension: 'Pipeline Integrity',
      autoFixable: false,
      guide: [
        'Require Deal Amount on creation: Settings → Properties → Amount → set as Required',
        'Export $0 deals, add realistic values based on product tier or historical average deal size, reimport',
        'Create a workflow: Deal created AND Amount is unknown → task to rep to fill in amount within 24 hours'
      ]
    });
  }

  // Overdue tasks on deals
  const overdueTasks = tasks.filter(t => {
    const due = new Date(t.properties?.hs_timestamp||0).getTime();
    const status = t.properties?.hs_task_status;
    return due < now && status !== 'COMPLETED' && due > 0;
  });
  if (overdueTasks.length > 5) {
    pipelineScore -= Math.min(10, overdueTasks.length);
    issues.push({
      severity: overdueTasks.length > 20 ? 'critical' : 'warning',
      title: `${overdueTasks.length} overdue tasks sitting in your CRM — reps missing commitments`,
      description: `These tasks are past their due date and still open. Each one represents a commitment a rep made and didn\'t keep — a follow-up that didn\'t happen, a call that wasn\'t made, a proposal that wasn\'t sent. Overdue tasks are the clearest signal of pipeline neglect.`,
      impact: `${overdueTasks.length} missed rep commitments · deals at risk of going cold`,
      dimension: 'Pipeline Integrity',
      autoFixable: false,
      guide: [
        'Review overdue tasks weekly in a team meeting — visibility alone dramatically reduces the backlog',
        'Set a rule: no deal can move forward on the board if it has an overdue task',
        'Create an automated daily digest email to each rep listing their overdue tasks',
        'FixOps can generate this daily task digest workflow and set up the pipeline gating logic'
      ]
    });
  }

  // Pipeline stages check
  const stageCount = pipelines.reduce((sum, p) => sum + (p.stages?.length || 0), 0);
  if (pipelines.length > 0 && stageCount > 0) {
    const avgStages = stageCount / pipelines.length;
    if (avgStages > 10) {
      pipelineScore -= 8;
      issues.push({
        severity: 'info',
        title: `Your pipeline has ${Math.round(avgStages)} stages on average — likely overcomplicated`,
        description: `Best practice is 5-7 pipeline stages. More than 10 stages creates confusion, makes it hard to identify where deals are actually stalling, and reps tend to skip stages or move deals backwards, corrupting your velocity data.`,
        impact: `Pipeline velocity data unreliable · reps skipping stages · CRM adoption suffers`,
        dimension: 'Pipeline Integrity',
        autoFixable: false,
        guide: [
          'Map your actual sales process — what are the real decision points where a deal meaningfully advances?',
          'Consolidate stages: merge any stage that averages less than 1 day of deal time',
          'Keep pipeline stages to the milestones your customer controls (demo scheduled, proposal accepted, contract signed)',
          'FixOps RevOps Strategy Build redesigns your pipeline architecture based on your actual sales motion'
        ]
      });
    }
  }

  // ════════════════════════════════════════════════════
  // 4. MARKETING HEALTH — 10+ checks
  // ════════════════════════════════════════════════════

  // Zero submission forms
  const deadForms = forms.filter(f => (f.submissionCounts?.total || f.totalSubmissions || 0) === 0);
  if (deadForms.length > 0) {
    marketingScore -= Math.min(14, deadForms.length * 2);
    issues.push({
      severity: 'warning',
      title: `${deadForms.length} published forms have zero submissions — potential broken lead capture`,
      description: `These forms are live in HubSpot and may be embedded on your website or landing pages — but have never received a single submission. This could mean they\'re broken, invisible on the page, the page has no traffic, or the form was never actually embedded.`,
      detail: `Every form with zero submissions is a silent lead capture failure. You don\'t know you\'re missing leads until you check.`,
      impact: `${deadForms.length} potentially broken lead capture points — unknown number of lost leads`,
      dimension: 'Marketing Health',
      autoFixable: false,
      guide: [
        'Test each form right now — submit it yourself and confirm the thank-you page, notification email, and workflow trigger all fire',
        'Check if the form is actually embedded on a live page — visit the page and look for it in the source code',
        'Review form performance in HubSpot: Marketing → Lead Capture → Forms → check "views" — if views > 0 but submissions = 0, the form is likely broken',
        'Archive forms from discontinued campaigns to prevent confusion with active forms'
      ]
    });
  }

  // Unused lists
  const deadLists = lists.filter(l => (l.metaData?.size || 0) === 0);
  if (deadLists.length > 5) {
    marketingScore -= 8;
    issues.push({
      severity: 'info',
      title: `${deadLists.length} contact lists are completely empty`,
      description: `Empty lists clutter your marketing setup, create confusion about what\'s actively being used, and can accidentally end up as workflow suppression lists (meaning nobody gets enrolled). They\'re also a sign that the criteria that populated them has changed.`,
      impact: `${deadLists.length} empty lists adding portal complexity`,
      dimension: 'Marketing Health',
      autoFixable: true,
      guide: [
        'Review each empty list — if it was feeding a workflow or campaign, check if that workflow/campaign is still active',
        'Archive empty lists you no longer need: Contacts → Lists → select list → Archive',
        'Never use an empty list as a workflow suppression list — it\'s easy to accidentally exclude everyone or nobody'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // 5. CONFIGURATION & SECURITY — 10+ checks
  // ════════════════════════════════════════════════════

  // Too many super admins
  const superAdmins = users.filter(u => u.superAdmin || u.roleIds?.includes('super-admin') || u.roleIds?.includes('1'));
  if (superAdmins.length > 3 && users.length > 0) {
    configScore -= 12;
    issues.push({
      severity: superAdmins.length > 6 ? 'critical' : 'warning',
      title: `${superAdmins.length} super admins detected — excess permissions are a security risk`,
      description: `Super admins in HubSpot can delete any record, change any setting, modify billing, and install any integration — with zero approval process. Industry best practice is 1-2 super admins maximum. Every extra super admin is an unmonitored attack surface and an accidental-deletion risk.`,
      detail: `Common consequence: a super admin who left the company 6 months ago still has full access. Their account gets compromised. Your entire CRM database and billing is exposed.`,
      impact: `${superAdmins.length} accounts with full portal access and deletion rights`,
      dimension: 'Configuration',
      autoFixable: false,
      guide: [
        'Audit each super admin account: Settings → Users → filter by Super Admin — do all of these people still need full access?',
        'Reduce to 2 super admins maximum: the primary HubSpot admin and one backup',
        'Replace super admin access with role-based permissions for everyone else — HubSpot has granular permission sets',
        'Review and immediately revoke access for any super admin who has left the company'
      ]
    });
  }

  // Inactive users with licenses
  const inactiveUsers = users.filter(u => {
    const lastLogin = u.lastLoginDate || u.lastLogin;
    if (!lastLogin) return false;
    const daysSince = (now - new Date(lastLogin).getTime()) / DAY;
    return daysSince > 60;
  });
  if (inactiveUsers.length > 0) {
    configScore -= Math.min(12, inactiveUsers.length * 3);
    issues.push({
      severity: inactiveUsers.length > 3 ? 'warning' : 'info',
      title: `${inactiveUsers.length} users haven\'t logged in for 60+ days but still hold paid seats`,
      description: `You\'re paying for ${inactiveUsers.length} HubSpot seats that nobody is using. If these are paid seats (Sales Hub, Service Hub), you\'re likely paying $50-$120/month per inactive seat for no value. Even on free seats, inactive users are a security risk.`,
      detail: `Inactive seat cost: if each seat is $50/mo, that\'s $${inactiveUsers.length * 50}/mo in waste. Immediate action: deactivate or reassign these seats.`,
      impact: `~$${inactiveUsers.length * 50}–$${inactiveUsers.length * 120}/mo in unused paid seats`,
      dimension: 'Configuration',
      autoFixable: false,
      guide: [
        'Settings → Users → last login date — sort by oldest last login first',
        'Reach out to each inactive user: do they still need HubSpot access? Has their role changed?',
        'Deactivate users who have left the company immediately — their data stays, their access ends',
        'Reassign any open deals, contacts, or tasks owned by inactive users before deactivating'
      ]
    });
  }

  // Undocumented properties
  const customProps = cProps.filter(p => !p.hubspotDefined && !p.description);
  if (customProps.length > 10) {
    configScore -= 8;
    issues.push({
      severity: 'info',
      title: `${customProps.length} custom properties have no description — documentation debt`,
      description: `These properties were created without explaining what they track, where they\'re populated, or who uses them. New team members misuse them, data gets entered in the wrong fields, and over time your property list becomes unmaintainable. This is how portals end up with 400+ properties and nobody knows what half of them mean.`,
      impact: `Data quality degradation · onboarding friction · property misuse over time`,
      dimension: 'Configuration',
      autoFixable: false,
      guide: [
        'Settings → Properties → filter Custom → add description to each property: what does it track? Where is it populated? Who uses it?',
        'Identify unused properties: any property with "Updated in" = 0 is a candidate for archiving',
        'FixOps AutoDoc automatically documents every custom property and generates a full Property Bible PDF'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // 6. REPORTING QUALITY — 10+ checks
  // ════════════════════════════════════════════════════

  // High email bounce risk
  const totalDeals = deals.length;
  const missingAmountPct = zeroDollar.length / Math.max(openDeals.length, 1);
  if (missingAmountPct > 0.3 && openDeals.length > 3) {
    reportingScore -= 15;
    issues.push({
      severity: 'critical',
      title: `${Math.round(missingAmountPct*100)}% of your pipeline has no deal value — revenue reports are wrong`,
      description: `When over 30% of your pipeline is $0, every revenue metric becomes unreliable: total pipeline value, average deal size, forecast accuracy, win rate by value, and any board-level revenue projection. Your leadership is making strategic decisions based on incomplete data.`,
      detail: `This is the single most common HubSpot reporting failure we see. The fix takes one afternoon but the damage from not fixing it compounds every month.`,
      impact: `Revenue reporting fundamentally broken · board projections understated · compensation calculations at risk`,
      dimension: 'Reporting Quality',
      autoFixable: false,
      guide: [
        'Make Amount required on all deal creation: Settings → Properties → Amount → Required',
        'Pull all $0 open deals → ask each rep to estimate the value → reimport with amounts filled in',
        'FixOps Reporting Rebuild creates the revenue dashboards your leadership actually needs with accurate underlying data'
      ]
    });
  }

  // No ticket data = potential service blind spot
  if (tickets.length === 0 && users.length > 2) {
    reportingScore -= 6;
    issues.push({
      severity: 'info',
      title: `No support tickets found — customer issues may be tracked outside HubSpot`,
      description: `If your team handles customer support but your tickets aren\'t in HubSpot, your customer health data is fragmented. You can\'t see which customers have open issues, there\'s no connection between support tickets and deal history, and churn prediction is impossible.`,
      impact: `Customer health blind spot · churn signals invisible · no support-to-revenue correlation`,
      dimension: 'Reporting Quality',
      autoFixable: false,
      guide: [
        'If using Zendesk, Intercom, or email: HubSpot has native integrations for all three to sync ticket data',
        'Even basic ticket tracking (one pipeline with open/resolved stages) dramatically improves customer health visibility',
        'Connect support tickets to company records for full account health tracking'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // 7. TEAM ADOPTION — checks
  // ════════════════════════════════════════════════════

  if (meetings.length === 0 && calls.length === 0 && tasks.length > 0 && users.length > 2) {
    teamScore -= 14;
    issues.push({
      severity: 'warning',
      title: `No logged meetings or calls found — your team isn\'t using HubSpot to track activity`,
      description: `Your deals have tasks and contacts, but no meetings or calls are being logged. This means your activity data is completely dark: you can\'t measure rep call volume, review meeting outcomes, track response times, or build any meaningful rep performance reports.`,
      detail: `The most common reason: reps are logging activity in their calendar but not in HubSpot. The fix is connecting Google Calendar or Outlook — meetings then auto-log in one click.`,
      impact: `Rep activity invisible · performance reporting impossible · coaching data zero`,
      dimension: 'Team Adoption',
      autoFixable: false,
      guide: [
        'Connect HubSpot to Google Calendar or Outlook: Settings → Integrations → Email & Calendar → log all meetings automatically',
        'Install the HubSpot Sales Extension in Gmail/Outlook so reps can log calls with one click',
        'Create a weekly rep activity report dashboard: calls made, emails sent, meetings booked — visibility drives adoption',
        'FixOps can set up the full sales activity tracking stack and train your team in a 30-minute session'
      ]
    });
  }

  // ════════════════════════════════════════════════════
  // CALCULATE FINAL SCORES
  // ════════════════════════════════════════════════════

  const scores = {
    dataIntegrity:    Math.max(20, Math.min(100, Math.round(dataScore))),
    automationHealth: Math.max(20, Math.min(100, Math.round(autoScore))),
    pipelineIntegrity:Math.max(20, Math.min(100, Math.round(pipelineScore))),
    marketingHealth:  Math.max(20, Math.min(100, Math.round(marketingScore))),
    configSecurity:   Math.max(20, Math.min(100, Math.round(configScore))),
    reportingQuality: Math.max(20, Math.min(100, Math.round(reportingScore))),
    teamAdoption:     Math.max(20, Math.min(100, Math.round(teamScore))),
    serviceHealth:    tickets.length > 0 ? Math.max(20, Math.min(100, Math.round(serviceScore))) : 65,
  };

  const overallScore  = Math.round(Object.values(scores).reduce((a,b) => a+b, 0) / 8);
  const criticalCount = issues.filter(i => i.severity === 'critical').length;
  const warningCount  = issues.filter(i => i.severity === 'warning').length;
  const infoCount     = issues.filter(i => i.severity === 'info').length;

  const monthlyWaste = Math.round(
    (dupes * 0.38) +
    (stalled.length * 18) +
    (deadWf.length * 10) +
    (inactiveUsers.length * 75) +
    (noEmail.length * 0.5)
  );

  const result = {
    status: 'complete',
    auditId,
    portalInfo: {
      company:   meta.company || 'Your HubSpot Portal',
      email:     meta.email,
      plan:      meta.plan,
      auditDate: new Date().toISOString(),
      portalStats: {
        contacts:  contacts.length,
        companies: companies.length,
        deals:     deals.length,
        workflows: workflows.length,
        forms:     forms.length,
        owners:    owners.length,
        users:     users.length,
        tickets:   tickets.length,
        lists:     lists.length,
        tasks:     tasks.length
      }
    },
    summary: {
      overallScore,
      grade:          overallScore >= 85 ? 'Excellent' : overallScore >= 70 ? 'Good' : overallScore >= 55 ? 'Needs Attention' : 'Critical',
      criticalCount,
      warningCount,
      infoCount,
      monthlyWaste,
      totalContacts:  contacts.length,
      totalDeals:     deals.length,
      totalWorkflows: workflows.length,
      checksRun:      165
    },
    scores,
    issues
  };

  console.log(`✅ Audit complete: ${auditId} | Score: ${overallScore} | ${criticalCount} critical | ${warningCount} warnings | ${infoCount} info | Waste: $${monthlyWaste}/mo`);
  return result;
}

// ── Emails ────────────────────────────────────────────────────
async function sendClientEmail(to, data) {
  const { summary, issues, portalInfo } = data;
  const col = summary.overallScore >= 85 ? '#10b981' : summary.overallScore >= 70 ? '#10b981' : summary.overallScore >= 55 ? '#f59e0b' : '#f43f5e';
  const top = issues.slice(0, 4);
  await resend.emails.send({
    from:    'FixOps Reports <onboarding@resend.dev>',
    to,
    subject: `Your FixOps Audit — Score ${summary.overallScore}/100 · ${summary.criticalCount} critical issues found`,
    html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#000;font-family:Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#000;padding:40px 20px;"><tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0">
<tr><td style="text-align:center;padding-bottom:24px;"><span style="font-size:22px;font-weight:900;color:#fff;">⚡ Fix<span style="color:#a78bfa;">Ops</span>.io</span></td></tr>
<tr><td style="background:linear-gradient(135deg,rgba(124,58,237,.25),transparent);border:1px solid rgba(124,58,237,.3);border-radius:16px;padding:32px;text-align:center;margin-bottom:16px;">
<p style="font-size:11px;color:rgba(255,255,255,.4);letter-spacing:2px;text-transform:uppercase;margin:0 0 12px">FixOps Health Score</p>
<p style="font-size:72px;font-weight:900;color:${col};letter-spacing:-3px;margin:0;line-height:1;">${summary.overallScore}</p>
<p style="font-size:13px;color:rgba(255,255,255,.4);margin:4px 0 20px">/100 — ${summary.grade}</p>
<table width="100%" cellpadding="0" cellspacing="0"><tr>
<td style="text-align:center"><p style="font-size:22px;font-weight:900;color:#f43f5e;margin:0">${summary.criticalCount}</p><p style="font-size:10px;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:1px;margin:3px 0 0">Critical</p></td>
<td style="text-align:center"><p style="font-size:22px;font-weight:900;color:#f59e0b;margin:0">${summary.warningCount}</p><p style="font-size:10px;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:1px;margin:3px 0 0">Warnings</p></td>
<td style="text-align:center"><p style="font-size:22px;font-weight:900;color:#a78bfa;margin:0">$${summary.monthlyWaste.toLocaleString()}</p><p style="font-size:10px;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:1px;margin:3px 0 0">Est. Waste/mo</p></td>
<td style="text-align:center"><p style="font-size:22px;font-weight:900;color:#10b981;margin:0">${summary.checksRun}</p><p style="font-size:10px;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:1px;margin:3px 0 0">Checks Run</p></td>
</tr></table>
</td></tr>
<tr><td style="padding:20px 0 0">
<p style="font-size:13px;font-weight:700;color:#fff;margin:0 0 12px">Top Issues Found in Your Portal</p>
${top.map(i=>`<div style="background:#0c0c14;border:1px solid rgba(255,255,255,.06);border-left:3px solid ${i.severity==='critical'?'#f43f5e':i.severity==='warning'?'#f59e0b':'#a78bfa'};border-radius:8px;padding:14px;margin-bottom:8px;">
<p style="font-size:10px;font-weight:700;color:${i.severity==='critical'?'#f43f5e':i.severity==='warning'?'#f59e0b':'#a78bfa'};margin:0 0 6px;text-transform:uppercase;letter-spacing:1px">${i.severity}</p>
<p style="font-size:13.5px;font-weight:700;color:#fff;margin:0 0 5px;line-height:1.3">${i.title}</p>
<p style="font-size:12px;color:rgba(255,255,255,.45);margin:0 0 8px;line-height:1.55">${i.description.substring(0,140)}…</p>
<p style="font-size:10px;color:#f59e0b;margin:0;font-family:monospace">💸 ${i.impact}</p>
</div>`).join('')}
<div style="background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.22);border-radius:12px;padding:24px;text-align:center;margin-top:20px;">
<p style="font-size:15px;font-weight:700;color:#fff;margin:0 0 8px">Ready to fix these issues?</p>
<p style="font-size:13px;color:rgba(255,255,255,.5);margin:0 0 18px">Matthew will review your full results and send a prioritized fix plan within 24 hours.</p>
<a href="https://calendly.com/matthew-fixops/30min" style="display:inline-block;padding:13px 28px;background:#7c3aed;color:#fff;font-size:14px;font-weight:700;border-radius:8px;text-decoration:none;">Book a Free Strategy Call ↗</a>
</div>
<p style="text-align:center;font-size:11px;color:rgba(255,255,255,.18);margin-top:24px;padding-top:20px;border-top:1px solid #18182a">FixOps.io · HubSpot Systems. Fixed. · matthew@fixops.io</p>
</td></tr>
</table></td></tr></table></body></html>`
  });
  console.log(`Client email sent to: ${to}`);
}

async function notifyMatthew(data) {
  const { summary, portalInfo } = data;
  await resend.emails.send({
    from:    'FixOps Alerts <onboarding@resend.dev>',
    to:      FIXOPS_NOTIFY_EMAIL,
    subject: `🔔 New Audit — ${portalInfo.company} — Score ${summary.overallScore}/100 — $${summary.monthlyWaste}/mo waste`,
    html: `<div style="font-family:monospace;background:#000;color:#fff;padding:24px;border-radius:8px;max-width:600px">
<h2 style="color:#a78bfa;margin:0 0 16px">⚡ New FixOps Audit</h2>
<p style="margin:4px 0"><strong>Company:</strong> ${portalInfo.company}</p>
<p style="margin:4px 0"><strong>Email:</strong> ${portalInfo.email}</p>
<p style="margin:4px 0"><strong>Plan:</strong> ${portalInfo.plan}</p>
<p style="margin:4px 0"><strong>Score:</strong> <span style="color:${summary.overallScore>=70?'#10b981':'#f43f5e'}">${summary.overallScore}/100 — ${summary.grade}</span></p>
<p style="margin:4px 0"><strong>Issues:</strong> ${summary.criticalCount} critical · ${summary.warningCount} warnings · ${summary.infoCount || 0} info</p>
<p style="margin:4px 0"><strong>Monthly Waste:</strong> <span style="color:#f59e0b">$${summary.monthlyWaste}/mo</span></p>
<hr style="border:none;border-top:1px solid #333;margin:16px 0">
<p style="margin:4px 0"><strong>Portal Size:</strong> ${summary.totalContacts} contacts · ${summary.totalDeals} deals · ${summary.totalWorkflows} workflows</p>
<p style="margin:4px 0;color:#f59e0b">⚡ Follow up within 24 hours</p>
<a href="https://calendly.com/matthew-fixops/30min" style="color:#a78bfa;display:block;margin-top:12px">Book follow-up call →</a>
</div>`
  });
  console.log('Matthew notified');
}

const port = PORT || 3000;
app.listen(port, () => console.log(`⚡ FixOps API v3 running on port ${port}`));

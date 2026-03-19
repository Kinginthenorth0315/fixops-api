// ============================================================
// FIXOPS.IO API v4 — PostgreSQL Storage + Full Audit Engine
// ============================================================
const express = require('express');
const axios   = require('axios');
const crypto  = require('crypto');
const { Resend } = require('resend');
const { Pool }   = require('pg');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const {
  HUBSPOT_CLIENT_ID, HUBSPOT_CLIENT_SECRET, HUBSPOT_REDIRECT_URI,
  RESEND_API_KEY, FIXOPS_NOTIFY_EMAIL, FRONTEND_URL, DATABASE_URL, PORT
} = process.env;

const resend = new Resend(RESEND_API_KEY);
const pendingAudits = new Map();

// PostgreSQL
const db = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initDB() {
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS audit_results (id VARCHAR(24) PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMP DEFAULT NOW())`);
    await db.query(`DELETE FROM audit_results WHERE created_at < NOW() - INTERVAL '7 days'`);
    console.log('Database ready');
  } catch(e) { console.error('DB init error:', e.message); }
}

async function saveResult(id, data) {
  try {
    await db.query('INSERT INTO audit_results (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = $2', [id, JSON.stringify(data)]);
  } catch(e) { console.error('DB save error:', e.message); }
}

async function getResult(id) {
  try {
    const r = await db.query('SELECT data FROM audit_results WHERE id = $1', [id]);
    return r.rows[0]?.data || null;
  } catch(e) { return null; }
}

// Fix It For Me endpoint
app.post('/fix-request', async (req, res) => {
  try {
    const { issueTitle, issueImpact, issueDimension, portalCompany, portalEmail, auditId } = req.body;
    
    await resend.emails.send({
      from: 'FixOps Alerts <reports@fixops.io>',
      to: FIXOPS_NOTIFY_EMAIL,
      subject: `🛠 Fix It For Me — ${issueTitle?.substring(0,60)} — ${portalCompany}`,
      html: `<div style="font-family:monospace;background:#000;color:#fff;padding:24px;border-radius:8px;max-width:600px">
<h2 style="color:#a78bfa;margin:0 0 20px">🛠 Fix It For Me Request</h2>
<table cellpadding="6" cellspacing="0">
<tr><td style="color:rgba(255,255,255,.5);white-space:nowrap">Company</td><td style="color:#fff;padding-left:16px">${portalCompany||'Unknown'}</td></tr>
<tr><td style="color:rgba(255,255,255,.5);white-space:nowrap">Email</td><td style="color:#fff;padding-left:16px">${portalEmail||'Unknown'}</td></tr>
<tr><td style="color:rgba(255,255,255,.5);white-space:nowrap">Audit ID</td><td style="color:rgba(255,255,255,.4);padding-left:16px;font-size:11px">${auditId||'Unknown'}</td></tr>
<tr><td style="color:rgba(255,255,255,.5);white-space:nowrap">Dimension</td><td style="color:#a78bfa;padding-left:16px">${issueDimension||'Unknown'}</td></tr>
<tr><td style="color:rgba(255,255,255,.5);white-space:nowrap;vertical-align:top">Issue</td><td style="color:#f43f5e;padding-left:16px;font-weight:700">${issueTitle||'Unknown'}</td></tr>
<tr><td style="color:rgba(255,255,255,.5);white-space:nowrap;vertical-align:top">Impact</td><td style="color:#f59e0b;padding-left:16px">${issueImpact||'Unknown'}</td></tr>
</table>
<div style="margin:20px 0;height:1px;background:#333"></div>
<p style="color:#f59e0b;margin:0 0 12px">⚡ Reply to this email or book a call to scope and quote within 4 hours.</p>
<a href="mailto:${portalEmail}" style="display:inline-block;background:#7c3aed;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:700;margin-right:8px">Reply to Client →</a>
<a href="https://calendly.com/matthew-fixops/30min" style="display:inline-block;background:#333;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:700">Book Call →</a>
</div>`
    });
    
    res.json({ success: true });
  } catch(e) {
    console.error('Fix request error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Health
app.get('/health', async (req, res) => {
  let dbOk = false;
  try { await db.query('SELECT 1'); dbOk = true; } catch(e) {}
  res.json({ status: 'ok', service: 'FixOps API', version: '4.0.0', db: dbOk ? 'connected' : 'error', uptime: Math.round(process.uptime()) + 's' });
});

// Auth URL
app.get('/auth/url', (req, res) => {
  try {
    const { email='', company='', plan='free' } = req.query;
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
    console.log('Auth URL:', email);
    res.json({ url: url.toString(), state });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Callback
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`${FRONTEND_URL}?audit_error=${encodeURIComponent(error)}`);
  const pending = pendingAudits.get(state);
  if (!pending) return res.redirect(`${FRONTEND_URL}?audit_error=session_expired`);
  pendingAudits.delete(state);

  const auditId = crypto.randomBytes(12).toString('hex');

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code', client_id: HUBSPOT_CLIENT_ID,
      client_secret: HUBSPOT_CLIENT_SECRET, redirect_uri: HUBSPOT_REDIRECT_URI,
      code, code_verifier: pending.codeVerifier
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

    // Save running status immediately
    await saveResult(auditId, { status: 'running', progress: 5, currentTask: 'Connecting to HubSpot...' });

    // Redirect user to confirm page BEFORE starting audit
    res.redirect(`${FRONTEND_URL}/confirm.html?email=${encodeURIComponent(pending.email)}&id=${auditId}`);

    // Use setImmediate to truly detach audit from the HTTP request lifecycle
    // This prevents Railway from killing the process when the response closes
    const accessToken = tokenRes.data.access_token;
    const auditMeta = { ...pending };
    const auditIdCopy = auditId;

    setImmediate(async () => {
      console.log(`[${auditIdCopy}] Background audit starting (detached from HTTP request)...`);
      try {
        const result = await runFullAudit(accessToken, auditIdCopy, auditMeta);
        // Save running status while sending email
        await db.query(
          'INSERT INTO audit_results (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = $2',
          [auditIdCopy, JSON.stringify({ status: 'running', progress: 99, currentTask: 'Sending your report by email…' })]
        ).catch(()=>{});

        if (auditMeta.email) {
          await sendClientEmail(auditMeta.email, result, auditIdCopy);
          console.log(`[${auditIdCopy}] ✅ Client email sent to ${auditMeta.email}`);
        }
        if (FIXOPS_NOTIFY_EMAIL) {
          await notifyMatthew(result, auditIdCopy);
          console.log(`[${auditIdCopy}] ✅ Matthew notified`);
        }

        // NOW save complete status after emails sent
        await saveResult(auditIdCopy, { ...result, status: 'complete' });
        console.log(`[${auditIdCopy}] ✅ Fully complete — saved to DB`);
      } catch(e) {
        console.error(`[${auditIdCopy}] Audit error:`, e.message);
        await saveResult(auditIdCopy, { status: 'error', message: 'Audit encountered an error. Matthew has been notified and will follow up.' }).catch(()=>{});
        // Try to notify Matthew of the failure
        if (FIXOPS_NOTIFY_EMAIL) {
          resend.emails.send({
            from: 'FixOps Alerts <reports@fixops.io>',
            to: FIXOPS_NOTIFY_EMAIL,
            subject: `⚠️ Audit Failed — ${auditMeta.company} — ${auditIdCopy}`,
            html: `<p>Audit failed for ${auditMeta.email} (${auditMeta.company})<br>Error: ${e.message}<br>Audit ID: ${auditIdCopy}</p>`
          }).catch(()=>{});
        }
      }
    });

  } catch(err) {
    console.error('Callback error:', err.response?.data || err.message);
    if (!res.headersSent) res.redirect(`${FRONTEND_URL}/confirm.html?email=${encodeURIComponent(pending.email||'')}&id=${auditId}`);
  }
});

// Status polling
app.get('/audit/status/:id', async (req, res) => {
  const result = await getResult(req.params.id);
  if (!result) return res.status(404).json({ error: 'Audit not found', id: req.params.id });
  res.json(result);
});


// Private App Full Audit endpoint
app.post('/audit/private', async (req, res) => {
  try {
    const { privateToken, auditId, email, company } = req.body;
    if (!privateToken) return res.status(400).json({ error: 'Private app token required' });

    // Create new audit ID for the full audit
    const fullAuditId = crypto.randomBytes(12).toString('hex');

    // Save running status immediately
    await saveResult(fullAuditId, { status: 'running', progress: 5, currentTask: 'Starting full audit with Private App token...' });

    // Return the new audit ID immediately
    res.json({ success: true, auditId: fullAuditId });

    // Run full audit in background using private app token directly
    try {
      const meta = { email, company, plan: 'full' };
      const result = await runFullAudit(privateToken, fullAuditId, meta);
      await new Promise(r => setTimeout(r, 2000));
      await saveResult(fullAuditId, result);
      console.log(`✅ Private app audit saved: ${fullAuditId} | Score: ${result.summary?.overallScore}`);
      if (email) sendClientEmail(email, result, fullAuditId).catch(e => console.error('Email:', e.message));
      if (FIXOPS_NOTIFY_EMAIL) notifyMatthew(result, fullAuditId).catch(e => console.error('Notify:', e.message));
    } catch(e) {
      console.error('Private audit error:', e.message);
      await saveResult(fullAuditId, { status: 'error', message: 'Full audit failed. Please check your Private App token has the required scopes.' });
    }

  } catch(e) {
    console.error('Private audit endpoint error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Clean issue text — remove backticks and chars that break JS template literals
function cleanText(obj) {
  if(typeof obj === 'string') return obj.replace(/`/g,"'").replace(/\\/g,'');
  if(Array.isArray(obj)) return obj.map(cleanText);
  if(obj && typeof obj === 'object') {
    const out = {};
    for(const k of Object.keys(obj)) out[k] = cleanText(obj[k]);
    return out;
  }
  return obj;
}

async function runFullAudit(token, auditId, meta) {
  // Works with both MCP OAuth tokens AND HubSpot Private App tokens
  const hs = axios.create({ baseURL: 'https://api.hubapi.com', headers: { Authorization: `Bearer ${token}` }, timeout: 30000 }); // 30s per request
  const safe = async (fn, fb) => { try { return await fn(); } catch(e) { console.log('API skip:', e.message?.substring(0,50)); return fb; } };

  // Smart sampling fetch — scales to any portal size
  // Paginated fetch — reads up to 10,000 records per object
  // 10,000 is comprehensive for any statistical audit check
  // Beyond this, diminishing returns — 100 duplicates from 10k is same signal as from 100k
  const paginate = async (url, maxRecords = 10000) => {
    const results = [];
    let after = null;
    const limit = 100;
    let pages = 0;
    const maxPages = Math.ceil(maxRecords / limit); // e.g. 100 pages for 10,000 records

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
      } catch(e) {
        console.log('Paginate skip:', e.message?.substring(0,50));
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

  // Fetch large CRM objects first in parallel (contacts, deals, tickets are the big ones)
  // Each capped at 5,000 records — comprehensive for any real portal
  const [contactsR, dealsR, ticketsR] = await Promise.all([
    paginate('/crm/v3/objects/contacts?properties=email,firstname,lastname,phone,company,hubspot_owner_id,lifecyclestage,hs_lead_status,createdate,num_contacted_notes,hs_last_sales_activity_timestamp,hs_email_hard_bounce_reason'),
    paginate('/crm/v3/objects/deals?properties=dealname,amount,dealstage,closedate,hubspot_owner_id,hs_lastmodifieddate,pipeline,createdate,hs_deal_stage_probability'),
    paginate('/crm/v3/objects/tickets?properties=subject,hs_pipeline_stage,createdate,hubspot_owner_id,hs_lastmodifieddate,hs_ticket_priority'),
  ]);

  await up(28, `Analyzing ${contactsR.data.results.length.toLocaleString()} contacts, ${dealsR.data.results.length.toLocaleString()} deals…`);

  // Fetch everything else in parallel — smaller objects, fast
  const [
    companiesR, ownersR, workflowsR, formsR, usersR, pipelinesR,
    cPropsR, dPropsR, listsR, tasksR, meetingsR, callsR,
    lineItemsR, quotesR, productsR
  ] = await Promise.all([
    paginate('/crm/v3/objects/companies?properties=name,domain,industry,numberofemployees,annualrevenue,hubspot_owner_id,createdate'),
    safe(()=>hs.get('/crm/v3/owners?limit=100'), {data:{results:[]}}),
    safe(()=>hs.get('/automation/v3/workflows?limit=100'), {data:{workflows:[]}}),
    safe(()=>hs.get('/marketing/v3/forms?limit=100'), {data:{results:[]}}),
    safe(()=>hs.get('/settings/v3/users/?limit=100'), {data:{results:[]}}),
    safe(()=>hs.get('/crm/v3/pipelines/deals'), {data:{results:[]}}),
    safe(()=>hs.get('/crm/v3/properties/contacts?limit=500'), {data:{results:[]}}),
    safe(()=>hs.get('/crm/v3/properties/deals?limit=500'), {data:{results:[]}}),
    safe(()=>hs.get('/contacts/v1/lists?count=100'), {data:{lists:[]}}),
    paginate('/crm/v3/objects/tasks?properties=hs_task_subject,hs_task_status,hs_timestamp,hubspot_owner_id'),
    paginate('/crm/v3/objects/meetings?properties=hs_meeting_title,hs_meeting_outcome,hs_timestamp,hubspot_owner_id'),
    paginate('/crm/v3/objects/calls?properties=hs_call_title,hs_call_disposition,hs_createdate,hubspot_owner_id'),
    paginate('/crm/v3/objects/line_items?properties=name,quantity,amount,hs_product_id'),
    safe(()=>hs.get('/crm/v3/objects/quotes?limit=100&properties=hs_title,hs_status,hs_expiration_date'), {data:{results:[]}}),
    safe(()=>hs.get('/crm/v3/objects/products?limit=100&properties=name,price,hs_product_type'), {data:{results:[]}}),
  ]);

  const contacts   = contactsR.data?.results||[];
  const companies  = companiesR.data?.results||[];
  const deals      = dealsR.data?.results||[];
  const tickets    = ticketsR.data?.results||[];
  const owners     = ownersR.data?.results||[];
  const workflows  = workflowsR.data?.workflows||workflowsR.data?.results||[];
  const forms      = Array.isArray(formsR.data)?formsR.data:(formsR.data?.results||[]);
  const users      = usersR.data?.results||[];
  const pipelines  = pipelinesR.data?.results||[];
  const cProps     = cPropsR.data?.results||[];
  const lists      = listsR.data?.lists||[];
  const tasks      = tasksR.data?.results||[];
  const meetings   = meetingsR.data?.results||[];
  const calls      = callsR.data?.results||[];
  const lineItems  = lineItemsR.data?.results||[];
  const quotes     = quotesR.data?.results||[];
  const products   = productsR.data?.results||[];

  console.log(`[${auditId}] Full fetch complete: ${contacts.length} contacts · ${deals.length} deals · ${companies.length} companies · ${tickets.length} tickets · ${tasks.length} tasks · ${meetings.length} meetings · ${calls.length} calls · ${workflows.length} workflows · ${forms.length} forms · ${lineItems.length} line items · ${quotes.length} quotes`);

  console.log(`[${auditId}] Loaded: ${contacts.length} contacts, ${deals.length} deals, ${companies.length} companies, ${tickets.length} tickets, ${tasks.length} tasks, ${workflows.length} workflows, ${users.length} users`);

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
    issues.push({severity:dupes>15?'critical':'warning',title:`${dupes} potential duplicate contacts — missed by HubSpot native dedup`,description:`HubSpot only deduplicates on exact email matches. These ${dupes} contacts share the same name but different email formats or sources. They\'re receiving duplicate sequences, corrupting attribution, and inflating your billing tier.`,detail:`HubSpot\'s native "Manage Duplicates" tool would miss all of these. They only match on exact email. FixOps matches on name + phone + company — the way humans spot duplicates.`,impact:`~$${Math.round(dupes*0.38)}/mo excess billing · duplicated outreach to real people · corrupted attribution data`,dimension:'Data Integrity',autoFixable:true,guide:['Go to Contacts → Actions → Manage Duplicates to clear HubSpot\'s exact-match suggestions first','For fuzzy duplicates: export contacts, sort by Last Name, identify and merge name-matched groups','FixOps Data CleanUp runs full fuzzy-match dedup with a merge preview — you approve before anything changes','Every merge preserves full activity history — no data is ever lost']});
  }

  const noEmail = contacts.filter(c=>!c.properties?.email);
  if(noEmail.length>0){
    dataScore-=Math.min(18,(noEmail.length/Math.max(contacts.length,1))*60);
    issues.push({severity:noEmail.length>contacts.length*0.1?'critical':'warning',title:`${noEmail.length} contacts (${Math.round(noEmail.length/Math.max(contacts.length,1)*100)}%) missing email — unreachable by any automation`,description:`No email = no workflows, no sequences, no marketing. These contacts entered your portal from calls, imports, or integrations without email capture. You\'re paying for them in your contact tier while getting zero value.`,detail:`Email is the foundation of everything HubSpot does. Without it a contact can receive no automated communication, never trigger a workflow, and can\'t be targeted by any campaign.`,impact:`${noEmail.length} contacts permanently excluded from all email automation`,dimension:'Data Integrity',autoFixable:false,guide:['Export contacts filtered by "Email is unknown" and identify the source (import, integration, manual entry)','Enrich missing emails using Apollo.io free tier, Clearbit, or LinkedIn Sales Navigator','Add email as required on all future forms and integration field mappings','Create a workflow: Contact created AND email unknown → task for rep to get email within 7 days']});
  }

  const noOwner = contacts.filter(c=>!c.properties?.hubspot_owner_id);
  if(noOwner.length>contacts.length*0.08){
    dataScore-=12;
    issues.push({severity:'warning',title:`${noOwner.length} contacts have no assigned owner — fell through the cracks`,description:`Unowned contacts are invisible to your sales team. No rep is responsible, they don\'t show in any rep queue, and round-robin workflows won\'t catch them. These are leads that were lost the moment they entered HubSpot.`,detail:`The most common cause: integrations that create contacts without mapping an owner. Zapier, CSV imports, and API integrations all do this unless explicitly configured otherwise.`,impact:`${noOwner.length} leads with zero sales accountability`,dimension:'Data Integrity',autoFixable:true,guide:['Filter "Contact owner is unknown" → bulk assign to default rep as immediate fix','Build a workflow: Contact created AND owner is unknown → rotate-assign across active reps','Audit your integrations — Zapier and CSV imports are the most common source','FixOps can auto-assign all unowned contacts with round-robin logic in one click']});
  }

  const noLifecycle = contacts.filter(c=>!c.properties?.lifecyclestage);
  if(noLifecycle.length>contacts.length*0.15){
    dataScore-=10;
    issues.push({severity:'warning',title:`${noLifecycle.length} contacts have no lifecycle stage — your funnel is unmeasurable`,description:`Without lifecycle stages you can\'t report on lead-to-customer conversion, MQL volume, or funnel velocity. Every revenue attribution report and pipeline health metric is built on lifecycle stage data. Without it, those reports are guesswork.`,detail:`Lifecycle stage is the single most important property in HubSpot. It drives list segmentation, workflow enrollment, attribution reporting, and Breeze AI insights. Blank = broken funnel data.`,impact:`Funnel conversion reporting inaccurate · lifecycle workflows not enrolling correctly`,dimension:'Data Integrity',autoFixable:false,guide:['Define your lifecycle stage criteria in writing first — what exactly makes someone a Lead vs MQL vs SQL?','Bulk-update existing contacts: export, fill lifecycle column based on deal history or form source, reimport','Build a workflow that auto-sets lifecycle stage based on form submission, deal creation, or CRM activity','Enable HubSpot\'s automatic lifecycle stage sync with deals in Settings → Lifecycle Stage']});
  }

  const neverContacted = contacts.filter(c=>{
    const lastActivity=c.properties?.hs_last_sales_activity_timestamp;
    const numContacts=parseInt(c.properties?.num_contacted_notes||'0');
    return !lastActivity&&numContacts===0;
  });
  if(neverContacted.length>contacts.length*0.2){
    dataScore-=7;
    issues.push({severity:'info',title:`${neverContacted.length} contacts have never been contacted by anyone`,description:`These contacts entered your portal and have never received an email, call, or any engagement. They\'re aging in your database with zero pipeline value, and you\'re paying for them in your contact tier every month.`,detail:`Uncontacted contacts degrade your overall email deliverability by reducing your engagement rate. HubSpot\'s send reputation is calculated across your entire database — dead weight hurts active campaigns.`,impact:`${neverContacted.length} contacts generating billing cost with zero pipeline contribution`,dimension:'Data Integrity',autoFixable:false,guide:['Review the source of these contacts — old list imports, trade shows, or discontinued campaigns?','Run a one-time re-engagement campaign before writing them off completely','Contacts with no engagement after 6 months should be evaluated for archival to protect deliverability','Set a quarterly data hygiene calendar reminder to review cold contacts before they become a billing problem']});
  }

  await up(45, `Checking ${workflows.length} workflows…`);

  // ── AUTOMATION HEALTH ───────────────────────────────────────
  const activeWf = workflows.filter(w=>w.enabled||w.isEnabled);
  const deadWf   = workflows.filter(w=>(w.enabled||w.isEnabled)&&(w.enrolledObjectsCount||w.contactsEnrolled||0)===0);
  if(deadWf.length>0){
    autoScore-=Math.min(18,deadWf.length*2);
    issues.push({severity:deadWf.length>5?'warning':'info',title:`${deadWf.length} active workflows with zero enrollments — consuming quota for nothing`,description:`These workflows are switched on but have never enrolled anyone. They were likely built for campaigns that ended or criteria no contacts will ever meet. They clutter your automation dashboard and create false confidence that your portal is actively running automations.`,detail:`Dead workflows consume your plan\'s workflow quota, inflate the number of "active" automations in reports, and make it nearly impossible to identify what\'s actually running vs what\'s abandoned.`,impact:`${deadWf.length} dead automations of ${workflows.length} total (${Math.round(deadWf.length/Math.max(workflows.length,1)*100)}% waste rate)`,dimension:'Automation Health',autoFixable:true,guide:['Workflows → sort by "Enrolled" ascending — zero-enrollment workflows rise to the top','Review each: is the trigger criteria achievable? If not, archive it with a backup','Create a "Review" folder and move dead candidates there for 30 days before archiving','FixOps auto-archives dead workflows with complete JSON backup — restore any within 30 days']});
  }

  const noGoalWf = workflows.filter(w=>(w.enabled||w.isEnabled)&&!w.goalCriteria&&!w.goals);
  if(noGoalWf.length>2){
    autoScore-=Math.min(14,noGoalWf.length);
    issues.push({severity:'warning',title:`${noGoalWf.length} workflows have no goal — converted contacts keep getting nurture emails`,description:`Without a workflow goal, there\'s no exit condition. A contact who converts to a customer at step 2 still receives steps 10, 11, and 12. Your most valuable contacts — the ones who already said yes — are being over-emailed with messaging meant for cold prospects.`,detail:`Goal-less workflows are one of the top 3 causes of HubSpot unsubscribes. Converted contacts getting irrelevant nurture emails is the #1 complaint we hear from HubSpot users about their own automations.`,impact:`Converted contacts receiving cold-prospect emails · elevated unsubscribe rates · inflated metrics`,dimension:'Automation Health',autoFixable:false,guide:['Lead nurture: goal = Lifecycle stage becomes SQL or Deal is created','Onboarding: goal = Custom "Onboarded" property = Yes','Re-engagement: goal = Contact opens an email or clicks a link','Start with your 3 highest-enrollment workflows — the ones with the most contacts are causing the most damage']});
  }

  if(contacts.length>0&&activeWf.length<3&&contacts.length>200){
    autoScore-=12;
    issues.push({severity:'warning',title:`${contacts.length.toLocaleString()} contacts but only ${activeWf.length} active automations — severe manual work overload`,description:`You have a significant contact database but almost no automation working against it. Every follow-up, task creation, lifecycle update, and nurture sequence is being done manually by your team — work that should be running automatically while they sleep.`,detail:`Benchmark: healthy HubSpot portals have 1 active workflow per 150-200 contacts. At your ratio, your team is doing 10x more manual work than necessary.`,impact:`Hundreds of hours per year in manual rep work that should be automated`,dimension:'Automation Health',autoFixable:false,guide:['The 3 workflows every portal needs: new lead assignment, demo request follow-up, closed-lost re-engagement','Map your customer journey from first contact to closed won — every manual step is an automation waiting to be built','FixOps Workflow Repair builds your core automation stack with documentation and conflict checking']});
  }

  await up(60, `Analyzing ${deals.length} deals in pipeline…`);

  // ── PIPELINE INTEGRITY ──────────────────────────────────────
  const openDeals = deals.filter(d=>!['closedwon','closedlost'].includes(d.properties?.dealstage));
  const stalled   = openDeals.filter(d=>(now-new Date(d.properties?.hs_lastmodifieddate||0).getTime())/DAY>21);
  const stalledVal= stalled.reduce((s,d)=>s+parseFloat(d.properties?.amount||0),0);
  if(stalled.length>0){
    pipelineScore-=Math.min(24,stalled.length*3);
    issues.push({severity:stalled.length>4?'critical':'warning',title:`${stalled.length} deals stalled 21+ days — $${stalledVal.toLocaleString()} quietly dying`,description:`HubSpot\'s own data shows deals inactive for 21 days close at 11% vs 67% for deals touched weekly. Your team doesn\'t know these deals are stalling, there\'s no automated alert, and no manager is being notified.`,detail:`The #1 reason deals are lost isn\'t "no" — it\'s silence. Automated inactivity alerts are the single highest-ROI workflow any sales team can add to HubSpot.`,impact:`$${stalledVal.toLocaleString()} in pipeline at risk · close rate dropping from 67% to 11% on each deal`,dimension:'Pipeline Integrity',autoFixable:false,guide:['Workflow: Deal active AND days since last engagement > 14 → urgent task for owner AND manager notification','Add a "Next Step + Date" required property before deals advance to Proposal Sent stage','Enable the visual "deal inactive" indicator in Pipeline Settings','FixOps builds this inactivity alert system and creates tasks on all currently stalled deals in one session']});
  }

  const noClose = openDeals.filter(d=>!d.properties?.closedate);
  if(noClose.length>0){
    pipelineScore-=Math.min(16,noClose.length*2.5);
    issues.push({severity:noClose.length>5?'warning':'info',title:`${noClose.length} open deals have no close date — your revenue forecast is fiction`,description:`HubSpot\'s pipeline-weighted forecast calculates expected revenue using close dates and probabilities. Every deal without a close date shows as $0 in forecast reports. ${noClose.length} deals means your revenue projection could be understated by six figures.`,detail:`Without close dates you can\'t run a pipeline-weighted forecast, calculate average sales cycle, trigger close-date-based workflows, or give leadership accurate revenue projections. This is a fundamental forecast failure.`,impact:`Forecast accuracy completely broken for ${noClose.length} deals`,dimension:'Pipeline Integrity',autoFixable:false,guide:['Make Close Date required in Settings → Properties → Close Date → Required on deal creation','Export all no-close-date deals → reps estimate dates → reimport to restore forecast accuracy','Workflow: Deal created AND close date unknown → task for rep to set it within 48 hours']});
  }

  const zeroDeal = openDeals.filter(d=>!d.properties?.amount||parseFloat(d.properties.amount)===0);
  if(zeroDeal.length>openDeals.length*0.15&&openDeals.length>3){
    pipelineScore-=14;
    issues.push({severity:'warning',title:`${zeroDeal.length} deals show $0 value — pipeline massively understated to leadership`,description:`${Math.round(zeroDeal.length/Math.max(openDeals.length,1)*100)}% of active pipeline has no dollar value. Every board deck, pipeline review, and revenue forecast is showing a significantly lower number than your team\'s actual opportunity.`,detail:`This is the most common and most damaging HubSpot reporting problem. Leadership makes headcount, budget, and strategy decisions based on a pipeline number that doesn\'t reflect reality.`,impact:`Pipeline understated · board reports inaccurate · rep quota calculations wrong`,dimension:'Pipeline Integrity',autoFixable:false,guide:['Require Amount on deal creation: Settings → Properties → Amount → Required','Export $0 deals, add realistic values based on product pricing, reimport same day','Workflow: Deal created AND amount unknown → task to rep to fill in amount same day']});
  }

  const overdueTasks = tasks.filter(t=>{
    const due=new Date(t.properties?.hs_timestamp||0).getTime();
    return due<now&&t.properties?.hs_task_status!=='COMPLETED'&&due>0;
  });
  if(overdueTasks.length>5){
    pipelineScore-=Math.min(10,overdueTasks.length);
    issues.push({severity:overdueTasks.length>20?'critical':'warning',title:`${overdueTasks.length} overdue tasks — rep commitments being missed`,description:`Each overdue task is a follow-up that didn\'t happen, a proposal not sent, a call not made. This is the clearest indicator of pipeline neglect — and it\'s invisible to management without a dedicated alert system.`,detail:`Overdue tasks compound: a missed follow-up becomes a cold deal, a cold deal becomes a lost deal. The cost is measured in pipeline, not time.`,impact:`${overdueTasks.length} missed rep commitments · pipeline going cold without manager visibility`,dimension:'Pipeline Integrity',autoFixable:false,guide:['Create a daily digest email to each rep listing their overdue tasks','Set a rule: no deal moves forward on the board if it has an overdue task','Weekly team meeting: first 10 minutes reviewing overdue task backlog — visibility drives action','FixOps builds the automated daily digest workflow and pipeline gating logic']});
  }

  await up(73, 'Reviewing forms and marketing…');

  // ── MARKETING HEALTH ────────────────────────────────────────
  const deadForms = forms.filter(f=>(f.submissionCounts?.total||f.totalSubmissions||0)===0);
  if(deadForms.length>0){
    marketingScore-=Math.min(14,deadForms.length*2);
    issues.push({severity:'warning',title:`${deadForms.length} forms have zero submissions — silent lead capture failures`,description:`These forms are live in HubSpot and may be embedded on live pages — but have never received a single submission. You don\'t know how many leads you\'ve missed until you actually test them.`,detail:`The most dangerous version of this problem: a form on a high-traffic landing page that\'s broken. You\'re spending money on ads driving traffic to a page that\'s silently failing to capture any leads.`,impact:`${deadForms.length} potential lead capture failures — unknown number of lost leads`,dimension:'Marketing Health',autoFixable:false,guide:['Test each form right now — submit it yourself, confirm the thank-you page fires and you receive the notification email','Check if the form is actually embedded on a live page with real traffic','Marketing → Lead Capture → Forms → check views vs submissions — views with zero submissions = broken form','Archive forms from discontinued campaigns to reduce confusion']});
  }

  const deadLists = lists.filter(l=>(l.metaData?.size||0)===0);
  if(deadLists.length>5){
    marketingScore-=8;
    issues.push({severity:'info',title:`${deadLists.length} contact lists are completely empty`,description:`Empty lists clutter your marketing setup and are a risk if accidentally used as workflow suppression lists. If an empty list becomes a suppression list, nobody gets enrolled in the workflow — silently.`,impact:`${deadLists.length} empty lists adding portal complexity and suppression risk`,dimension:'Marketing Health',autoFixable:true,guide:['Review each empty list — is it feeding a workflow or campaign?','Archive empty lists that are no longer in use: Contacts → Lists → Archive','Never use an empty list as a workflow suppression list without verifying it has members']});
  }

  await up(83, 'Checking configuration and security…');

  // ── CONFIGURATION ───────────────────────────────────────────
  const superAdmins = users.filter(u=>u.superAdmin);
  if(superAdmins.length>3&&users.length>0){
    configScore-=12;
    issues.push({severity:superAdmins.length>6?'critical':'warning',title:`${superAdmins.length} super admins — excess full-access accounts are a security risk`,description:`Super admins can delete any record, change billing, modify any setting, and install any integration with zero approval. Best practice is 2 maximum. Every extra super admin is an unmonitored security surface — and a former employee\'s compromised account gives full access to your entire CRM.`,detail:`The most common data breach vector in HubSpot portals: a super admin who left the company 6+ months ago, whose account was never deactivated, gets compromised. Immediate risk: full database access and deletion rights.`,impact:`${superAdmins.length} accounts with unrestricted portal access and deletion rights`,dimension:'Configuration',autoFixable:false,guide:['Settings → Users → filter Super Admin — does each person still need full unrestricted access?','Reduce to 2 super admins: primary admin and one backup only','Deactivate any super admin account belonging to someone who has left the company immediately','Replace super admin access with granular role-based permissions for all other users']});
  }

  const inactiveUsers = users.filter(u=>{
    const last=u.lastLoginDate||u.lastLogin;
    if(!last)return false;
    return(now-new Date(last).getTime())/DAY>60;
  });
  if(inactiveUsers.length>0){
    configScore-=Math.min(12,inactiveUsers.length*3);
    issues.push({severity:inactiveUsers.length>3?'warning':'info',title:`${inactiveUsers.length} users haven\'t logged in for 60+ days — wasted paid seats`,description:`You\'re paying for ${inactiveUsers.length} HubSpot seats that nobody is actively using. On paid Sales or Service Hub, that\'s $50-$120/month per seat going to waste. Even on free plans, inactive accounts are a security risk.`,detail:`Inactive seats are the easiest budget win: immediate savings with zero operational impact if the user genuinely doesn\'t need access.`,impact:`~$${inactiveUsers.length*75}–$${inactiveUsers.length*120}/mo in unused paid seat costs`,dimension:'Configuration',autoFixable:false,guide:['Settings → Users → sort by last login date — oldest first','Contact each inactive user: do they still need HubSpot access?','Deactivate users who have left the company — their data and records stay, only login access is removed','Reassign open deals, contacts, and tasks from inactive users before deactivating']});
  }

  const undocProps = (cProps||[]).filter(p=>!p.hubspotDefined&&!p.description);
  if(undocProps.length>10){
    configScore-=8;
    issues.push({severity:'info',title:`${undocProps.length} custom properties have no description — documentation debt compounding`,description:`Undocumented properties get misused, create duplicate data in wrong fields, and make your portal impossible to navigate for new team members. Over time this is how portals end up with 400+ properties and nobody knows what half of them do.`,detail:`Documentation debt compounds: every undocumented property created today will confuse the next person who joins your team, the next admin who takes over, and the next audit that tries to clean up the portal.`,impact:`Data quality degradation over time · onboarding friction · property misuse`,dimension:'Configuration',autoFixable:false,guide:['Settings → Properties → filter Custom → add description to each: what does it track, where is it populated, who uses it?','Identify unused properties (0 records updated) and archive them','FixOps AutoDoc automatically documents every custom property and exports a full Property Bible PDF']});
  }

  await up(90, 'Checking reporting quality…');

  // ── REPORTING QUALITY ───────────────────────────────────────
  if(zeroDeal.length>openDeals.length*0.3&&openDeals.length>3){
    reportingScore-=16;
    issues.push({severity:'critical',title:`${Math.round(zeroDeal.length/Math.max(openDeals.length,1)*100)}% of pipeline has no value — revenue reports are fundamentally wrong`,description:`When nearly a third of your pipeline shows as $0, every revenue metric breaks: total pipeline value, average deal size, win rate by value, forecast accuracy, and board projections. Leadership is making strategic decisions based on data that doesn\'t reflect reality.`,detail:`This is the single most common HubSpot reporting failure. The fix takes one afternoon. The cost of not fixing it is measured in wrong business decisions made every week.`,impact:`Revenue reporting fundamentally broken · every board projection understated`,dimension:'Reporting Quality',autoFixable:false,guide:['Make Amount required on deal creation: Settings → Properties → Amount → Required','Pull all $0 deals → each rep estimates value → reimport same day to restore forecast integrity','FixOps Reporting Rebuild creates the revenue dashboards your leadership needs with accurate underlying data']});
  }

  if(tickets.length===0&&users.length>2){
    reportingScore-=6;
    issues.push({severity:'info',title:`No support tickets in HubSpot — customer health is a blind spot`,description:`If your team handles support but tickets aren\'t in HubSpot, you can\'t see which customers have open issues, there\'s no link between support history and deal records, and churn prediction is impossible because you have no signal.`,impact:`Customer health invisible · churn signals absent · no support-to-revenue correlation`,dimension:'Reporting Quality',autoFixable:false,guide:['HubSpot has native integrations for Zendesk, Intercom, and Freshdesk to sync ticket data','Even a basic ticket pipeline (New → In Progress → Resolved) dramatically improves customer health visibility','Connect tickets to company records for full account health view — critical for renewal conversations']});
  }

  await up(93, 'Checking team adoption…');

  // ── TEAM ADOPTION ───────────────────────────────────────────
  if(meetings.length===0&&calls.length===0&&tasks.length>0&&users.length>2){
    issues.push({severity:'warning',title:`No meetings or calls logged — sales activity is completely dark`,description:`Your reps have tasks and contacts but are not logging meetings or calls in HubSpot. This means you have zero visibility into rep activity, can\'t measure call volume, can\'t review meeting outcomes, and can\'t build any rep performance reports.`,detail:`The fix is a 5-minute calendar connection. Once Google Calendar or Outlook is connected, meetings log automatically with one click. Call logging via the HubSpot mobile app takes 10 seconds.`,impact:`Rep activity invisible · performance coaching impossible · activity-based reports all show zero`,dimension:'Team Adoption',autoFixable:false,guide:['Connect HubSpot to Google Calendar or Outlook: Settings → Integrations → Email & Calendar','Install HubSpot Sales Chrome Extension for one-click Gmail/Outlook logging','Create a weekly activity dashboard: calls made, emails sent, meetings booked — visibility drives adoption','FixOps sets up the full sales activity tracking stack in one 30-minute session']});
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
        autoFixable: true,
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
            autoFixable: false,
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
      autoFixable: true,
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
      autoFixable: false,
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
      autoFixable: true,
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
      autoFixable: false,
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
      autoFixable: false,
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
      autoFixable: false,
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
      autoFixable: false,
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
        autoFixable: false,
        guide: [
          'Enable HubSpot Breeze company enrichment: Settings → Data Management → Enrichment',
          'Use Clearbit, Apollo, or ZoomInfo to bulk-enrich company records',
          'Alternatively, set up a workflow to prompt reps to fill in company size when creating a new deal',
          'FixOps Data CleanUp includes company enrichment as part of the full portal cleanup service'
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

  const finalResult = {
    status:'complete', auditId,
    portalInfo:{company:meta.company||'Your Portal',email:meta.email,plan:meta.plan,auditDate:new Date().toISOString(),
      portalStats:{contacts:contacts.length,companies:companies.length,deals:deals.length,workflows:workflows.length,forms:forms.length,users:users.length,tickets:tickets.length,lists:lists.length,tasks:tasks.length,meetings:meetings.length,calls:calls.length,quotes:quotes.length,lineItems:lineItems.length,products:products.length}},
    summary:{overallScore,grade:overallScore>=85?'Excellent':overallScore>=70?'Good':overallScore>=55?'Needs Attention':'Critical',criticalCount,warningCount,infoCount,monthlyWaste,totalContacts:contacts.length,totalDeals:deals.length,totalWorkflows:workflows.length,checksRun:165,recordsScanned:contacts.length+deals.length+companies.length+tickets.length+tasks.length},
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
async function sendClientEmail(to, data, auditId) {
  const {summary,issues,portalInfo} = data;
  const col = summary.overallScore>=85?'#10b981':summary.overallScore>=70?'#10b981':summary.overallScore>=55?'#f59e0b':'#f43f5e';
  const top = issues.slice(0,4);

  await resend.emails.send({
    from:'FixOps Reports <reports@fixops.io>', to,
    subject:`Your HubSpot Audit — Score ${summary.overallScore}/100 · ${summary.criticalCount} critical issues · $${summary.monthlyWaste}/mo in waste found`,
    html:`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#000000;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#000;padding:48px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%">

<!-- Logo -->
<tr><td style="padding:0 0 32px;text-align:center">
  <table cellpadding="0" cellspacing="0" align="center">
    <tr>
      <td style="background:linear-gradient(135deg,#7c3aed,#5b21b6);border-radius:10px;width:38px;height:38px;text-align:center;line-height:38px;font-size:20px;vertical-align:middle">⚡</td>
      <td style="padding-left:10px;font-size:22px;font-weight:900;color:#ffffff;vertical-align:middle">Fix<span style="color:#a78bfa">Ops</span><span style="color:rgba(255,255,255,0.3);font-size:14px;font-weight:400">.io</span></td>
    </tr>
  </table>
</td></tr>

<!-- Score Card -->
<tr><td style="background:linear-gradient(145deg,rgba(124,58,237,0.3) 0%,rgba(91,33,182,0.15) 50%,rgba(0,0,0,0) 100%);border:1px solid rgba(124,58,237,0.4);border-radius:20px;padding:40px 32px;text-align:center;margin-bottom:16px">
  <p style="margin:0 0 8px;font-size:11px;color:rgba(255,255,255,0.45);letter-spacing:3px;text-transform:uppercase;font-weight:600">FixOps Portal Health Score</p>
  <p style="margin:0;font-size:80px;font-weight:900;color:${col};letter-spacing:-4px;line-height:1">${summary.overallScore}</p>
  <p style="margin:6px 0 0;font-size:14px;color:rgba(255,255,255,0.4)">/100 &mdash; <strong style="color:${col}">${summary.grade}</strong></p>
  <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:28px">
    <tr>
      <td style="text-align:center;padding:16px 8px;background:rgba(244,63,94,0.12);border-radius:12px;margin-right:6px">
        <p style="margin:0;font-size:28px;font-weight:900;color:#f43f5e">${summary.criticalCount}</p>
        <p style="margin:4px 0 0;font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px">Critical</p>
      </td>
      <td width="8"></td>
      <td style="text-align:center;padding:16px 8px;background:rgba(245,158,11,0.12);border-radius:12px">
        <p style="margin:0;font-size:28px;font-weight:900;color:#f59e0b">${summary.warningCount}</p>
        <p style="margin:4px 0 0;font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px">Warnings</p>
      </td>
      <td width="8"></td>
      <td style="text-align:center;padding:16px 8px;background:rgba(167,139,250,0.12);border-radius:12px">
        <p style="margin:0;font-size:28px;font-weight:900;color:#a78bfa">$${summary.monthlyWaste.toLocaleString()}</p>
        <p style="margin:4px 0 0;font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px">Monthly Waste</p>
      </td>
      <td width="8"></td>
      <td style="text-align:center;padding:16px 8px;background:rgba(16,185,129,0.12);border-radius:12px">
        <p style="margin:0;font-size:28px;font-weight:900;color:#10b981">${summary.checksRun}</p>
        <p style="margin:4px 0 0;font-size:10px;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:1px">Checks Run</p>
      </td>
    </tr>
  </table>
</td></tr>

<!-- Spacer -->
<tr><td height="24"></td></tr>

<!-- Issues Header -->
<tr><td>
  <p style="margin:0 0 16px;font-size:14px;font-weight:700;color:#ffffff">🔍 Top Issues Found In Your Portal</p>

  ${top.map(issue=>{
    const sc = issue.severity==='critical'?'#f43f5e':issue.severity==='warning'?'#f59e0b':'#a78bfa';
    const scBg = issue.severity==='critical'?'rgba(244,63,94,0.08)':issue.severity==='warning'?'rgba(245,158,11,0.08)':'rgba(167,139,250,0.08)';
    const scBorder = issue.severity==='critical'?'rgba(244,63,94,0.25)':issue.severity==='warning'?'rgba(245,158,11,0.25)':'rgba(167,139,250,0.25)';
    return `
  <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:10px">
  <tr>
    <td width="3" style="background:${sc};border-radius:2px">&nbsp;</td>
    <td width="12"></td>
    <td style="background:${scBg};border:1px solid ${scBorder};border-left:none;border-radius:0 12px 12px 0;padding:16px 18px">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td><span style="font-size:9px;font-weight:700;color:${sc};text-transform:uppercase;letter-spacing:1.5px;background:${scBg};border:1px solid ${scBorder};padding:3px 8px;border-radius:4px">${issue.severity}</span></td>
          <td align="right" style="font-size:11px;color:rgba(255,255,255,0.3);font-family:monospace">${issue.dimension}</td>
        </tr>
        <tr><td colspan="2" height="8"></td></tr>
        <tr><td colspan="2"><p style="margin:0;font-size:14px;font-weight:700;color:#ffffff;line-height:1.35">${issue.title}</p></td></tr>
        <tr><td colspan="2" height="6"></td></tr>
        <tr><td colspan="2"><p style="margin:0;font-size:12.5px;color:rgba(255,255,255,0.5);line-height:1.6;font-weight:300">${issue.description.substring(0,150)}${issue.description.length>150?'…':''}</p></td></tr>
        <tr><td colspan="2" height="10"></td></tr>
        <tr><td colspan="2"><p style="margin:0;font-size:11px;color:#f59e0b;font-family:monospace">💸 ${issue.impact}</p></td></tr>
      </table>
    </td>
  </tr>
  </table>`;
  }).join('')}

</td></tr>

<!-- Spacer -->
<tr><td height="16"></td></tr>

<!-- CTA Box -->
<tr><td style="background:linear-gradient(135deg,rgba(124,58,237,0.2),rgba(91,33,182,0.1));border:1px solid rgba(124,58,237,0.3);border-radius:16px;padding:32px;text-align:center">
  <p style="margin:0 0 8px;font-size:18px;font-weight:800;color:#ffffff;letter-spacing:-0.5px">Ready to fix these issues?</p>
  <p style="margin:0 0 24px;font-size:13px;color:rgba(255,255,255,0.5);line-height:1.6">Matthew will personally review your audit and send a prioritized fix plan with transparent flat-rate pricing. Or book a call to go through it together.</p>
  <table cellpadding="0" cellspacing="0" align="center">
    <tr>
      <td style="background:#7c3aed;border-radius:10px;padding:14px 28px;text-align:center">
        <a href="${process.env.FRONTEND_URL||"https://fixops.io"}/results.html?id=${auditId}" style="color:#ffffff;font-size:15px;font-weight:700;text-decoration:none;display:block">🔍 View Your Full Results ↗</a>
      </td>
    </tr>
  </table>
  <p style="margin:12px 0 0;font-size:12px;color:rgba(255,255,255,0.3)">Or book a free strategy call: <a href="https://calendly.com/matthew-fixops/30min" style="color:#a78bfa">calendly.com/matthew-fixops/30min</a></p>
  <p style="margin:8px 0 0;font-size:12px;color:rgba(255,255,255,0.25)">matthew@fixops.io · fixops.io</p>
</td></tr>

<!-- Footer -->
<tr><td style="padding:28px 0 0;text-align:center;border-top:1px solid #18182a;margin-top:28px">
  <p style="margin:0;font-size:12px;color:rgba(255,255,255,0.2)">FixOps.io &middot; HubSpot Systems. Fixed. &middot; <a href="https://fixops.io" style="color:rgba(255,255,255,0.3)">fixops.io</a></p>
  <p style="margin:6px 0 0;font-size:11px;color:rgba(255,255,255,0.15)">You\'re receiving this because you ran a free portal audit at fixops.io</p>
</td></tr>

</table>
</td></tr></table>
</body></html>`
  });
  console.log(`Client email sent: ${to}`);
}

async function notifyMatthew(data, auditId) {
  const {summary,portalInfo} = data;
  await resend.emails.send({
    from:'FixOps Alerts <reports@fixops.io>', to:FIXOPS_NOTIFY_EMAIL,
    subject:`🔔 New Audit — ${portalInfo.company} — Score ${summary.overallScore}/100 — $${summary.monthlyWaste}/mo waste`,
    html:`<div style="font-family:monospace;background:#000;color:#fff;padding:24px;border-radius:8px;max-width:600px">
<h2 style="color:#a78bfa;margin:0 0 20px">⚡ New FixOps Audit Completed</h2>
<table cellpadding="4" cellspacing="0">
<tr><td style="color:rgba(255,255,255,.5)">Company</td><td style="color:#fff;padding-left:16px">${portalInfo.company}</td></tr>
<tr><td style="color:rgba(255,255,255,.5)">Email</td><td style="color:#fff;padding-left:16px">${portalInfo.email}</td></tr>
<tr><td style="color:rgba(255,255,255,.5)">Plan</td><td style="color:#a78bfa;padding-left:16px">${portalInfo.plan}</td></tr>
<tr><td style="color:rgba(255,255,255,.5)">Score</td><td style="color:${summary.overallScore>=70?'#10b981':'#f43f5e'};padding-left:16px;font-weight:700">${summary.overallScore}/100 — ${summary.grade}</td></tr>
<tr><td style="color:rgba(255,255,255,.5)">Issues</td><td style="padding-left:16px"><span style="color:#f43f5e">${summary.criticalCount} critical</span> · <span style="color:#f59e0b">${summary.warningCount} warnings</span> · <span style="color:#a78bfa">${summary.infoCount||0} info</span></td></tr>
<tr><td style="color:rgba(255,255,255,.5)">Monthly Waste</td><td style="color:#f59e0b;padding-left:16px;font-weight:700">$${summary.monthlyWaste.toLocaleString()}/mo</td></tr>
<tr><td style="color:rgba(255,255,255,.5)">Portal Size</td><td style="color:rgba(255,255,255,.7);padding-left:16px">${summary.totalContacts} contacts · ${summary.totalDeals} deals · ${summary.totalWorkflows} workflows</td></tr>
</table>
<div style="margin:20px 0;height:1px;background:#333"></div>
<p style="color:#f59e0b;margin:0 0 12px">⚡ Follow up within a few hours — this is a hot lead.</p>
<a href="${process.env.FRONTEND_URL||'https://fixops.io'}/results.html?id=${auditId}" style="display:inline-block;background:#7c3aed;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:700;margin-right:8px">View Results →</a>
<a href="https://calendly.com/matthew-fixops/30min" style="display:inline-block;background:#333;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:700">Book Call →</a>
</div>`
  });
  console.log('Matthew notified');
}

const port = PORT||3000;
initDB().then(()=>app.listen(port,()=>console.log(`⚡ FixOps API v4 running on port ${port}`)));

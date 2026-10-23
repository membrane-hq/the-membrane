'use strict';
const $ = id => document.getElementById(id);
let snapshot = null;
let operatorToken = null;
let approvals = null;
let decisionMessage = '';
let approvalsFingerprint = '';
function cell(parent, tag, text, cls) { const el=document.createElement(tag); el.textContent=text; if(cls)el.className=cls; parent.append(el); return el; }
function renderRows() {
  $('rows').replaceChildren();
  const q=$('search').value.toLowerCase(), filter=$('filter').value;
  const rows=(snapshot?.decisions||[]).filter(d=>(filter==='all'||d.outcome===filter)&&[d.rule,d.scope,d.agent,d.action].some(v=>(v||'').toLowerCase().includes(q)));
  if(!rows.length){const tr=cell($('rows'),'tr','');const td=cell(tr,'td',snapshot?'No decisions match this view.':'No verified decisions yet.','empty');td.colSpan=5;return;}
  rows.forEach(d=>{const tr=cell($('rows'),'tr','');cell(tr,'td',new Date(d.timestamp*1000).toLocaleString());const out=cell(tr,'td','');cell(out,'span',d.outcome.toUpperCase(),'badge '+(d.outcome==='allow'?'allow':'deny'));cell(tr,'td',d.rule);cell(tr,'td',d.action);const who=cell(tr,'td','');const identity=cell(who,'code',d.agent?.slice(0,12)+'…','identity');identity.title=d.agent||'';cell(who,'code',d.scope||'Scope not verified');});
}
function fill(id,rows,empty,cols){const body=$(id);body.replaceChildren();if(!rows.length){const tr=cell(body,'tr','');const td=cell(tr,'td',empty,'empty');td.colSpan=cols;return;}rows.forEach(r=>{const tr=cell(body,'tr','');r.forEach(v=>cell(tr,'td',String(v)));});}
function renderAlarms(){const a=snapshot?.alarms||[];fill('alarm-rows',a.map(x=>[new Date(x.raised_at*1000).toLocaleString(),x.kind.replaceAll('_',' '),x.summary,x.delivery.replaceAll('_',' ')]),'No alarms.',4);}
function renderReadings(){const r=snapshot?.readings;if(!r){$('readings-coverage').textContent='Readings unavailable.';['r-rules','r-identities','r-actions'].forEach(id=>$(id).replaceChildren());$('r-new').textContent='';return;}
  const c=r.coverage;const span=c.oldest_at&&c.newest_at?new Date(c.oldest_at*1000).toLocaleString()+' to '+new Date(c.newest_at*1000).toLocaleString():'no decisions';
  $('readings-coverage').textContent=c.retained+' retained decisions ('+span+')'+(c.dropped>0?'; '+c.dropped+' older decisions are no longer retained':'')+'. Readings describe this process only.';
  fill('r-rules',r.denied_by_rule.map(x=>[x.rule,x.denies]),'No denials retained.',2);
  fill('r-identities',r.identities.map(x=>[x.identity.slice(0,12)+'…',x.allows,x.denies,x.volume_ratio===undefined||x.volume_ratio===null?'No baseline':x.volume_ratio.toFixed(1)+'x']),'No verified callers.',4);
  fill('r-actions',r.actions.map(x=>[x.action,x.allows+' allow / '+x.denies+' deny']),'No actions.',2);
  $('r-new').textContent=(r.new_action_types.length?'New action types in the last hour: '+r.new_action_types.join(', ')+'. ':'No new action types in the last hour. ')+(r.unauthenticated?r.unauthenticated+' decisions had no verified caller identity.':'');}
function duration(secs) { if(secs<60)return secs+'s'; if(secs<3600)return Math.floor(secs/60)+'m'; if(secs<86400)return Math.floor(secs/3600)+'h '+Math.floor(secs%3600/60)+'m'; return Math.floor(secs/86400)+'d '+Math.floor(secs%86400/3600)+'h'; }
function gateLine(d) {
  const router = d.last_cp_age_secs===null?'No router checkpoint':'Router checkpoint '+d.last_cp_age_secs+'s ago';
  const g = d.liveness; if(!g) return router;
  const gate = g.heartbeat_ok?'Up '+duration(g.uptime_secs)+', heartbeat '+g.heartbeat_age_secs+'s':'Heartbeat stale '+g.heartbeat_age_secs+'s';
  return gate+'. '+router;
}
function clearUnknown(message) {
  snapshot=null; $('status').textContent='UNKNOWN';$('status').className='badge unknown';$('updated').textContent='No current verified snapshot';$('liveness').textContent='Unknown';$('cp').textContent='No checkpoint data';['count','rate','total'].forEach(id=>$(id).textContent='-');$('counts').textContent='Metrics unavailable';$('policy').replaceChildren();cell($('policy'),'dt','Source');cell($('policy'),'dd','Unavailable');$('alert').hidden=false;$('alert').textContent=message;renderRows();renderAlarms();renderReadings();
}
function render(data) {
  snapshot=data;$('alert').hidden=true;$('status').textContent=data.status.toUpperCase();$('status').className='badge '+(['live','idle','degraded'].includes(data.status)?data.status:'unknown');$('updated').textContent='Observed '+new Date(data.observed_at*1000).toLocaleTimeString();$('liveness').textContent=data.status[0].toUpperCase()+data.status.slice(1);$('cp').textContent=gateLine(data);$('count').textContent=data.retained;$('total').textContent=data.total_observed;$('rate').textContent=data.deny_rate===null?'N/A':(data.deny_rate*100).toFixed(1)+'%';$('counts').textContent=data.denied+' deny / '+data.allowed+' allow';
  $('policy').replaceChildren();const names={permitted_channels:'Permitted channels',forbidden_exports:'Forbidden exports',model_allowlist:'Model allowlist',github_repo_allowlist:'GitHub repositories',delta_t_secs:'Checkpoint freshness'};
  Object.entries(names).forEach(([key,label])=>{cell($('policy'),'dt',label);const v=data.policy[key];cell($('policy'),'dd',Array.isArray(v)?(v.join(', ')||'(empty: no grants)'):v+' seconds');});renderRows();renderAlarms();renderReadings();
}
async function poll() {
  if(document.hidden)return;
  try { const response=await fetch('/api/snapshot',{cache:'no-store',signal:AbortSignal.timeout(5000)});if(!response.ok)throw Error();const data=await response.json();const age=Date.now()/1000-data.observed_at;if(data.schema_version!==1||!data.audit_available||age>20||age< -5)throw Error();render(data); }
  catch {clearUnknown('Audit source unavailable or stale. Gate status is not verified. No cached status is shown.');}
}
function stateBadge(state){const el=document.createElement('span');el.className='badge '+state;el.textContent=state.toUpperCase();return el;}
function rejectToken(){operatorToken=null;approvals=null;decisionMessage='The gate rejected that operator token. Paste a fresh one to keep deciding.';renderApprovals();}
function arm(button,fn){
  if(button.dataset.armed){delete button.dataset.armed;button.disabled=true;fn();return;}
  button.dataset.armed='1';const label=button.textContent;button.textContent='Confirm '+label.toLowerCase();button.classList.add('armed');
  setTimeout(()=>{if(button.dataset.armed){delete button.dataset.armed;button.textContent=label;button.classList.remove('armed');}},5000);
}
async function decide(id,decision,noteEl,button){
  try{
    const body={decision};const note=noteEl.value.trim();if(note)body.note=note;
    const response=await fetch('/api/approvals/'+id+'/decision',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+operatorToken},body:JSON.stringify(body)});
    const data=await response.json().catch(()=>({}));
    if(response.status===401||response.status===403){rejectToken();return;}
    decisionMessage=data.message||(response.ok?'Decision recorded: '+decision+'. The caller can now retry the exact call.':'Decision failed.');
  }catch{decisionMessage='Decision failed: dashboard or gate unreachable.';}
  approvalsFingerprint='';
  await pollApprovals(true);
}
function approvalCard(a){
  const card=document.createElement('div');card.className='approval';
  const head=cell(card,'div','','ahead');
  const what=cell(head,'div','','what');
  what.append(stateBadge(a.state),document.createTextNode(' '+a.tool+' on '+a.target));
  cell(head,'div','Requested '+new Date(a.requested_at*1000).toLocaleString(),'meta');
  const meta=cell(card,'div','','meta');
  const idEl=cell(meta,'code',(a.identity||'').slice(0,12)+'…','identity');idEl.title=a.identity||'';
  meta.append(document.createTextNode(' scope '+(a.scope_id||'(none)')+' · hold expires '+new Date(a.expires_at*1000).toLocaleString()));
  if(a.decided_by){const d=cell(card,'div','','meta');d.textContent=(a.state==='rejected'?'Rejected':'Approved')+' by '+a.decided_by+(a.decided_at?' at '+new Date(a.decided_at*1000).toLocaleString():'')+(a.note?' · note: '+a.note:'')+(a.consumed_at?' · consumed at '+new Date(a.consumed_at*1000).toLocaleString():'');}
  const details=cell(card,'details','');cell(details,'summary','Held request payload');
  cell(details,'pre',JSON.stringify(a.request,null,2));
  if(a.state==='pending'){
    const acts=cell(card,'div','','acts');
    const note=cell(acts,'input','');note.type='text';note.placeholder='Optional note for the receipt';note.maxLength=1024;note.setAttribute('aria-label','Decision note');
    const ok=cell(acts,'button','Approve','act');ok.type='button';
    const no=cell(acts,'button','Reject','act reject');no.type='button';
    ok.addEventListener('click',()=>arm(ok,()=>decide(a.id,'approve',note,ok)));
    no.addEventListener('click',()=>arm(no,()=>decide(a.id,'reject',note,no)));
  }
  return card;
}
function renderApprovals(force){
  const list=$('approval-list');const status=$('approval-status');
  if(!operatorToken){
    status.textContent=decisionMessage||'Paste the operator OIDC token from your identity provider. It stays in this tab and goes only to the gate with each approvals request.';
    $('operator-token').hidden=false;$('token-connect').hidden=false;$('token-forget').hidden=true;
    list.replaceChildren();return;
  }
  $('operator-token').hidden=true;$('token-connect').hidden=true;$('token-forget').hidden=false;
  status.textContent=decisionMessage||'Connected. The token stays in this tab; every decision is authenticated and receipted by the gate.';
  decisionMessage='';
  if(!approvals){list.replaceChildren();cell(list,'p','Loading approvals…','empty');return;}
  if(approvals.state!=='ok'){list.replaceChildren();cell(list,'p',approvals.message,'empty');return;}
  const items=approvals.items.slice().sort((x,y)=>{
    const px=x.state==='pending'?0:1,py=y.state==='pending'?0:1;
    if(px!==py)return px-py;
    return px===0?x.expires_at-y.expires_at:y.requested_at-x.requested_at;
  });
  const fingerprint=JSON.stringify(items);
  if(fingerprint===approvalsFingerprint&&list.childElementCount)return;
  if(!force&&list.contains(document.activeElement)&&document.activeElement!==list)return;
  approvalsFingerprint=fingerprint;
  list.replaceChildren();
  if(!items.length){cell(list,'p','No held calls. Nothing is waiting for a decision.','empty');return;}
  items.forEach(a=>list.append(approvalCard(a)));
}
async function pollApprovals(force){
  if(!operatorToken||document.hidden)return;
  try{
    const response=await fetch('/api/approvals',{headers:{'authorization':'Bearer '+operatorToken},cache:'no-store',signal:AbortSignal.timeout(5000)});
    const data=await response.json().catch(()=>({}));
    if(response.status===401||response.status===403){rejectToken();return;}
    if(response.status===404)approvals={state:'disabled',message:'Approval gates are not enabled on this gate. Held calls never open.'};
    else if(!response.ok)approvals={state:'error',message:'Approvals unavailable: '+(data.message||'gate error')+'. The audit view is unaffected.'};
    else approvals={state:'ok',items:data.approvals||[]};
  }catch{approvals={state:'error',message:'Approvals unavailable: gate unreachable. The audit view is unaffected.'};}
  renderApprovals(force);
}
function connectToken(){
  const token=$('operator-token').value.trim();if(!token)return;
  operatorToken=token;$('operator-token').value='';approvals=null;approvalsFingerprint='';decisionMessage='';renderApprovals();pollApprovals();
}
$('token-connect').addEventListener('click',connectToken);
$('operator-token').addEventListener('keydown',e=>{if(e.key==='Enter')connectToken();});
$('token-forget').addEventListener('click',()=>{operatorToken=null;approvals=null;approvalsFingerprint='';decisionMessage='';renderApprovals();});
$('filter').addEventListener('change',renderRows);$('search').addEventListener('input',renderRows);document.addEventListener('visibilitychange',()=>{if(document.hidden)clearUnknown('Polling paused while this page is hidden.');else{poll();pollApprovals();}});renderApprovals();poll();setInterval(poll,10000);setInterval(pollApprovals,10000);

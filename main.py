from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app import app as api_app

app = FastAPI(title="UNG IAM Console", docs_url=None, redoc_url=None, openapi_url=None)

HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>UNG IAM</title>
<style>
:root{--bg:#f4f6f8;--panel:#fff;--ink:#111827;--muted:#667085;--line:#e5e7eb;--nav:#101828;--accent:#1f4d7a;--ok:#067647;--warn:#b54708;--bad:#b42318;--shadow:0 18px 50px rgba(16,24,40,.10)}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink)}button,input,select{font:inherit}.hidden{display:none!important}
.login{min-height:100vh;display:grid;place-items:center;padding:24px}.login-card{width:min(460px,100%);background:var(--panel);border:1px solid var(--line);border-radius:24px;padding:28px;box-shadow:var(--shadow)}
.brand{display:flex;gap:14px;align-items:center;margin-bottom:24px}.mark{width:52px;height:52px;border-radius:16px;background:var(--nav);display:grid;place-items:center;color:#fff;font-weight:800;letter-spacing:.08em}.brand h1{font-size:22px;margin:0}.brand p{margin:4px 0 0;color:var(--muted);font-size:13px}
label{display:block;font-size:13px;font-weight:700;margin:14px 0 7px}.field{width:100%;padding:14px 15px;border:1px solid #d0d5dd;border-radius:12px;background:#fff;outline:none}.field:focus{border-color:#7a9cbc;box-shadow:0 0 0 3px rgba(31,77,122,.1)}
.primary,.secondary,.danger{border:0;border-radius:12px;padding:13px 16px;font-weight:750;cursor:pointer}.primary{background:var(--nav);color:#fff}.secondary{background:#eef2f6;color:var(--ink)}.danger{background:#fee4e2;color:var(--bad)}.wide{width:100%;margin-top:18px}.error{margin-top:12px;color:var(--bad);font-size:13px;min-height:18px}
.shell{min-height:100vh}.topbar{background:var(--nav);color:#fff;padding:14px 18px;position:sticky;top:0;z-index:5}.topbar-inner{max-width:1200px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:10px}.top-title{font-weight:800}.top-sub{font-size:12px;color:#d0d5dd;margin-top:2px}
.main{max-width:1200px;margin:auto;padding:18px}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin:8px 0 18px}.hero h2{margin:0;font-size:26px}.hero p{margin:6px 0 0;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px}.metric{font-size:28px;font-weight:800;margin-top:7px}.small{font-size:12px;color:var(--muted)}
.tabs{display:flex;gap:8px;overflow:auto;padding-bottom:8px;margin-bottom:10px}.tab{white-space:nowrap;border:1px solid var(--line);background:#fff;border-radius:999px;padding:10px 14px;font-weight:700}.tab.active{background:var(--nav);color:#fff;border-color:var(--nav)}
.panel{background:#fff;border:1px solid var(--line);border-radius:18px;overflow:hidden}.panel-head{padding:16px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}.panel-head h3{margin:0}.toolbar{display:flex;gap:8px;flex-wrap:wrap}.content{padding:12px 16px 18px}
.table-wrap{overflow:auto}.table{width:100%;border-collapse:collapse;min-width:720px}.table th,.table td{text-align:left;padding:12px 10px;border-bottom:1px solid #eef0f2;font-size:13px}.table th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}.pill{display:inline-block;padding:5px 9px;border-radius:999px;background:#eef2f6;font-size:11px;font-weight:750}.pill.ok{background:#dcfae6;color:var(--ok)}.pill.off{background:#fee4e2;color:var(--bad)}
.empty{padding:28px;text-align:center;color:var(--muted)}.audit{display:grid;gap:8px}.event{padding:12px;border:1px solid var(--line);border-radius:12px}.event strong{font-size:13px}.event div{font-size:12px;color:var(--muted);margin-top:4px}
.modal{position:fixed;inset:0;background:rgba(16,24,40,.48);display:grid;place-items:end center;padding:18px;z-index:10}.sheet{width:min(560px,100%);background:#fff;border-radius:22px;padding:20px;max-height:90vh;overflow:auto}.sheet h3{margin-top:0}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.actions{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}.note{font-size:12px;color:var(--muted);margin-top:10px}.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#12b76a;margin-right:7px}
@media(max-width:800px){.cards{grid-template-columns:1fr 1fr}.hero{align-items:flex-start;flex-direction:column}.main{padding:14px}.panel-head{align-items:flex-start;flex-direction:column}.row{grid-template-columns:1fr}.topbar{padding-top:calc(12px + env(safe-area-inset-top))}}
@media(max-width:430px){.cards{grid-template-columns:1fr 1fr}.metric{font-size:24px}.login-card{padding:22px}.hero h2{font-size:23px}}
</style>
</head>
<body>
<section id="loginView" class="login">
  <div class="login-card">
    <div class="brand"><div class="mark">IAM</div><div><h1>UNG Identity & Access</h1><p>Corporate administration console</p></div></div>
    <label for="email">Administrator email</label><input id="email" class="field" type="email" autocomplete="username" placeholder="name@organization">
    <label for="password">Password</label><input id="password" class="field" type="password" autocomplete="current-password" placeholder="Enter password">
    <button id="loginBtn" class="primary wide">Sign in</button><div id="loginError" class="error"></div>
    <div class="note">Authorized administrators only. Access is logged.</div>
  </div>
</section>

<section id="appView" class="shell hidden">
  <header class="topbar"><div class="topbar-inner"><div><div class="top-title">UNG IAM</div><div class="top-sub"><span class="status-dot"></span>Production • PostgreSQL</div></div><button id="logoutBtn" class="secondary">Sign out</button></div></header>
  <main class="main">
    <div class="hero"><div><h2>Identity Administration</h2><p id="welcome">Manage people, roles and access across the UNG ecosystem.</p></div><button id="newIdentityBtn" class="primary">+ New identity</button></div>
    <div class="cards">
      <div class="card"><div class="small">Identities</div><div id="identityCount" class="metric">—</div></div>
      <div class="card"><div class="small">Active</div><div id="activeCount" class="metric">—</div></div>
      <div class="card"><div class="small">Roles</div><div id="roleCount" class="metric">—</div></div>
      <div class="card"><div class="small">Audit events</div><div id="auditCount" class="metric">—</div></div>
    </div>
    <div class="tabs"><button class="tab active" data-tab="identities">Identities</button><button class="tab" data-tab="roles">Roles</button><button class="tab" data-tab="audit">Audit</button></div>

    <section id="identitiesPanel" class="panel"><div class="panel-head"><h3>Identities</h3><div class="toolbar"><button class="secondary" onclick="loadAll()">Refresh</button></div></div><div class="content"><div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Email</th><th>Type</th><th>Class</th><th>Roles</th><th>Status</th><th>Action</th></tr></thead><tbody id="identityRows"></tbody></table></div><div id="identityEmpty" class="empty hidden">No identities found.</div></div></section>
    <section id="rolesPanel" class="panel hidden"><div class="panel-head"><h3>Roles & permissions</h3></div><div class="content"><div class="table-wrap"><table class="table"><thead><tr><th>Role</th><th>Description</th><th>Permissions</th></tr></thead><tbody id="roleRows"></tbody></table></div></div></section>
    <section id="auditPanel" class="panel hidden"><div class="panel-head"><h3>Recent audit activity</h3><button class="secondary" onclick="loadAudit()">Refresh</button></div><div class="content"><div id="auditRows" class="audit"></div></div></section>
  </main>
</section>

<div id="identityModal" class="modal hidden"><div class="sheet"><h3>Create identity</h3>
  <div class="row"><div><label>Display name</label><input id="newName" class="field"></div><div><label>Email</label><input id="newEmail" class="field" type="email"></div></div>
  <div class="row"><div><label>Identity type</label><select id="newType" class="field"><option value="human">Human</option><option value="service">Service</option></select></div><div><label>Access class</label><select id="newClass" class="field"><option value="corporate">Corporate</option><option value="vendor">Vendor</option><option value="contractor">Contractor</option><option value="service">Service</option></select></div></div>
  <label>Password <span class="small">(human identities only, minimum 12 characters)</span></label><input id="newPassword" class="field" type="password">
  <label>Role</label><select id="newRole" class="field"></select><div id="modalError" class="error"></div>
  <div class="actions"><button class="secondary" onclick="closeModal()">Cancel</button><button class="primary" onclick="createIdentity()">Create identity</button></div>
</div></div>

<script>
let token=sessionStorage.getItem('ung_iam_token')||'';let me=null;let roles=[];
const $=id=>document.getElementById(id);
async function api(path,opts={}){opts.headers=Object.assign({'Content-Type':'application/json'},opts.headers||{});if(token)opts.headers.Authorization='Bearer '+token;const r=await fetch(path,opts);let data={};try{data=await r.json()}catch(e){}if(!r.ok)throw new Error(data.detail||('Request failed: '+r.status));return data}
async function login(){ $('loginError').textContent='';$('loginBtn').disabled=true;try{const d=await api('/v1/auth/login',{method:'POST',body:JSON.stringify({email:$('email').value.trim(),password:$('password').value})});token=d.access_token;sessionStorage.setItem('ung_iam_token',token);me=d.identity;await showApp()}catch(e){$('loginError').textContent=e.message}finally{$('loginBtn').disabled=false}}
async function showApp(){try{if(!me)me=await api('/v1/me');$('loginView').classList.add('hidden');$('appView').classList.remove('hidden');$('welcome').textContent='Signed in as '+me.display_name+' • '+(me.roles||[]).join(', ');await loadAll()}catch(e){sessionStorage.removeItem('ung_iam_token');token='';$('appView').classList.add('hidden');$('loginView').classList.remove('hidden')}}
async function logout(){try{await api('/v1/auth/logout',{method:'POST'})}catch(e){}sessionStorage.removeItem('ung_iam_token');token='';me=null;location.reload()}
async function loadAll(){await Promise.all([loadIdentities(),loadRoles(),loadAudit()])}
async function loadIdentities(){try{const d=await api('/v1/identities');$('identityCount').textContent=d.count;$('activeCount').textContent=d.results.filter(x=>x.is_active).length;const body=$('identityRows');body.innerHTML='';d.results.forEach(x=>{const tr=document.createElement('tr');tr.innerHTML=`<td><strong>${esc(x.display_name)}</strong></td><td>${esc(x.email||'—')}</td><td>${esc(x.identity_type)}</td><td><span class="pill">${esc(x.access_class)}</span></td><td>${esc((x.roles||[]).join(', ')||'—')}</td><td><span class="pill ${x.is_active?'ok':'off'}">${x.is_active?'Active':'Disabled'}</span></td><td><button class="secondary" onclick="revoke('${x.id}')">Revoke</button></td>`;body.appendChild(tr)});$('identityEmpty').classList.toggle('hidden',d.count!==0)}catch(e){if(e.message.includes('401'))logout()}}
async function loadRoles(){try{const d=await api('/v1/roles');roles=d.results;$('roleCount').textContent=d.count;const body=$('roleRows');body.innerHTML='';roles.forEach(r=>{const tr=document.createElement('tr');tr.innerHTML=`<td><strong>${esc(r.name)}</strong></td><td>${esc(r.description||'')}</td><td>${esc((r.permissions||[]).join(', '))}</td>`;body.appendChild(tr)});const s=$('newRole');s.innerHTML='<option value="">No role</option>'+roles.map(r=>`<option value="${esc(r.name)}">${esc(r.name)}</option>`).join('')}catch(e){}}
async function loadAudit(){try{const d=await api('/v1/audit?limit=50');$('auditCount').textContent=d.count;const box=$('auditRows');box.innerHTML='';d.results.forEach(x=>{const el=document.createElement('div');el.className='event';el.innerHTML=`<strong>${esc(x.event)}</strong><div>${new Date(x.created_at*1000).toLocaleString()}${x.detail?' • '+esc(x.detail):''}</div>`;box.appendChild(el)});if(!d.count)box.innerHTML='<div class="empty">No audit events yet.</div>'}catch(e){$('auditRows').innerHTML='<div class="empty">Audit data unavailable for this role.</div>'}}
async function revoke(id){if(!confirm('Revoke all sessions and service credentials for this identity?'))return;try{await api('/v1/identities/'+id+'/revoke',{method:'POST'});await loadAudit()}catch(e){alert(e.message)}}
function openModal(){$('modalError').textContent='';$('identityModal').classList.remove('hidden')}function closeModal(){$('identityModal').classList.add('hidden')}
async function createIdentity(){try{const type=$('newType').value;const role=$('newRole').value;const payload={display_name:$('newName').value.trim(),email:$('newEmail').value.trim()||null,password:$('newPassword').value||null,identity_type:type,access_class:$('newClass').value,roles:role?[role]:[]};if(type==='service'){payload.email=null;payload.password=null}await api('/v1/identities',{method:'POST',body:JSON.stringify(payload)});closeModal();$('newName').value='';$('newEmail').value='';$('newPassword').value='';await loadAll()}catch(e){$('modalError').textContent=e.message}}
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function setTab(name){document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));['identities','roles','audit'].forEach(n=>$(n+'Panel').classList.toggle('hidden',n!==name))}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>setTab(b.dataset.tab));$('loginBtn').onclick=login;$('logoutBtn').onclick=logout;$('newIdentityBtn').onclick=openModal;$('password').addEventListener('keydown',e=>{if(e.key==='Enter')login()});$('identityModal').addEventListener('click',e=>{if(e.target===$('identityModal'))closeModal()});
if(token)showApp();
</script>
</body></html>'''

@app.get("/", response_class=HTMLResponse)
def console():
    return HTMLResponse(HTML, headers={"Cache-Control":"no-store"})

@app.get("/admin", response_class=HTMLResponse)
def admin_console():
    return HTMLResponse(HTML, headers={"Cache-Control":"no-store"})

app.mount("/", api_app)

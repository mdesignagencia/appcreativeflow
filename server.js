const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'troque-esta-senha-admin-2025';

// ── HELPERS ───────────────────────────────────────────────────────────
function genId() { return crypto.randomBytes(12).toString('hex'); }
function now()   { return new Date().toISOString(); }

app.use(express.json({ limit: '100mb' }));
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
const DEFAULT_DB = { clients:[], creatives:[], requests:[], notifications:[], comments:[], tasks:[], prospects:[], campaigns:[] };

// ── DB READ/WRITE ─────────────────────────────────────────────────────
// No Vercel (serverless), cada request pode rodar em instância diferente.
// Cache em memória é INVÁLIDO entre instâncias — sempre lê do Postgres.
// Usamos um cache de curtíssima duração (150ms) apenas para coalescer
// requests paralelos dentro da MESMA instância, sem stale data entre instâncias.
let _dbCache = null;
let _dbCacheAt = 0;
const DB_CACHE_TTL = 150; // ms — apenas dentro da mesma instância

async function ensureTable() {
  await pool.query(`CREATE TABLE IF NOT EXISTS db_store (id INT PRIMARY KEY, data JSONB NOT NULL)`);
}
let _tableReady = null;
async function getTableReady() {
  if (!_tableReady) _tableReady = ensureTable().catch(e => { _tableReady = null; throw e; });
  return _tableReady;
}

async function getDB() {
  await getTableReady();
  const now = Date.now();
  // Cache válido por DB_CACHE_TTL ms — garante leitura fresca do Postgres a cada request
  if (_dbCache && (now - _dbCacheAt) < DB_CACHE_TTL) return _dbCache;
  const res = await pool.query('SELECT data FROM db_store WHERE id=1');
  if (res.rows.length > 0) {
    _dbCache = res.rows[0].data;
  } else {
    _dbCache = JSON.parse(JSON.stringify(DEFAULT_DB));
    await pool.query('INSERT INTO db_store (id, data) VALUES (1, $1)', [JSON.stringify(_dbCache)]);
  }
  _dbCacheAt = Date.now();
  return _dbCache;
}

async function saveDB(db) {
  // Persiste imediatamente no Postgres e invalida cache local
  await pool.query('UPDATE db_store SET data=$1 WHERE id=1', [JSON.stringify(db)]);
  _dbCache = db;
  _dbCacheAt = Date.now();
}


// ── AUTH ──────────────────────────────────────────────────────────────
function authAdmin(req,res,next) {
  if(req.headers['x-admin-token']!==ADMIN_SECRET) return res.status(401).json({error:'Acesso negado'});
  next();
}
async function authClient(req,res,next) {
  const email=(req.headers['x-client-email']||'').toLowerCase().trim();
  const password=req.headers['x-client-password']||'';
  if(!email||!password) return res.status(401).json({error:'Credenciais ausentes'});
  const db=await getDB();
  const c=db.clients.find(c=>c.email.toLowerCase()===email&&c.password===password&&c.active);
  if(!c) return res.status(401).json({error:'Email ou senha incorretos'});
  req.client=c; next();
}

// ── ADMIN AUTH ────────────────────────────────────────────────────────
app.post('/api/admin/login',(req,res)=>{
  if(req.body.secret!==ADMIN_SECRET) return res.status(401).json({error:'Senha incorreta'});
  res.json({ok:true,token:ADMIN_SECRET});
});

// ── CLIENTS ───────────────────────────────────────────────────────────
app.get('/api/admin/clients',authAdmin,async(req,res)=>{ const db=await getDB(); res.json(db.clients); });

app.post('/api/admin/clients',authAdmin,async(req,res)=>{
  try {
    const {name,email,company,phone,avatar,password}=req.body;
    if(!name||!email) return res.status(400).json({error:'Nome e email obrigatórios'});
    if(!password||password.length<4) return res.status(400).json({error:'Senha deve ter ao menos 4 caracteres'});
    const db=await getDB();
    if(db.clients.find(c=>c.email.toLowerCase()===email.toLowerCase())) return res.status(400).json({error:'Email já cadastrado'});
    const client={id:genId(),name,email:email.toLowerCase(),company:company||'',phone:phone||'',password,avatar:avatar||'',active:true,createdAt:now(),stats:{approved:0,correct:0,rejected:0,pending:0}};
    db.clients.push(client); await saveDB(db);
    const {password:_,...safe}=client;
    res.json({client:safe});
  } catch(e) { console.error('Erro ao criar cliente:',e); res.status(500).json({error:'Erro interno ao criar cliente'}); }
});

app.put('/api/admin/clients/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); const idx=db.clients.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  const {name,email,company,phone,active,avatar,password}=req.body;
  if(name) db.clients[idx].name=name;
  if(email) db.clients[idx].email=email.toLowerCase();
  if(company!==undefined) db.clients[idx].company=company;
  if(phone!==undefined) db.clients[idx].phone=phone;
  if(active!==undefined) db.clients[idx].active=active;
  if(password&&password.length>=4) db.clients[idx].password=password;
  if(avatar) { db.clients[idx].avatar=avatar; }
  await saveDB(db);
  const {password:_,...safe}=db.clients[idx];
  res.json(safe);
});

app.delete('/api/admin/clients/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); db.clients=db.clients.filter(c=>c.id!==req.params.id);
  db.creatives=db.creatives.filter(c=>c.clientId!==req.params.id);
  db.requests=(db.requests||[]).filter(r=>r.clientId!==req.params.id);
  await saveDB(db); res.json({ok:true});
});

// ── CREATIVES (admin) ─────────────────────────────────────────────────
app.post('/api/admin/creatives',authAdmin,async(req,res)=>{
  const {clientId,title,type,platform,fileData,fileName,fileSize,batch,files,scheduleDate,caption}=req.body;
  if(!clientId||!title) return res.status(400).json({error:'clientId e title obrigatórios'});
  const db=await getDB(); const client=db.clients.find(c=>c.id===clientId);
  if(!client) return res.status(404).json({error:'Cliente não encontrado'});
  let filePaths=[];
  if(files&&Array.isArray(files)&&files.length>0){
    for(const f of files){filePaths.push({data:f.data,name:f.name||''});}
  } else if(fileData){
    filePaths.push({data:fileData,name:fileName||''});
  }
  const isCarousel=filePaths.length>1;
  const filePath=filePaths.length>0?filePaths[0].data:null;
  const firstVersion = filePaths.length>0 ? {
    v:1, filePath:filePaths[0].data, filePaths,
    fileName:filePaths.length>0?filePaths[0].name:'', fileSize:filePaths.reduce((s,f)=>s+(f.size||0),0),
    uploadedAt:now(), note:'Versão inicial'
  } : null;
  const creative={id:genId(),clientId,title,type:type||'FEED',platform:platform||'geral',filePath,filePaths,isCarousel,fileName:filePaths.length>0?filePaths[0].name:'',fileSize:filePaths.reduce((s,f)=>s+(f.size||0),0),batch:batch||'',scheduleDate:scheduleDate||null,caption:caption||'',status:'pending',createdAt:now(),updatedAt:now(),comments:[],versions:firstVersion?[firstVersion]:[]};
  db.creatives.push(creative);
  if(!client.stats) client.stats={approved:0,correct:0,rejected:0,pending:0};
  client.stats.pending=(client.stats.pending||0)+1;
  db.notifications=db.notifications||[];
  db.notifications.push({id:genId(),clientId,forClient:true,type:'upload',message:`📁 Novo criativo: "${title}"${isCarousel?' 🎠':''}`,read:false,createdAt:now()});
  await saveDB(db); res.json(creative);
});
app.get('/api/admin/creatives',authAdmin,async(req,res)=>{
  const db=await getDB();
  let list=req.query.clientId?db.creatives.filter(c=>c.clientId===req.query.clientId):db.creatives;
  // By default hide archived unless explicitly requested
  if(req.query.archived!=='true') list=list.filter(c=>c.status!=='archived');
  res.json(list);
});
app.get('/api/admin/creatives/:id',authAdmin,async(req,res)=>{
  const db=await getDB();
  const c=db.creatives.find(c=>c.id===req.params.id);
  if(!c) return res.status(404).json({error:'Não encontrado'});
  res.json(c);
});
app.put('/api/admin/creatives/:id/archive',authAdmin,async(req,res)=>{
  const db=await getDB(); const idx=db.creatives.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  const prev=db.creatives[idx].status;
  db.creatives[idx].status='archived';
  db.creatives[idx].archivedAt=now(); db.creatives[idx].updatedAt=now();
  const client=db.clients.find(c=>c.id===db.creatives[idx].clientId);
  if(client&&client.stats&&prev&&client.stats[prev]>0) client.stats[prev]--;
  await saveDB(db); res.json({ok:true});
});
app.put('/api/admin/creatives/:id/unarchive',authAdmin,async(req,res)=>{
  const db=await getDB(); const idx=db.creatives.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  db.creatives[idx].status='pending'; db.creatives[idx].archivedAt=null; db.creatives[idx].updatedAt=now();
  const client=db.clients.find(c=>c.id===db.creatives[idx].clientId);
  if(client&&client.stats) client.stats.pending=(client.stats.pending||0)+1;
  await saveDB(db); res.json({ok:true});
});
app.put('/api/admin/creatives/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); const idx=db.creatives.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  const {title,batch,status,scheduleDate,caption,viewedAt}=req.body;
  if(title) db.creatives[idx].title=title; if(batch!==undefined) db.creatives[idx].batch=batch;
  if(status) db.creatives[idx].status=status; if(scheduleDate!==undefined) db.creatives[idx].scheduleDate=scheduleDate;
  if(caption!==undefined) db.creatives[idx].caption=caption;
  if(viewedAt!==undefined) db.creatives[idx].viewedAt=viewedAt;
  db.creatives[idx].updatedAt=now(); await saveDB(db); res.json(db.creatives[idx]);
});
app.delete('/api/admin/creatives/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); const idx=db.creatives.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  const cr=db.creatives[idx];
  // file stored as base64, no disk deletion needed
  const client=db.clients.find(c=>c.id===cr.clientId);
  if(client&&client.stats&&cr.status&&client.stats[cr.status]>0) client.stats[cr.status]--;
  db.creatives.splice(idx,1); await saveDB(db); res.json({ok:true});
});

// ── CLEAR ALL CREATIVES (admin util) ────────────────────────────────────
app.delete('/api/admin/creatives',authAdmin,async(req,res)=>{
  const db=await getDB();
  (db.clients||[]).forEach(c=>{ c.stats={approved:0,correct:0,rejected:0,pending:0}; });
  db.notifications=(db.notifications||[]).filter(n=>!['upload','approved','rejected','correct','comment'].includes(n.type));
  db.creatives=[];
  await saveDB(db);
  res.json({ok:true});
});

// ── STATS / ACTIVITY ──────────────────────────────────────────────────
app.get('/api/admin/stats',authAdmin,async(req,res)=>{
  const db=await getDB(),c=db.creatives;
  res.json({totalClients:db.clients.filter(x=>x.active).length,totalCreatives:c.length,approved:c.filter(x=>x.status==='approved').length,rejected:c.filter(x=>x.status==='rejected').length,correct:c.filter(x=>x.status==='correct').length,pending:c.filter(x=>x.status==='pending').length,totalRequests:(db.requests||[]).length});
});
app.get('/api/admin/activity',authAdmin,async(req,res)=>{
  const db=await getDB();
  res.json((db.notifications||[]).filter(n=>n.forAdmin).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,30));
});

// ── REQUESTS ──────────────────────────────────────────────────────────
app.get('/api/admin/requests',authAdmin,async(req,res)=>{ const db=await getDB(); res.json((db.requests||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))); });
app.delete('/api/admin/requests/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); db.requests=(db.requests||[]).filter(r=>r.id!==req.params.id);
  await saveDB(db); res.json({ok:true});
});
app.put('/api/admin/requests/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); const r=(db.requests||[]).find(x=>x.id===req.params.id); if(!r) return res.status(404).json({error:'Não encontrado'});
  const {status,adminNote}=req.body; if(status) r.status=status; if(adminNote!==undefined) r.adminNote=adminNote;
  r.updatedAt=now(); await saveDB(db); res.json(r);
});

// ── TASKS ─────────────────────────────────────────────────────────────
app.get('/api/admin/tasks',authAdmin,async(req,res)=>{ const db=await getDB(); res.json((db.tasks||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))); });
app.post('/api/admin/tasks',authAdmin,async(req,res)=>{
  const {client,title,observations,checkpoints}=req.body;
  if(!title||!client) return res.status(400).json({error:'Cliente e título obrigatórios'});
  const db=await getDB(); if(!db.tasks) db.tasks=[];
  const task={id:genId(),client,title,observations:observations||'',checkpoints:checkpoints||[],status:'ongoing',createdAt:now(),updatedAt:now()};
  db.tasks.push(task); await saveDB(db); res.json(task);
});
app.put('/api/admin/tasks/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); if(!db.tasks) db.tasks=[];
  const idx=db.tasks.findIndex(t=>t.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrada'});
  const {client,title,observations,checkpoints,status}=req.body;
  if(client) db.tasks[idx].client=client; if(title) db.tasks[idx].title=title;
  if(observations!==undefined) db.tasks[idx].observations=observations;
  if(checkpoints!==undefined) db.tasks[idx].checkpoints=checkpoints;
  if(status) db.tasks[idx].status=status;
  db.tasks[idx].updatedAt=now(); await saveDB(db); res.json(db.tasks[idx]);
});
app.delete('/api/admin/tasks/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); if(!db.tasks) db.tasks=[];
  db.tasks=db.tasks.filter(t=>t.id!==req.params.id); await saveDB(db); res.json({ok:true});
});

// ── PROSPECTS ─────────────────────────────────────────────────────────
app.get('/api/admin/prospects',authAdmin,async(req,res)=>{ const db=await getDB(); res.json((db.prospects||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))); });
app.post('/api/admin/prospects',authAdmin,async(req,res)=>{
  const {name,segment,address,contact,instagram,site,priority,description,status}=req.body;
  if(!name) return res.status(400).json({error:'Nome obrigatório'});
  const db=await getDB(); if(!db.prospects) db.prospects=[];
  const p={id:genId(),name,segment:segment||'',address:address||'',contact:contact||'',instagram:instagram||'',site:site||'',priority:priority||'medium',description:description||'',status:status||'active',createdAt:now(),updatedAt:now()};
  db.prospects.push(p); await saveDB(db); res.json(p);
});
app.put('/api/admin/prospects/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); if(!db.prospects) db.prospects=[];
  const idx=db.prospects.findIndex(p=>p.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  const fields=['name','segment','address','contact','instagram','site','priority','description','status'];
  fields.forEach(f=>{if(req.body[f]!==undefined) db.prospects[idx][f]=req.body[f];});
  db.prospects[idx].updatedAt=now(); await saveDB(db); res.json(db.prospects[idx]);
});
app.delete('/api/admin/prospects/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); if(!db.prospects) db.prospects=[];
  db.prospects=db.prospects.filter(p=>p.id!==req.params.id); await saveDB(db); res.json({ok:true});
});

// ── CAMPAIGNS ─────────────────────────────────────────────────────────
app.get('/api/admin/campaigns',authAdmin,async(req,res)=>{ const db=await getDB(); res.json((db.campaigns||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))); });
app.post('/api/admin/campaigns',authAdmin,async(req,res)=>{
  const {title,objective,location,dailyBudget,totalBudget,keywords,destination,startDate,endDate,status}=req.body;
  if(!title) return res.status(400).json({error:'Título obrigatório'});
  const db=await getDB(); if(!db.campaigns) db.campaigns=[];
  const c={id:genId(),title,objective:objective||'',location:location||'',dailyBudget:dailyBudget||'',totalBudget:totalBudget||'',keywords:keywords||'',destination:destination||'',startDate:startDate||'',endDate:endDate||'',status:status||'active',createdAt:now(),updatedAt:now()};
  db.campaigns.push(c); await saveDB(db); res.json(c);
});
app.put('/api/admin/campaigns/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); if(!db.campaigns) db.campaigns=[];
  const idx=db.campaigns.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrada'});
  const fields=['title','objective','location','dailyBudget','totalBudget','keywords','destination','startDate','endDate','status'];
  fields.forEach(f=>{if(req.body[f]!==undefined) db.campaigns[idx][f]=req.body[f];});
  db.campaigns[idx].updatedAt=now(); await saveDB(db); res.json(db.campaigns[idx]);
});
app.delete('/api/admin/campaigns/:id',authAdmin,async(req,res)=>{
  const db=await getDB(); if(!db.campaigns) db.campaigns=[];
  db.campaigns=db.campaigns.filter(c=>c.id!==req.params.id); await saveDB(db); res.json({ok:true});
});

// ── CALENDAR ──────────────────────────────────────────────────────────
app.get('/api/admin/calendar',authAdmin,async(req,res)=>{
  const db=await getDB(); const {month,year}=req.query;
  let list=db.creatives.filter(c=>c.scheduleDate);
  if(month&&year){ list=list.filter(c=>{const d=new Date(c.scheduleDate);return d.getMonth()+1===parseInt(month)&&d.getFullYear()===parseInt(year);}); }
  res.json(list);
});
app.get('/api/client/calendar',authClient,async(req,res)=>{
  const db=await getDB();
  res.json(db.creatives.filter(c=>c.clientId===req.client.id&&c.scheduleDate));
});

// ── CLIENT ENDPOINTS (password auth) ─────────────────────────────────
app.post('/api/client/login',async(req,res)=>{
  const {email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'Email e senha obrigatórios'});
  const db=await getDB();
  const c=db.clients.find(c=>c.email.toLowerCase()===email.toLowerCase().trim()&&c.password===password&&c.active);
  if(!c) return res.status(401).json({error:'Email ou senha incorretos'});
  const {password:_,...safe}=c;
  res.json({ok:true,client:safe});
});

app.get('/api/client/me',authClient,async(req,res)=>{
  const {password:_,...safe}=req.client; res.json(safe);
});
app.get('/api/client/creatives',authClient,async(req,res)=>{
  const db=await getDB(); let list=db.creatives.filter(c=>c.clientId===req.client.id&&c.status!=='archived');
  const {status}=req.query; if(status&&status!=='all') list=list.filter(c=>c.status===status);
  res.json(list);
});
app.get('/api/client/creatives/:id',authClient,async(req,res)=>{
  const db=await getDB();
  const c=db.creatives.find(c=>c.id===req.params.id&&c.clientId===req.client.id&&c.status!=='archived');
  if(!c) return res.status(404).json({error:'Não encontrado'});
  res.json(c);
});
app.put('/api/client/creatives/:id/status',authClient,async(req,res)=>{
  const {status,comment}=req.body;
  if(!['approved','correct','rejected'].includes(status)) return res.status(400).json({error:'Status inválido'});
  const db=await getDB(); const cr=db.creatives.find(c=>c.id===req.params.id&&c.clientId===req.client.id);
  if(!cr) return res.status(404).json({error:'Não encontrado'});
  const old=cr.status; cr.status=status; cr.updatedAt=now();
  const client=db.clients.find(c=>c.id===req.client.id);
  if(client){if(!client.stats)client.stats={approved:0,correct:0,rejected:0,pending:0};if(old&&client.stats[old]>0)client.stats[old]--;client.stats[status]=(client.stats[status]||0)+1;}
  if(comment) cr.comments.push({id:genId(),text:comment,author:req.client.name,createdAt:now()});
  const lbl={approved:'✅ aprovou',rejected:'❌ rejeitou',correct:'⚡ pediu correção em'};
  db.notifications=db.notifications||[];
  db.notifications.push({id:genId(),clientId:req.client.id,forAdmin:true,type:status,message:`${req.client.name} ${lbl[status]}: "${cr.title}"`,creative:{id:cr.id,title:cr.title},read:false,createdAt:now()});
  await saveDB(db); res.json({ok:true,creative:cr});
});
app.put('/api/client/creatives/:id/viewed',authClient,async(req,res)=>{
  const db=await getDB();
  const c=db.creatives.find(c=>c.id===req.params.id&&c.clientId===req.client.id);
  if(!c) return res.status(404).json({error:'Não encontrado'});
  if(!c.viewedAt){ c.viewedAt=now(); await saveDB(db); }
  res.json({ok:true, viewedAt:c.viewedAt});
});
app.post('/api/admin/creatives/:id/version',authAdmin,async(req,res)=>{
  const db=await getDB(); const idx=db.creatives.findIndex(c=>c.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Não encontrado'});
  const {fileData,fileName,fileSize,note,files}=req.body;
  if(!db.creatives[idx].versions) db.creatives[idx].versions=[];
  const vNum=(db.creatives[idx].versions.length||0)+1;
  let newFilePath=fileData||db.creatives[idx].filePath;
  let newFilePaths=db.creatives[idx].filePaths;
  if(files&&files.length>0){newFilePath=files[0].data;newFilePaths=files;}
  const version={v:vNum,filePath:newFilePath,filePaths:newFilePaths,fileName:fileName||db.creatives[idx].fileName,fileSize:fileSize||db.creatives[idx].fileSize,uploadedAt:now(),note:note||`Revisão ${vNum}`};
  db.creatives[idx].versions.push(version);
  // Also update main file to latest version
  db.creatives[idx].filePath=newFilePath;
  db.creatives[idx].filePaths=newFilePaths;
  db.creatives[idx].status='pending'; // reset to pending on new version
  db.creatives[idx].updatedAt=now();
  // Notify client
  const creative=db.creatives[idx];
  db.notifications=db.notifications||[];
  db.notifications.push({id:genId(),clientId:creative.clientId,forClient:true,type:'upload',message:`🔄 Nova versão disponível: "${creative.title}" (v${vNum})`,read:false,createdAt:now()});
  await saveDB(db); res.json(db.creatives[idx]);
});
app.put('/api/client/creatives/:id/caption',authClient,async(req,res)=>{
  const {caption}=req.body;
  const db=await getDB(); const c=db.creatives.find(c=>c.id===req.params.id&&c.clientId===req.client.id);
  if(!c) return res.status(404).json({error:'Não encontrado'});
  c.caption=caption||''; c.updatedAt=now(); await saveDB(db); res.json({ok:true,caption:c.caption});
});
app.post('/api/client/creatives/:id/comment',authClient,async(req,res)=>{
  const {text}=req.body; if(!text) return res.status(400).json({error:'Texto obrigatório'});
  const db=await getDB(); const c=db.creatives.find(c=>c.id===req.params.id&&c.clientId===req.client.id);
  if(!c) return res.status(404).json({error:'Não encontrado'});
  const comment={id:genId(),text,author:req.client.name,createdAt:now()};
  c.comments.push(comment);
  db.notifications.push({id:genId(),clientId:req.client.id,forAdmin:true,type:'comment',message:`💬 ${req.client.name} comentou em "${c.title}": ${text.substring(0,60)}`,creative:{id:c.id,title:c.title},read:false,createdAt:now()});
  await saveDB(db); res.json(comment);
});
app.get('/api/client/notifications',authClient,async(req,res)=>{
  const db=await getDB();
  res.json((db.notifications||[]).filter(n=>n.clientId===req.client.id&&n.forClient&&!n.read).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)));
});
app.get('/api/client/notifications/all',authClient,async(req,res)=>{
  const db=await getDB();
  res.json((db.notifications||[]).filter(n=>n.clientId===req.client.id&&n.forClient).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,30));
});
app.put('/api/client/notifications/read',authClient,async(req,res)=>{
  const db=await getDB(); (db.notifications||[]).forEach(n=>{if(n.clientId===req.client.id&&n.forClient)n.read=true;}); await saveDB(db); res.json({ok:true});
});
app.post('/api/client/requests',authClient,async(req,res)=>{
  const {title,description,urgency,observation,briefingMeta,refs}=req.body; if(!title) return res.status(400).json({error:'Título obrigatório'});
  const db=await getDB(); db.requests=db.requests||[];
  const request={id:genId(),clientId:req.client.id,clientName:req.client.name,title,description:description||'',urgency:urgency||'medium',observation:observation||'',briefingMeta:briefingMeta||null,refs:refs||[],status:'pending',createdAt:now()};
  db.requests.push(request);
  db.notifications.push({id:genId(),clientId:req.client.id,forAdmin:true,type:'request',message:`📋 ${req.client.name} solicitou: "${title}"`,read:false,createdAt:now()});
  await saveDB(db); res.json(request);
});
app.put('/api/client/requests/:id',authClient,async(req,res)=>{
  const db=await getDB(); db.requests=db.requests||[];
  const r=db.requests.find(x=>x.id===req.params.id&&x.clientId===req.client.id);
  if(!r) return res.status(404).json({error:'Não encontrado'});
  if(r.status!=='pending') return res.status(400).json({error:'Já processada'});
  const {title,description,urgency,observation}=req.body;
  if(title) r.title=title; if(description!==undefined) r.description=description;
  if(urgency) r.urgency=urgency; if(observation!==undefined) r.observation=observation;
  r.updatedAt=now(); await saveDB(db); res.json(r);
});
app.get('/api/client/requests',authClient,async(req,res)=>{
  const db=await getDB(); res.json((db.requests||[]).filter(r=>r.clientId===req.client.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)));
});

app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'admin.html')));
app.get('/client',(req,res)=>res.sendFile(path.join(__dirname,'client.html')));
app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'login.html')));

app.listen(PORT,()=>{ console.log(`\n🚀 CreativeFlow porta ${PORT}\n`); });

module.exports = app;

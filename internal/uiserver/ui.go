package uiserver

import (
	"html"
	"io"
	"net/http"
	"strings"
)

// registerShell serves the tabbed console at / .
func (s *Server) registerShell(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		ro := s.readOnly
		s.mu.Unlock()
		mode := "live"
		if ro {
			mode = "read-only"
		}
		out := strings.Replace(shellPage, "<head>", "<head>"+s.tokenScript()+`<meta name="kms-mode" content="`+mode+`">`, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		_, _ = io.WriteString(w, out)
	})
}

// tokenScript embeds the per-run token and makes every same-origin POST
// carry it, so both pages work unchanged when EnableToken is on.
func (s *Server) tokenScript() string {
	s.mu.Lock()
	t := s.token
	s.mu.Unlock()
	if t == "" {
		return ""
	}
	return `<meta name="kms-token" content="` + html.EscapeString(t) + `"><script>(function(){var t=document.querySelector('meta[name=kms-token]').content;var f=window.fetch;window.fetch=function(u,o){o=o||{};if((o.method||"GET").toUpperCase()!=="GET"){o.headers=Object.assign({},o.headers||{},{"X-KMS-Token":t});}return f(u,o);};})();</script>`
}

const shellPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terp KMS console</title>
<style>
:root{
  /* palette from permissionless.money/alpha/zcinti.html ("pearl white") */
  --pearl-bg:#F7F4FF;--pearl-surface:#FCFBFF;--pearl-surface-alt:#EEE9FC;--pearl-text:#3E384A;--pearl-muted:#59516D;
  --pearl-border:#DAD6E8;--pearl-border-strong:#CBC8D5;--pearl-accent:#776C91;--pearl-on-accent:#FFFFFF;
  --paper:#FAF9FD;--spark:#A89DC5;--spring:#6DB978;--amber:#D49564;--cyan:#6DB5A4;
  --space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-5:24px;--space-6:32px;--space-7:48px;
  --radius-1:8px;--radius-2:12px;--radius-3:18px;--radius-pill:999px;
  --font:"Avenir Next","Segoe UI",ui-sans-serif,system-ui,sans-serif;
  --serif:Palatino,"Palatino Linotype","Iowan Old Style",Georgia,serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --fs-xs:11px;--fs-sm:12.5px;--fs-md:14.5px;--fs-lg:18px;--fs-xl:28px;--fs-2xl:40px;
  --lh:1.5;
  --bg:var(--pearl-bg);--surface:var(--pearl-surface);--surface-2:var(--pearl-surface-alt);--border:var(--pearl-border);--border-strong:var(--pearl-border-strong);
  --text:var(--pearl-text);--muted:var(--pearl-muted);--faint:#8A839C;--kicker:var(--spark);
  --accent:var(--pearl-accent);--accent-weak:#E9E5F4;--accent-text:var(--pearl-on-accent);
  --ok:#3F7F4B;--ok-weak:#E3F2E5;--warn:#93592A;--warn-weak:#F8EBDF;--info:#3A7A6B;--info-weak:#E1F1ED;--danger:#A2475A;--danger-weak:#F6E3E8;
  --dot-ok:var(--spring);--dot-warn:var(--amber);--dot-info:var(--cyan);--dot-danger:#C46A7A;
  --shadow:0 1px 2px rgba(62,56,74,.05),0 6px 20px rgba(119,108,145,.08);
  --focus:0 0 0 2px var(--surface),0 0 0 4px var(--pearl-accent);
  color-scheme:light;
}
[data-theme=dark]{
  --pearl-bg:#100D18;--pearl-surface:#1B1824;--pearl-surface-alt:#2A2633;--pearl-text:#EDE9F8;--pearl-muted:#B7B3C4;
  --pearl-border:#373341;--pearl-border-strong:#776C91;--pearl-accent:#CBC8D5;--pearl-on-accent:#211F28;
  --faint:#857F95;--accent-weak:#2E2A3A;
  --ok:var(--spring);--ok-weak:#1C2B20;--warn:var(--amber);--warn-weak:#2F2219;--info:var(--cyan);--info-weak:#182A27;--danger:#E39AA6;--danger-weak:#33191F;--dot-danger:#E39AA6;
  --shadow:0 1px 2px rgba(0,0,0,.35),0 8px 24px rgba(0,0,0,.25);
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:var(--fs-md)/var(--lh) var(--font)}
code,.mono{font-family:var(--mono);font-size:.92em}
a{color:var(--info)}
header.top{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:var(--space-4);padding:var(--space-3) var(--space-5);background:var(--surface);border-bottom:1px solid var(--border)}
.brand{font-family:var(--serif);font-weight:500;font-size:22px;letter-spacing:-.02em}
.brand small{display:block;font-family:var(--font);font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}
.spacer{flex:1}
.tabs{display:flex;gap:var(--space-1);padding:0 var(--space-5);background:var(--surface);border-bottom:1px solid var(--border);overflow-x:auto}
.tab{display:flex;align-items:center;gap:var(--space-2);padding:var(--space-3) var(--space-4);border:0;background:none;color:var(--muted);font:inherit;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}
.tab[aria-selected=true]{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.tab:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible{outline:none;box-shadow:var(--focus)}
main{max-width:1180px;margin:0 auto;padding:var(--space-5)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:var(--space-4)}
.card{grid-column:span 12;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-3);box-shadow:var(--shadow);padding:var(--space-5)}
.card h2{margin:0 0 var(--space-1);font-family:var(--serif);font-weight:500;font-size:24px;letter-spacing:-.01em}
.card h3{margin:var(--space-4) 0 var(--space-2);font-size:var(--fs-md)}
.empty h2{font-family:var(--serif)}
.sub{color:var(--muted);font-size:var(--fs-sm);margin:0 0 var(--space-4)}
.span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-6{grid-column:span 6}
@media(max-width:860px){.span-4,.span-5,.span-6,.span-7,.span-8{grid-column:span 12}}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:var(--radius-pill);font-size:var(--fs-xs);font-weight:600;letter-spacing:.02em;background:var(--surface-2);color:var(--muted);border:1px solid var(--border)}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;opacity:.9}
.pill.ok::before{background:var(--dot-ok)}.pill.warn::before{background:var(--dot-warn)}.pill.info::before{background:var(--dot-info)}.pill.danger::before{background:var(--dot-danger)}
.dv-top{display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-2)}
.layout{display:grid;grid-template-columns:minmax(260px,320px) 1fr;gap:var(--space-4);align-items:start}.layout>aside{position:sticky;top:var(--space-3)}.layout>aside .card{margin:0}.layout>aside .dv-grid{grid-template-columns:1fr}.lh{font:600 var(--fs-xs)/1 var(--font);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0}.icon-btn{border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:999px;width:30px;height:30px;cursor:pointer;margin-left:auto}.icon-btn.on{background:var(--accent);border-color:var(--accent);color:var(--accent-text)}
@media(max-width:860px){.layout{grid-template-columns:1fr}.layout>aside{position:static}}
.dv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:var(--space-3);margin:var(--space-3) 0}
.dv{border:1px solid var(--border);border-radius:12px;padding:var(--space-3);display:flex;flex-direction:column;gap:6px;background:var(--surface-2)}
.dv.ok{border-color:var(--ok)}.dv.danger{opacity:.8}
.dv-h{display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap}
.dv-r{display:flex;align-items:center;gap:var(--space-3);flex-wrap:wrap;font-size:var(--fs-sm)}
.dv-i{display:inline-flex;align-items:baseline;gap:3px;letter-spacing:-1px}.dv-i small{letter-spacing:0;color:var(--muted)}
.dv-add{margin:var(--space-2) 0}
.pill.plain::before{display:none}
.pill.ok{background:var(--ok-weak);color:var(--ok);border-color:transparent}
.pill.warn{background:var(--warn-weak);color:var(--warn);border-color:transparent}
.pill.danger{background:var(--danger-weak);color:var(--danger);border-color:transparent}
.pill.info{background:var(--info-weak);color:var(--info);border-color:transparent}
.pill.live::before{animation:pulse 1.6s infinite}
@keyframes pulse{50%{opacity:.25}}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:var(--space-2) var(--space-4);margin:0}
.kv dt{color:var(--muted);font-size:var(--fs-sm)}.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:var(--space-3);margin:var(--space-3) 0}
.stat{background:var(--surface-2);border-radius:var(--radius-2);padding:var(--space-3)}
.stat b{display:block;font-size:var(--fs-lg)}.stat span{color:var(--kicker);font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.06em}
.stepper{list-style:none;display:flex;gap:0;margin:0 0 var(--space-5);padding:0;counter-reset:s}
.stepper li{flex:1;position:relative;padding-top:34px;text-align:center;font-size:var(--fs-sm);color:var(--faint)}
.stepper li::before{counter-increment:s;content:counter(s);position:absolute;top:0;left:50%;transform:translateX(-50%);width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:var(--fs-sm);background:var(--surface-2);border:2px solid var(--border);color:var(--faint);z-index:1}
.stepper li::after{content:"";position:absolute;top:13px;left:calc(-50% + 16px);right:calc(50% + 16px);height:2px;background:var(--border)}
.stepper li:first-child::after{display:none}
.stepper li.done{color:var(--muted)}.stepper li.done::before{content:"\2713";background:var(--accent);border-color:var(--accent);color:var(--accent-text)}
.stepper li.current.error::before{border-color:var(--dot-danger)}
.stepper li.done::after,.stepper li.current::after{background:var(--accent)}
.stepper li.current{color:var(--text);font-weight:600}.stepper li.current::before{border-color:var(--accent);color:var(--accent);background:var(--accent-weak)}
.stepper li.error::before{border-color:var(--danger);color:var(--danger);background:var(--danger-weak)}
.stepper small{display:block;font-weight:400;color:var(--faint)}
.next{display:flex;gap:var(--space-3);align-items:center;padding:var(--space-3) var(--space-4);border-radius:var(--radius-2);background:var(--info-weak);color:var(--info);font-size:var(--fs-sm);margin-bottom:var(--space-4)}
.next.ok{background:var(--ok-weak);color:var(--ok)}.next.warn{background:var(--warn-weak);color:var(--warn)}.next.danger{background:var(--danger-weak);color:var(--danger)}
.btn{display:inline-flex;align-items:center;gap:var(--space-2);padding:8px 16px;border-radius:var(--radius-pill);border:1px solid var(--border-strong);background:var(--surface);color:var(--text);font:inherit;font-weight:600;cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-text)}
.btn.danger{color:var(--danger)}
.btn.ghost{background:none;border-color:transparent;color:var(--muted)}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.btn .why{font-weight:400;font-size:var(--fs-xs)}
.row{display:flex;gap:var(--space-3);align-items:center;flex-wrap:wrap}
.seg{display:inline-flex;background:var(--surface-2);border-radius:var(--radius-2);padding:3px;gap:2px;margin-bottom:var(--space-4)}
.seg button{border:0;background:none;color:var(--muted);font:inherit;font-weight:600;padding:7px 14px;border-radius:8px;cursor:pointer}
.seg button[aria-pressed=true]{background:var(--surface);color:var(--text);box-shadow:var(--shadow)}
.field{display:flex;flex-direction:column;gap:6px;margin-bottom:var(--space-4)}
.field label{font-weight:600;font-size:var(--fs-sm)}
.field .hint{color:var(--muted);font-size:var(--fs-xs)}
.field input,.field textarea{font:inherit;padding:9px 12px;border-radius:var(--radius-2);border:1px solid var(--border);background:var(--surface);color:var(--text)}
.field.invalid input,.field.invalid textarea{border-color:var(--danger)}
.field .err{color:var(--danger);font-size:var(--fs-xs);min-height:1em}
.field.valid input{border-color:var(--accent)}
.inline{display:flex;gap:var(--space-2)}.inline input{flex:1}
.review{border:1px dashed var(--border);border-radius:var(--radius-2);padding:var(--space-4);background:var(--surface-2)}
pre.msg{max-height:220px;overflow:auto;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-1);padding:var(--space-3);font:var(--fs-xs)/1.5 var(--mono);white-space:pre-wrap;word-break:break-all}
.qr{display:flex;gap:var(--space-5);align-items:flex-start;flex-wrap:wrap}
.qrbox{position:relative;width:240px;height:240px;border-radius:var(--radius-3);background:var(--paper);border:1px solid var(--border);display:grid;place-items:center;overflow:hidden}
.qrbox img{width:100%;height:100%;image-rendering:pixelated}
.qrbox.stale img{filter:blur(4px) grayscale(1);opacity:.4}
.qrbox .veil{position:absolute;inset:0;display:none;place-items:center;text-align:center;padding:var(--space-4);color:#333;font-weight:600}
.qrbox.stale .veil{display:grid}
.ring{height:4px;border-radius:2px;background:var(--surface-2);overflow:hidden;margin-top:var(--space-2);width:240px}
.ring i{display:block;height:100%;background:var(--accent);transition:width 1s linear}
.empty{text-align:center;padding:var(--space-7) var(--space-5);color:var(--muted)}
.empty h2{color:var(--text)}
.empty .icon{font-size:40px;opacity:.6}
.banner{padding:var(--space-3) var(--space-5);font-size:var(--fs-sm);text-align:center}
.banner.ro{background:var(--warn-weak);color:var(--warn)}
.toasts{position:fixed;right:var(--space-5);bottom:var(--space-5);display:flex;flex-direction:column;gap:var(--space-2);z-index:20}
.toast{min-width:260px;max-width:420px;padding:var(--space-3) var(--space-4);border-radius:var(--radius-2);background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--info);box-shadow:var(--shadow);font-size:var(--fs-sm);animation:in .2s ease-out}
.toast.ok{border-left-color:var(--ok)}.toast.danger{border-left-color:var(--danger)}.toast.warn{border-left-color:var(--warn)}
.toast b{display:block}
@keyframes in{from{transform:translateY(8px);opacity:0}}
table{width:100%;border-collapse:collapse;font-size:var(--fs-sm)}
th{text-align:left;color:var(--kicker);font-weight:600;font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.05em}
th,td{padding:var(--space-2) var(--space-3);border-bottom:1px solid var(--border)}
tr.click{cursor:pointer}tr.click:hover{background:var(--surface-2)}
.codes{display:flex;gap:var(--space-2);flex-wrap:wrap}
.code{font:600 var(--fs-lg) var(--mono);letter-spacing:.12em;padding:var(--space-3) var(--space-4);border:1px solid var(--border);border-radius:var(--radius-2);background:var(--surface);cursor:pointer;color:var(--text)}
.code small{display:block;font:var(--fs-xs) var(--font);letter-spacing:0;color:var(--muted)}
.hash{font-family:var(--mono);font-size:var(--fs-sm);word-break:break-all}
.skeleton{background:linear-gradient(90deg,var(--surface-2),var(--border),var(--surface-2));background-size:200% 100%;animation:sk 1.2s infinite;border-radius:6px;height:14px}
@keyframes sk{to{background-position:-200% 0}}
</style></head>
<body>
<header class="top">
  <div class="brand">Terp KMS<small>one engine · every chain it signs for</small></div>
  <span id="engine-pill" class="pill">loading</span>
  <span id="phone-pill" class="pill">phone</span>
  <span id="mode-pill" class="pill plain" hidden>read-only preview</span>
  <div class="spacer"></div>
  <button class="btn ghost" id="theme" aria-label="Toggle light or dark">◐ Theme</button>
</header>
<div id="ro-banner" class="banner ro" hidden>Read-only preview. Forms and reviews work; pairing, grants and broadcasts are disabled and nothing is written to the live Bluetooth link.</div>
<nav class="tabs" role="tablist" id="tabs"></nav>
<main id="view"></main>
<div class="toasts" id="toasts" aria-live="polite"></div>
<script src="/move.js"></script>
<script>
(function(){
"use strict";
var RO=(document.querySelector('meta[name=kms-mode]')||{}).content==="read-only";
var S={vals:[],phone:null,tab:sessionStorage.getItem("tab")||"overview",act:"delegate",owners:{},hold:{},createDraft:{},review:{},grant:{},result:{},errs:{},flow:{},sig:{}};
// Owner is per validator slot and lives on the server (/api/owners), never in
// browser storage: switching tabs switches owner, clearing touches one slot.
// A saved owner wins; otherwise the owner re-encoded from the on-chain valoper.
function derivedOwner(id){var v=(S.vals||[]).filter(function(x){return x.id===id})[0];return v&&v.owner_derived||""}
Object.defineProperty(S,"granter",{get:function(){var o=S.owners[S.tab];return o&&o.granter||derivedOwner(S.tab)}});
function ownerPost(body){body.id=S.tab;return api("/api/owners",body).then(function(r){if(body.clear)delete S.owners[body.id];else S.owners[body.id]=r.owner;delete S.hold[body.id];return r})}
function loadOwners(){return api("/api/owners").then(function(d){S.owners=d.owners||{}}).catch(function(){})}
function halted(v){return !!(v&&v.lag_ms>30000)}
function notValidator(v){return !!(v&&v.onchain&&v.onchain.checked&&!v.onchain.found&&!v.onchain.error&&!halted(v))}
function actOf(v){return notValidator(v)?"create":(S.act==="create"?"delegate":S.act)}
function vname(v){return v.display_name||v.name}
function $(q,el){return (el||document).querySelector(q)}
function esc(t){var d=document.createElement("span");d.textContent=t==null?"":String(t);return d.innerHTML}
function toast(kind,title,msg){var t=document.createElement("div");t.className="toast "+kind;t.innerHTML="<b>"+esc(title)+"</b>"+esc(msg||"");$("#toasts").appendChild(t);setTimeout(function(){t.remove()},kind==="danger"?9000:5000)}
function api(path,body){return fetch(path,{method:body?"POST":"GET",headers:{"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined}).then(function(r){return r.text().then(function(t){var j;try{j=JSON.parse(t)}catch(e){j={error:t.trim()}}if(!r.ok){var e=new Error(j.error||r.statusText);e.status=r.status;e.body=j;throw e}return j})})}
function theme(t){document.documentElement.dataset.theme=t;localStorage.setItem("theme",t)}
theme(localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"));
$("#theme").onclick=function(){theme(document.documentElement.dataset.theme==="dark"?"light":"dark")};
if(RO){$("#mode-pill").hidden=false;$("#mode-pill").className="pill warn plain";$("#ro-banner").hidden=false}
var TERP=/^\d+(\.\d{1,6})?$/;
function statusPill(v){var s=v.status||"unknown",k="";if(s==="signing")k="ok live";else if(/jailed|tombstoned/.test(s))k="danger";else if(/synced|catching/.test(s))k="info";else if(/down|mismatch/.test(s))k="danger";else k="warn";return '<span class="pill '+k+'">'+esc(s)+'</span>'}
function jailPill(v){var j=v.jail;if(!j)return "";if(j.tombstoned)return '<span class="pill danger" title="double-sign: permanent">Tombstoned</span>';if(j.jailed)return '<span class="pill danger" title="'+esc(j.can_unjail?"can unjail now":j.reason)+'">Jailed</span>';if(j.warn)return '<span class="pill warn" title="missed '+j.missed_blocks+' of '+j.max_missed+' allowed">Missing blocks</span>';return ""}
function when(t){var d=new Date(t);if(!t||isNaN(d)||d.getFullYear()<1971)return "—";return d.toLocaleString()+" ("+d.toISOString().replace("T"," ").slice(0,19)+" UTC)"}
function jailBanner(v){var j=v.jail;if(!j)return "";var miss=esc(j.missed_blocks)+" missed of "+esc(j.max_missed)+" allowed in the last "+esc(j.signed_blocks_window)+" blocks";
  if(j.tombstoned)return '<div class="next danger"><b>Tombstoned.</b> This validator double-signed and can never be unjailed. '+miss+'.</div>';
  if(j.jailed)return '<div class="next danger"><b>Jailed</b> (liveness). Jailed until '+esc(when(j.jailed_until))+'. '+miss+'. '+(j.can_unjail?'The jail period has passed: make sure the node signs again, then use <b>Unjail</b> in Validator actions.':'Unjail opens when the jail period ends.')+'</div>';
  if(j.warn)return '<div class="next warn"><b>Liveness warning.</b> '+miss+'. The chain jails this validator once missed blocks pass '+esc(j.max_missed)+'.</div>';
  return ""}
function unjailWhy(v){var j=v.jail;if(!j)return "slashing state not loaded yet";return j.can_unjail?"":j.reason}
function enginePill(v){var e=v.engine||"not served",k=/serving/.test(e)?"ok":/waiting|dialing/.test(e)?"warn":/error|refused/.test(e)?"danger":"";return '<span class="pill '+k+'" title="signing engine">'+esc(e)+'</span>'}
function tabs(){var h='<button class="tab" role="tab" data-tab="overview" aria-selected="'+(S.tab==="overview")+'">Overview <span class="pill plain">'+S.vals.length+'</span></button>';
  S.vals.forEach(function(v){var dot=v.status==="signing"?"ok":/down|mismatch|jailed|tombstoned/.test(v.status)?"danger":/synced|catching/.test(v.status)?"info":"warn";
    h+='<button class="tab" role="tab" data-tab="'+esc(v.id)+'" aria-selected="'+(S.tab===v.id)+'"><span class="pill '+dot+' plain" style="padding:0;width:8px;height:8px;border:0"></span>'+esc(vname(v))+' <small class="pill plain">'+esc(v.chain_id)+'</small>'+(v.jail&&v.jail.jailed?' <small class="pill danger plain">Jailed</small>':'')+'</button>'});
  $("#tabs").innerHTML=h}
$("#tabs").onclick=function(e){var b=e.target.closest("[data-tab]");if(!b)return;S.tab=b.dataset.tab;sessionStorage.setItem("tab",S.tab);render()};
function cur(){for(var i=0;i<S.vals.length;i++)if(S.vals[i].id===S.tab)return S.vals[i];return null}
function headerPills(){var serving=S.vals.filter(function(v){return /serving/.test(v.engine||"")}).length;
  var ep=$("#engine-pill");ep.className="pill "+(serving?"ok live":"warn");ep.textContent=serving+"/"+S.vals.length+" serving";
  var p=S.phone,pp=$("#phone-pill");if(!p){pp.className="pill";pp.textContent="phone ?";return}
  if(p.healthy){pp.className="pill ok live";pp.textContent="phone linked"}else if(p.paired){pp.className="pill warn";pp.textContent="phone paired, idle"}else if(p.bluetooth){pp.className="pill info";pp.textContent="scanning"}else{pp.className="pill";pp.textContent="phone off"}}
function overview(){if(!S.vals.length)return '<div class="card empty"><div class="icon">⌁</div><h2>No validators configured</h2><p>Start the console with <code>--config kms.yaml</code>. Each validator entry gets a tab; each chain slot keeps its own double-sign state.</p></div>';
  var rows=S.vals.map(function(v){return '<tr class="click" data-open="'+esc(v.id)+'"><td><b>'+esc(vname(v))+'</b>'+onchainTag(v)+'<br><small class="mono">'+esc(v.slot)+'</small></td><td>'+esc(v.chain_id)+'</td><td>'+statusPill(v)+' '+jailPill(v)+'</td><td>'+enginePill(v)+'</td><td>'+esc(v.signer)+(v.key_id?' <small class="mono">'+esc(v.key_id)+'</small>':'')+'</td><td class="mono">'+esc(v.height||"—")+'</td><td class="mono">'+esc(v.privval)+'</td></tr>'}).join("");
  return '<div class="grid"><section class="card"><h2>Validators</h2><p class="sub">One engine, one signer connection per validator, one sign-state per slot. Click a row to open its tab.</p><table><thead><tr><th>Validator</th><th>Chain</th><th>Node</th><th>Engine</th><th>Signer</th><th>Height</th><th>Privval</th></tr></thead><tbody>'+rows+'</tbody></table></section></div>'}
function step(list,curIdx,err){return '<ol class="stepper">'+list.map(function(s,i){var c=i<curIdx?"done":i===curIdx?(err?"current error":"current"):"";return '<li class="'+c+'">'+esc(s[0])+'<small>'+esc(s[1])+'</small></li>'}).join("")+'</ol>'}
function btn(label,attrs,disabledWhy,kind){var d=disabledWhy?' disabled title="'+esc(disabledWhy)+'"':'';return '<button class="btn '+(kind||"")+'" '+attrs+d+'>'+esc(label)+(disabledWhy?' <span class="why">· '+esc(disabledWhy)+'</span>':'')+'</button>'}
function rssiBars(r){if(r==null)return '<span class="dv-i" title="signal unknown">▁</span>';var n=r>-60?4:r>-70?3:r>-80?2:1;return '<span class="dv-i" title="RSSI '+r+' dBm">'+"▁▃▅▇".slice(0,n)+'<small>'+r+'</small></span>'}
function devCard(d){var st={up:["ok","●","sealed"],connecting:["warn","◌","dialing"],down:["danger","○","down"],pending:["info","◈","verify"],standby:["info","◇","member · no slot"]}[d.link]||["","○",d.link];
  var slots=(d.slots||[]).map(function(x){return '<span class="pill plain">'+esc(x==="*"?"all unpinned":x)+'</span>'}).join(" ")||'<span class="sub">no slots</span>';
  var lat=d.last_ms?'<span class="dv-i" title="last vote round-trip">⏱<small>'+esc(d.last_ms)+'ms</small></span>':'';
  var fp=d.fingerprint&&window.fpTiles?fpTiles(d.fingerprint.replace(/ /g,""),"phone identity"):'';
  var acts='';
  if(d.pending)acts=btn("Fingerprints match",'data-do="pin"',RO?"read-only":"","primary")+(d.code?btn("Reject",'data-drop="'+esc(d.code)+'"',RO?"read-only":"","danger"):'');
  else if(d.code)acts=btn("Drop link",'data-drop="'+esc(d.code)+'"',RO?"read-only":"","ghost");
  return '<div class="dv '+st[0]+'"><div class="dv-h"><span class="pill '+st[0]+'" title="link">'+st[1]+' '+esc(st[2])+'</span><b>'+esc(d.label)+'</b><small class="mono sub">'+esc(d.id)+'</small></div>'+
    '<div class="dv-r"><span class="dv-i" title="pairing code">⌁<small class="mono">'+esc(d.code||"—")+'</small></span>'+rssiBars(d.rssi)+lat+'</div>'+
    '<div class="dv-r" title="slots this phone signs">◎ '+slots+'</div>'+(fp?'<div class="dv-fp">'+fp+'</div>':'')+(acts?'<div class="row">'+acts+'</div>':'')+'</div>'}
function pairCard(){var p=S.phone||{};var devs=p.devices||[];var chosen=p.codes||[];var max=p.max_links||7;
  var up=devs.filter(function(d){return d.link==="up"}).length;
  var dial=devs.some(function(d){return d.link==="connecting"})||p.link==="connecting"||chosen.length>0;
  var ls=!p.bluetooth?["","○","off"]:up?["ok live","●","connected"]:dial?["warn","◌","connecting"]:["","○","idle"];
  var head='<div class="dv-top"><h2 class="lh">ᛒ Phones</h2><span class="pill '+ls[0]+'" title="Bluetooth link">'+ls[1]+' '+ls[2]+'</span><span class="pill plain" title="sealed sessions">🔒 '+up+'/'+devs.filter(function(d){return !d.pending}).length+'</span><span class="pill plain" title="concurrent Bluetooth links">⇄ '+chosen.length+'/'+max+'</span><button class="icon-btn'+(p.bluetooth?" on":"")+'" data-do="'+(p.bluetooth?"bt-off":"bt-on")+'" title="'+(p.bluetooth?"Bluetooth is on · tap to turn off":"Bluetooth is off · tap to turn on")+'" aria-label="Bluetooth '+(p.bluetooth?"on":"off")+'"'+(RO?" disabled":"")+'>⏻</button></div>';
  var free=Object.keys(p.seen||{}).filter(function(c){return chosen.indexOf(c)<0});
  var add='';
  if(p.bluetooth){add=free.length&&chosen.length<max?'<div class="dv-add"><small class="sub">＋ add phone · pick the code your phone shows</small><div class="codes">'+free.map(function(c){return '<button class="code" data-pair="'+esc(c)+'"'+(RO?' disabled':'')+'>'+esc(c)+'<small>rssi '+esc(p.seen[c])+'</small></button>'}).join("")+'</div></div>':(chosen.length<max?'<p class="sub">＋ open KMS on another phone to add it.</p>':'')}
  var kfp=p.kms_fingerprint?'<small class="sub">this console · <span class="mono">'+esc(p.kms_fingerprint)+'</span></small>':'';
  var grid=devs.length?'<div class="dv-grid">'+devs.map(devCard).join("")+'</div>':'<div class="empty" style="padding:16px">No phones yet. Turn on Bluetooth and pick your phone\'s code.</div>';
  var pairQR=(!p.paired&&S.vals.length)?'<div class="qr" style="margin-top:12px"><img alt="Pairing QR" width="160" height="160" src="/slot-qr.png?pair=1"></div>':'';
  return '<section class="card" id="phones">'+head+(p.error?'<div class="next danger">'+esc(p.error)+'</div>':'')+grid+add+kfp+pairQR+'</section>'}
function onchainTag(v){var o=v.onchain;if(halted(v)&&!(o&&o.found))return ' <span class="pill warn plain" title="No new blocks; validator status not re-checked">⏸ chain halted</span>';if(!o||!o.checked)return "";if(!o.found)return ' <span class="pill warn plain">not a validator yet</span>';return ' <small class="sub">on-chain “'+esc(o.moniker)+'”</small>'}
function namesBlock(v){var o=v.onchain||{};var own=S.owners[v.id]||{};
  var h='<dl class="kv" style="margin:8px 0"><dt>Name on phone</dt><dd>'+(v.phone_names?esc(v.phone_name||"—"):'<span class="sub">this zigner does not send names yet</span>')+'</dd><dt>Console name</dt><dd>'+esc(own.name||"—")+'</dd><dt>On-chain moniker</dt><dd>'+(o.checked?(o.found?esc(o.moniker)+' <span class="mono sub">'+esc(o.valoper)+'</span>':'<span class="pill warn plain">no validator for this key</span>'):'<span class="sub">checking…</span>')+'</dd></dl>';
  if(v.phone_names&&own.name&&v.phone_name&&own.name!==v.phone_name)h+='<div class="next warn">The phone calls this key “'+esc(v.phone_name)+'”. The phone name wins; rename on the phone or set the console name to match.</div>';
  return h+'<div class="inline"><input id="console-name" maxlength="40" placeholder="'+esc(vname(v))+'" value="'+esc(own.name||"")+'">'+btn("Save name",'id="name-save"',RO?"read-only":"","ghost")+'</div>'}
function slotKeyBlock(v){if(v.signer!=="phone")return "";
  if(v.phone_key)return '<dl class="kv" style="margin:8px 0 16px"><dt>Phone key</dt><dd><span class="pill ok">on phone</span> <span class="mono">'+esc(v.phone_key_id)+'</span></dd><dt>Phone slot</dt><dd class="mono">'+esc(v.slot_name)+'</dd></dl>'+(window.moveBlock?moveBlock(v):"");
  return '<div class="review" style="margin:8px 0 16px"><h3 style="margin-top:0">Add this validator\'s key to your phone</h3><div class="qr"><figure style="margin:0;text-align:center"><img alt="'+esc(v.name)+' key QR" width="200" height="200" src="/slot-qr.png?id='+encodeURIComponent(v.id)+'"><figcaption class="sub"><b>'+esc(v.name)+'</b> · '+esc(v.chain_id)+' · slot '+esc(v.slot_name)+'</figcaption></figure><ol class="sub" style="max-width:360px"><li>On the phone, open Zigner and tap <b>New validator</b>.</li><li>Scan this QR. It names the slot <b>'+esc(v.slot_name)+'</b>, so the phone makes a new key for '+esc(v.name)+' instead of reusing another validator\'s key.</li><li>Tap <b>Start</b> for '+esc(v.name)+' on the phone.</li><li>This tab updates when the phone publishes the key.</li></ol></div></div>'}
function validatorView(v){
  var ph=S.phone||{};
  var e=v.engine||"";var needKey=v.signer==="phone"&&!v.phone_key;
  var jailed=v.jail&&v.jail.jailed;var life=needKey?0:jailed&&/serving/.test(e)?3:v.status==="signing"?4:/serving/.test(e)?3:/waiting for node/.test(e)?2:1;
  var lifeNext=["Add "+v.name+"'s key to your phone (below).",
    /waiting for arm/.test(e)?"Key is on the phone. The engine is waiting for the arm marker.":"Key is on the phone. Engine: "+(e||"not running")+".",
    "Waiting for the "+v.name+" node to open its privval socket ("+v.privval+"). Not an error.",
    jailed?"Serving, but the validator is jailed: it has no voting power until it is unjailed.":"Serving. On the phone, make sure "+v.name+" is started; the node is "+(v.status||"unknown")+".",
    "Signing. Use the actions below to manage stake and info."][life];
  var h='<div class="grid"><section class="card span-8"><div class="row"><h2 style="margin:0">'+esc(v.name)+'</h2>'+statusPill(v)+jailPill(v)+enginePill(v)+'</div><p class="sub">'+esc(v.chain_id)+(v.slot!==v.chain_id?' · slot '+esc(v.slot):'')+' · '+esc(v.source)+'</p>'+
  step([["Phone key","on phone"],["Engine","armed"],["Node","privval connected"],["Signing","votes signed"],["Active","in set"]],life,/down|mismatch|error/.test(v.status+e))+
  '<div class="next '+(life===4?"ok":"")+'">'+esc(lifeNext)+'</div>'+jailBanner(v)+slotKeyBlock(v)+
  '<div class="stats"><div class="stat"><span>Height</span><b class="mono">'+esc(v.height||"—")+'</b></div><div class="stat"><span>Block lag</span><b>'+(v.lag_ms?(v.lag_ms/1000).toFixed(1)+"s":"—")+(halted(v)?' <span class="pill warn plain">⏸ halted</span>':"")+'</b></div><div class="stat"><span>Voting power</span><b>'+esc(v.voting_power||"0")+'</b></div><div class="stat"><span>Last signed</span><b class="mono">'+esc(v.last_signed||"—")+'</b></div></div>'+
  '<dl class="kv"><dt>Node RPC</dt><dd class="mono">'+esc(v.rpc||"none in config")+'</dd><dt>Privval</dt><dd class="mono">'+esc(v.privval)+'</dd><dt>Signer</dt><dd>'+esc(v.signer)+' <span class="mono">'+esc(v.signer_ref||"")+'</span></dd><dt>Key id</dt><dd class="mono">'+esc(v.key_id||"—")+'</dd><dt>Consensus addr</dt><dd class="mono">'+esc(v.consensus_addr||"—")+'</dd></dl>'+(v.error?'<div class="next danger" style="margin-top:12px">'+esc(v.error)+'</div>':'')+'</section>'+
  '<section class="card span-4"><h2>Owner</h2><p class="sub">Every action is one transaction signed by this account on the phone; it pays the THIOL fee.</p><div class="field" id="f-granter"><label for="granter">Owner account</label><input id="granter" class="mono" placeholder="terp1…" value="'+esc(S.granter)+'" autocomplete="off" spellcheck="false"><span class="hint">'+(!(S.owners[v.id]||{}).granter&&v.owner_derived?'<span class="pill info plain" title="Derived from '+esc((v.onchain||{}).valoper||"")+' (same bytes, account prefix)">⇄ valoper</span> ':"")+'Offline account that owns this validator. Never a key.</span><span class="err"></span></div>'+ownerBlock()+namesBlock(v)+'<div id="holdings">'+holdingsView(v)+'</div></section>'+
  actionsCard(v)+'</div>';
  return h}
function holdingsView(v){var d=S.hold[v.id];if(!S.granter)return '<p class="sub">Enter the owner account to load balances.</p>';if(!d)return '<div class="skeleton"></div>';if(d.error)return '<div class="next danger">'+esc(d.error)+'</div>';var f=d.fmt;
  return '<div class="stats" style="grid-template-columns:1fr 1fr"><div class="stat"><span>Available</span><b>'+esc(f.spendable)+'</b><span>TERP</span></div><div class="stat"><span>Delegated</span><b>'+esc(f.delegated)+'</b><span>TERP</span></div><div class="stat"><span>Rewards</span><b>'+esc(f.rewards)+'</b><span>TERP</span></div><div class="stat"><span>Commission</span><b>'+esc(f.commission)+'</b><span>TERP</span></div><div class="stat" style="grid-column:span 2"><span>Gas balance</span><b>'+esc(f.thiol)+'</b><span>THIOL · each action costs 0.02–0.03</span></div></div>'+(d.holdings.validator_found?'':'<div class="next warn">Validator '+esc(d.holdings.validator.operator)+' is not on chain yet.</div>')}
var ACTS=[["delegate","Self-delegate"],["undelegate","Undelegate"],["rewards","Claim rewards"],["edit","Update info"],["unjail","Unjail"]];
function flowIdx(id){var f=S.flow[id]||"form";return {form:0,review:1,grant:2,broadcast:3,result:4}[f]}
function actionsCard(v){var f=S.flow[v.id]||"form";var idx=flowIdx(v.id);var res=S.result[v.id];
  var h='<section class="card"><h2>Validator actions</h2><p class="sub">Every action: fill the form, review exactly what will be signed, sign that one transaction on the phone, then broadcast it. Nothing is sent before Broadcast.</p>';
  if(notValidator(v))h+='<div class="next info">This slot\'s phone key ('+esc(v.phone_key_id)+') is not a validator on '+esc(v.chain_id)+' yet. The only action is <b>Create validator</b>: one MsgCreateValidator signed by the owner, with this phone key as the consensus key.</div>';else h+='<div class="seg" role="group">'+ACTS.map(function(a){var hide=a[0]==="unjail"&&!(v.jail&&v.jail.jailed)&&S.act!=="unjail";if(hide)return "";return '<button data-act="'+a[0]+'" aria-pressed="'+(S.act===a[0])+'"'+(f!=="form"?' disabled':'')+'>'+a[1]+(a[0]==="unjail"?' <span class="pill danger plain">jailed</span>':'')+'</button>'}).join("")+'</div>';
  h+=step([["Details","form"],["Review","what is signed"],["Sign on phone","QR + scan"],["Broadcast","one tx"],["Result","on chain"]],idx,res&&res.error);
  if(f==="form")h+=formView(v);else if(f==="review")h+=reviewView(v);else if(f==="grant")h+=grantView(v);else if(f==="broadcast")h+='<div class="next">Broadcasting and waiting for the block…</div>';else h+=resultView(v);
  return h+'</section>'}
function fld(id,label,hint,val,ph,extra){var e=(S.errs[id]||"");return '<div class="field'+(e?" invalid":"")+'" id="f-'+id+'"><label for="'+id+'">'+label+'</label>'+(extra||'<input id="'+id+'" value="'+esc(val||"")+'" placeholder="'+esc(ph||"")+'" autocomplete="off">')+'<span class="hint">'+hint+'</span><span class="err">'+esc(e)+'</span></div>'}
function formView(v){var d=S.hold[v.id],f=d&&d.fmt,vi=d&&d.holdings.validator||{};var a=actOf(v),h='';
  var ready=S.granter&&d&&!d.error;
  if(a==="delegate")h+=fld("amount","Amount (TERP)","Available "+(f?f.spendable:"—")+" TERP. Up to 6 decimals.","","0.000000",'<div class="inline"><input id="amount" inputmode="decimal" placeholder="0.000000"><button class="btn ghost" data-max="spendable">Max</button></div>');
  if(a==="undelegate")h+=fld("amount","Amount (TERP)","Delegated "+(f?f.delegated:"—")+" TERP. Unbonding locks funds for the unbonding period.","","0.000000",'<div class="inline"><input id="amount" inputmode="decimal" placeholder="0.000000"><button class="btn ghost" data-max="delegated">Max</button></div>');
  if(a==="rewards")h+='<div class="review"><dl class="kv"><dt>Delegator rewards</dt><dd>'+(f?f.rewards:"—")+' TERP</dd><dt>Validator commission</dt><dd>'+(f?f.commission:"—")+' TERP</dd></dl><p class="hint">Both are withdrawn in one MsgExec.</p></div>';
  if(a==="edit"){h+='<p class="sub">Leave a field unchanged to keep it; only changed fields are sent, the rest as [do-not-modify].</p><div class="grid"><div class="span-6">'+fld("moniker","Moniker","≤ 70 characters",vi.moniker)+fld("website","Website","https://…",vi.website)+fld("identity","Identity","Keybase id or similar",vi.identity)+'</div><div class="span-6">'+fld("security_contact","Security contact","email",vi.security_contact)+fld("details","Details","≤ 280 characters","","",'<textarea id="details" rows="3">'+esc(vi.details||"")+'</textarea>')+fld("commission_percent","Commission (%)","Now "+(d?esc(d.rate_pct):"—")+", max "+(d?esc(d.max_rate_pct):"—")+", may change by "+(d?esc(d.max_change_pct):"—")+" per 24h",d&&d.rate_pct?d.rate_pct.replace("%",""):"")+'</div></div>'}
  if(a==="create"){var c=S.createDraft[v.id]||{};function cv(k,d){return c[k]!=null?c[k]:d}
    h+='<div class="grid"><div class="span-6">'+fld("moniker","Moniker","Prefilled from the validator name. ≤ 70 characters.",cv("moniker",vname(v)))+fld("identity","Identity","Keybase id (optional)",cv("identity",""))+fld("website","Website","https://… (optional)",cv("website",""))+fld("security_contact","Security contact","email (optional)",cv("security_contact",""))+fld("details","Details","≤ 280 characters (optional)","","",'<textarea id="details" rows="3">'+esc(cv("details",""))+'</textarea>')+'</div>'+
    '<div class="span-6">'+fld("rate_percent","Commission rate (%)","Starting commission",cv("rate_percent","5"))+fld("max_rate_percent","Max commission (%)","Can never be changed after creation",cv("max_rate_percent","20"))+fld("max_change_percent","Max daily change (%)","Can never be changed after creation",cv("max_change_percent","1"))+fld("min_self_delegation","Min self delegation (uterp)","The validator is jailed if self-delegation drops below this",cv("min_self_delegation","1"))+
    fld("amount","Self-delegation (TERP)","Available "+(f?f.spendable:"—")+" TERP. Bonded from the owner account.","","0.000000",'<div class="inline"><input id="amount" inputmode="decimal" placeholder="0.000000" value="'+esc(cv("amount",""))+'"><button class="btn ghost" data-max="spendable">Max</button></div>')+
    fld("consensus_pubkey_hex","Consensus key (phone, ed25519)","This slot\'s phone key '+esc(v.phone_key_id)+'. Fixed by the console.","","",'<input id="consensus_pubkey_hex" class="mono" readonly value="'+esc(v.phone_pub||"phone has not published a key yet")+'">')+'</div></div>'}
  if(a==="unjail"){var j=v.jail||{};h+='<div class="review"><dl class="kv"><dt>Validator</dt><dd class="mono">'+esc(j.operator||"—")+'</dd><dt>Jailed until</dt><dd>'+esc(when(j.jailed_until))+'</dd><dt>Missed blocks</dt><dd>'+esc(j.missed_blocks)+' of '+esc(j.max_missed)+' allowed / '+esc(j.signed_blocks_window)+' blocks</dd><dt>Tombstoned</dt><dd>'+(j.tombstoned?"yes":"no")+'</dd></dl><p class="hint">Sends <code>MsgUnjail</code> in one tx signed by the owner. Only the operator account can unjail. Make sure the node is signing first, or it will be jailed again.</p></div>'}
  if(S.errs.action)h+='<div class="next danger">'+esc(S.errs.action)+'</div>';
  var why=!S.granter?"enter the owner account":!d?"loading balances":d.error?"rpc unavailable":a==="unjail"?unjailWhy(v):"";
  return h+'<div class="row">'+btn("Review",'data-do="review"',why,"primary")+'</div>'}
function reviewView(v){var r=S.review[v.id];var h='<div class="review"><h3 style="margin-top:0">'+esc(r.title)+'</h3><dl class="kv">'+r.lines.map(function(l){return '<dt>'+esc(l.label)+'</dt><dd>'+esc(l.value)+'</dd>'}).join("")+'<dt>Fee</dt><dd>'+fmtU(r.exec_fee_uthiol)+' THIOL, paid by the owner <span class="mono">'+esc(r.fee_payer||r.granter)+'</span></dd><dt>Gas</dt><dd>'+esc(r.gas)+'</dd><dt>Memo</dt><dd class="mono">'+esc(r.memo)+'</dd><dt>Fingerprint</dt><dd class="mono">'+esc(r.fingerprint)+'</dd></dl><h3>Messages, exactly as signed</h3>'+r.messages.map(function(m){return '<div class="mono" style="font-size:12px;margin-top:8px">'+esc(m.type_url)+'</div><pre class="msg">'+esc(JSON.stringify(m.json,null,2))+'</pre>'}).join("")+'</div>';
  return h+'<div class="row" style="margin-top:16px">'+btn("Back to edit",'data-do="back"',"","ghost")+btn("Sign on phone",'data-do="to-grant"',RO?"read-only preview stops at review":"","primary")+'</div>'}
function fmtU(u){u=String(u||"0");while(u.length<7)u="0"+u;var s=u.slice(0,-6)+"."+u.slice(-6);return s.replace(/0+$/,"").replace(/\.$/,"")}
function grantView(v){var g=S.grant[v.id]||{};var h='';
  if(g.error)return '<div class="next danger">'+esc(g.error)+'</div><div class="row">'+btn("Back",'data-do="back"',"","ghost")+'</div>';
  if(!g.kind)return '<div class="skeleton" style="width:240px;height:240px"></div>';
  var blind=(S.review[v.id].messages||[]).some(function(m){return /MsgUnjail|MsgEditValidator|MsgWithdrawValidatorCommission/.test(m.type_url)});
  var qleft=Math.max(0,(new Date(g.qr_expires_at)-Date.now())/1000),pct=Math.min(100,qleft/6);var sg=S.sig[v.id]||{};var ok=sg.ok&&sg.auth_id===g.auth_id;
  h+='<div class="qr"><div><div class="qrbox'+(g.stale?" stale":"")+'" id="qrbox"><img alt="sign QR" src="data:image/png;base64,'+g.png+'"><div class="veil">Account sequence moved.<br>Refreshing QR…</div></div><div class="ring"><i style="width:'+pct+'%"></i></div><small class="sub" id="qrmeta">QR '+esc(g.auth_id)+' · '+esc(g.chain_id||"")+' · account '+esc(g.account)+' · seq '+esc(g.sequence)+' · amino JSON · <span id="qrleft">'+qrLeft(g)+'</span></small></div>';
  h+='<div style="flex:1;min-width:260px"><ol><li>Open Zigner → scan this QR (it signs as the owner account).</li><li>Check it shows only: '+(S.review[v.id].messages.map(function(m){return m.type_url.split(".").pop()}).join(", "))+', fee '+fmtU(g.fee_uthiol)+' THIOL.'+(blind?' Zigner does not decode this message type yet, so it shows the raw JSON: compare it with the review.':'')+'</li><li>Zigner shows a signature QR (<code>ur:cworch-sig</code>). Scan it here.</li></ol>';
  h+='<div class="row">'+btn("Scan signature",'data-do="sig-scan"',"","primary")+'</div>';
  if(sg.progress)h+='<div class="next">Reading animated signature QR: '+sg.progress.have+' of '+sg.progress.need+' frames…</div>';
  if(ok)h+='<div class="next ok">✓ Signature verified: signed by '+esc(sg.signer)+' over QR '+esc(sg.auth_id)+' ('+esc(sg.format)+(sg.high_s?", high-S normalized":"")+').</div>';
  else if(sg.reason)h+='<div class="next danger"><b>Signature did not verify'+(sg.mismatch?' — wrong '+esc({key:"account key",sequence:"sequence",account:"account number",chain:"chain id",doc:"document",format:"QR format",signature:"signature"}[sg.mismatch]||sg.mismatch):'')+'.</b> '+esc(sg.reason)+'</div>';
  h+='<details style="margin-top:8px"'+(S.sigPaste?" open":"")+'><summary>Camera not working? Paste the signature text</summary>'+fld("payload","Phone signature","Paste one ur:cworch-sig/… per line (all frames for an animated QR).","","ur:cworch-sig/…")+'<div class="row">'+btn("Verify pasted",'data-do="sig-paste"',"","ghost")+'</div></details>';
  h+='<div class="row" style="margin-top:12px">'+btn("Back",'data-do="back"',"","ghost")+btn("Broadcast",'data-do="sig"',RO?"read-only":!ok?"scan and verify the signature first":"","primary")+'</div></div></div>';
  return h}
function qrLeft(g){var l=Math.max(0,Math.round((new Date(g.qr_expires_at)-Date.now())/1000));return l?"QR refreshes in "+Math.floor(l/60)+":"+("0"+l%60).slice(-2):"QR refreshing…"}
function sigVerify(v,frames,done){var o=ownerGet();return api("/api/actions/verify",{id:v.id,frames:frames,owner_pubkey_hex:o&&o.pubkey_hex||""}).then(function(r){S.sig[v.id]=r;if(!r.progress&&done)done();render();return r}).catch(function(e){S.sig[v.id]=e.body||{reason:e.message};if(done)done();render();return S.sig[v.id]})}
function sigScan(v){var frames=[];scanStart(function(t){if(!/^ur:cworch-sig\//i.test(t)&&!/^(0x)?[0-9a-f]{128}([0-9a-f]{66})?$/i.test(t)){SCAN&&SCAN.say("That QR is not a signature: "+t.slice(0,24)+"…");return false}
  if(frames.indexOf(t.toLowerCase())>=0)return false;frames.push(t.toLowerCase());
  sigVerify(v,frames.slice(),scanStop).then(function(r){if(r&&r.progress&&SCAN)SCAN.say("Animated QR: "+r.progress.have+" of "+r.progress.need+" frames. Keep it in view.")});return false},"Hold zigner's signature QR in the frame.")}

function resultView(v){var r=S.result[v.id]||{},x=r.tx||{};var bad=r.error||x.stage!=="committed";return '<div class="next '+(bad?(x.stage==="pending"?"warn":"danger"):"ok")+'">'+esc(r.summary||r.error||"")+(r.error&&r.summary?'<br>'+esc(r.error):'')+'</div><dl class="kv"><dt>Tx hash</dt><dd class="hash">'+esc(x.hash||"—")+'</dd><dt>Stage</dt><dd>'+esc(x.stage||"—")+'</dd><dt>Height</dt><dd>'+esc(x.height||"—")+'</dd><dt>Code</dt><dd>'+esc(x.code==null?"—":x.code)+'</dd>'+(x.log&&x.code?'<dt>Log</dt><dd class="mono">'+esc(x.log)+'</dd>':'')+(r.status?'<dt>Validator</dt><dd>'+esc(r.status.replace("BOND_STATUS_","").toLowerCase())+(r.jailed?", jailed":", not jailed")+'</dd>':'')+(r.power_note?'<dt>Active set</dt><dd>'+esc(r.power_note)+'</dd>':'')+'</dl><div class="row" style="margin-top:16px">'+btn("New action",'data-do="reset"',"","primary")+'</div>'}
function render(){tabs();headerPills();var v=cur();var html=v?validatorView(v):overview();$("#view").innerHTML='<div class="layout"><aside>'+pairCard()+'</aside><div class="main">'+html+'</div></div>';wire(v)}
function setErr(id,msg){S.errs[id]=msg;var f=$("#f-"+id);if(!f)return;f.classList.toggle("invalid",!!msg);f.classList.toggle("valid",!msg&&!!($("input,textarea",f)||{}).value);$(".err",f).textContent=msg||""}
function validateGranter(x){return /^terp1[02-9ac-hj-np-z]{38}$/.test(x)?"":"a terp1… account (39 characters after terp1)"}
function validateAmount(x,v){if(!x)return "required";if(!TERP.test(x))return "a number with up to 6 decimals";if(Number(x)<=0)return "must be above zero";var d=S.hold[v.id];if(d&&!d.error){var un=actOf(v)==="undelegate";var cap=un?d.holdings.delegated_uterp:d.holdings.spendable_uterp;if(Math.round(Number(x)*1e6)>Number(cap))return "more than "+(un?"delegated":"available")}return ""}
function ownerGet(){var o=S.owners[S.tab];return o&&o.pubkey_hex?{address:o.granter,pubkey_hex:o.pubkey_hex}:null}
function ownerBlock(){var o=ownerGet();var idx=!S.granter||validateGranter(S.granter)?0:!o?1:2;
  var h=step([["Owner account","terp1…"],["Owner pubkey","scan account QR"],["Ready","signs actions"]],idx,!!S.ownerErr);
  if(o)return h+'<div class="next ok">✓ Owner pubkey matches '+esc(o.address)+(o.source==="chain"?" (address QR; key read from chain)":"")+'</div><dl class="kv"><dt>Pubkey</dt><dd class="mono" style="word-break:break-all">'+esc(o.pubkey_hex)+'</dd></dl><div class="row">'+btn("Clear owner for this slot",'id="owner-clear"',"","ghost")+'</div>';
  return h+'<div class="next">→ '+(idx===0?"Enter the owner account above, or scan its QR to fill it.":"On zigner, open the owner key and show its address QR (or Export for the public key), then scan it here.")+'</div>'+
  '<div class="row">'+btn("Scan owner account",'id="owner-scan"',"","primary")+'</div>'+
  '<div class="field"><label for="owner-paste">Or paste the account QR text / pubkey</label><textarea id="owner-paste" class="mono" rows="2" spellcheck="false" placeholder="cosmos:terp1…:0x… / 02… pubkey / zigner export JSON"></textarea></div><div class="row">'+btn("Check pasted",'id="owner-check"',"","ghost")+'</div>'+
  (S.ownerNote?'<div class="next warn">'+esc(S.ownerNote)+'</div>':'')+(S.ownerErr?'<div class="next danger">'+esc(S.ownerErr)+'</div>':'')}
function ownerSubmit(text){S.ownerErr="";var g=S.granter&&!validateGranter(S.granter)?S.granter:"";
  S.ownerNote="";api("/api/actions/owner-pubkey",{id:S.tab,granter:g,qr:text}).then(function(d){if(!d.pubkey_hex)S.ownerNote=d.note;return ownerPost({granter:d.address,pubkey_hex:d.pubkey_hex||""}).then(function(){scanStop();render()})}).catch(function(e){S.ownerErr=e.message;scanStop();render()})}
var SCAN=null;
function scanStop(){if(!SCAN)return;SCAN.stop=true;if(SCAN.stream)SCAN.stream.getTracks().forEach(function(t){t.stop()});if(SCAN.box)SCAN.box.remove();SCAN=null}
function loadJSQR(){return window.jsQR?Promise.resolve():new Promise(function(ok,bad){var sc=document.createElement("script");sc.src="/jsqr.js";sc.onload=ok;sc.onerror=function(){bad(new Error("QR decoder failed to load"))};document.head.appendChild(sc)})}
function scanStart(onText,prompt){if(typeof onText!=="function"){onText=function(t){ownerSubmit(t);return true};prompt="Hold the owner account QR in the frame."}scanStop();if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia){S.ownerErr="No camera access in this browser. Paste the QR text instead.";render();return}
  var box=document.createElement("div");box.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.8);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:99;gap:12px";
  box.innerHTML='<video playsinline muted style="max-width:90vw;max-height:70vh;border-radius:12px"></video><p style="color:#fff" class="say"></p><button class="btn ghost">Cancel</button>';
  document.body.appendChild(box);SCAN={box:box,say:function(m){box.querySelector(".say").textContent=m}};SCAN.say(prompt);box.querySelector("button").onclick=scanStop;var vid=box.querySelector("video"),cv=document.createElement("canvas"),cx=cv.getContext("2d",{willReadFrequently:true});
  var det=window.BarcodeDetector?new BarcodeDetector({formats:["qr_code"]}):null;var me=SCAN;
  Promise.all([navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}}),det?null:loadJSQR()]).then(function(r){if(me.stop){r[0].getTracks().forEach(function(t){t.stop()});return}me.stream=r[0];vid.srcObject=r[0];vid.play();
    (function tick(){if(me.stop)return;if(vid.readyState>=2){cv.width=vid.videoWidth;cv.height=vid.videoHeight;cx.drawImage(vid,0,0);
      var p=det?det.detect(cv).then(function(c){return c[0]&&c[0].rawValue}):Promise.resolve((function(){var q=jsQR(cx.getImageData(0,0,cv.width,cv.height).data,cv.width,cv.height,{inversionAttempts:"dontInvert"});return q&&q.data})());
      p.then(function(t){if(t&&onText(t.trim()))return;setTimeout(tick,200)}).catch(function(){setTimeout(tick,200)})}else setTimeout(tick,200)})()}).catch(function(e){scanStop();S.ownerErr="Camera: "+e.message+". Paste the account QR text instead.";render()})}
window.scanStart=scanStart;window.scanStop=scanStop;window.scanSay=function(m){if(SCAN)SCAN.say(m)};
function loadHold(v){if(!S.granter||validateGranter(S.granter))return;api("/api/actions/holdings?id="+encodeURIComponent(v.id)+"&granter="+encodeURIComponent(S.granter)).then(function(d){S.hold[v.id]=d;if(S.flow[v.id]==null||S.flow[v.id]==="form")render()}).catch(function(e){S.hold[v.id]={error:e.message};render()})}
function wire(v){
  var g=$("#granter");if(g){g.oninput=function(){var x=g.value.trim();var e=validateGranter(x);setErr("granter",x?e:"");if(!e&&x!==S.granter){ownerPost({granter:x}).then(function(){loadHold(v);render()}).catch(fail)}}}
  var a=$("#amount");if(a){a.oninput=function(){setErr("amount",validateAmount(a.value.trim(),v))}}
  var c=$("#commission_percent");if(c){c.oninput=function(){var x=c.value.trim();setErr("commission_percent",x&&!/^\d+(\.\d+)?$/.test(x)?"a percentage like 5 or 5.25":"")}}
  var w=$("#website");if(w){w.oninput=function(){var x=w.value.trim();setErr("website",x&&!/^https?:\/\//.test(x)?"start with https://":"")}}
  var m=$("#moniker");if(m){m.oninput=function(){setErr("moniker",!m.value.trim()?"moniker cannot be empty":m.value.length>70?"at most 70 characters":"")}}
  var os=$("#owner-scan");if(os)os.onclick=scanStart;var oc=$("#owner-check");if(oc)oc.onclick=function(){var t=$("#owner-paste").value.trim();if(t)ownerSubmit(t)};var ox=$("#owner-clear");if(ox)ox.onclick=function(){S.ownerErr="";ownerPost({clear:true}).then(render).catch(fail)};
  var nm=$("#name-save");if(nm)nm.onclick=function(){var x=(val("console-name")||"");if(!x)return;ownerPost({name:x}).then(function(){toast("ok","Saved","Console name for "+v.slot);render()}).catch(fail)};
  if(v&&S.granter&&!S.hold[v.id])loadHold(v)}
document.addEventListener("click",function(e){var t=e.target.closest("[data-open],[data-act],[data-do],[data-max],[data-pair],[data-drop]");if(!t||t.disabled)return;var v=cur();
  if(t.dataset.open){S.tab=t.dataset.open;sessionStorage.setItem("tab",S.tab);render();return}
  if(t.dataset.act){S.act=t.dataset.act;S.errs={};render();return}
  if(t.dataset.max){var d=S.hold[v.id];if(d&&!d.error){$("#amount").value=d.fmt[t.dataset.max].replace(/,/g,"");$("#amount").oninput()}return}
  if(t.dataset.pair){api("/api/pair",{code:t.dataset.pair}).then(function(p){S.phone=p;toast("ok","Paired","Waiting for the phone's fingerprint");render()}).catch(fail);return}
  if(t.dataset.drop){if(!confirm("Drop the Bluetooth link to "+t.dataset.drop+"? Signing on this phone stops until you pick its code again."))return;api("/api/reject",{code:t.dataset.drop}).then(function(p){S.phone=p;render()}).catch(fail);return}
  var d=t.dataset.do;
  if(d==="bt-on"||d==="bt-off")api("/api/bluetooth",{enabled:d==="bt-on"}).then(function(p){S.phone=p;render()}).catch(fail);
  if(d==="pin")api("/api/confirm-phone",{}).then(function(){toast("ok","Phone pinned","Only this phone can sign now")}).catch(fail);
  if(d==="reject")api("/api/reject",{code:(S.phone||{}).chosen||""}).then(function(p){S.phone=p;render()}).catch(fail);
  if(d==="review")doReview(v);
  if(d==="back"){var f=S.flow[v.id];S.flow[v.id]=f==="review"?"form":f==="grant"?"review":"form";render()}
  if(d==="to-grant"){S.flow[v.id]="grant";delete S.grant[v.id];render();pollGrant(v)}

  if(d==="sig-scan"){delete S.sig[v.id];sigScan(v)}
  if(d==="sig-paste"){var x=(($("#payload")||{}).value||"").trim();if(!x){setErr("payload","paste the text zigner's signature QR holds");return}S.sigPaste=true;sigVerify(v,x.split(/\s+/))}
  if(d==="sig"){t.disabled=true;S.flow[v.id]="broadcast";render();api("/api/actions/signature",{id:v.id,payload:""}).then(function(r){S.result[v.id]=r;S.flow[v.id]="result";toast(r.tx&&r.tx.stage==="committed"?"ok":"danger","Broadcast",r.tx&&r.tx.hash);delete S.hold[v.id];render()}).catch(function(e){var b=e.body||{};var fe=b.errors;if(fe){S.flow[v.id]="grant";render();setErr("payload",fe[0].message);return}S.result[v.id]=b.tx||b.result?(b.result||b):{error:e.message,summary:"Broadcast failed."};S.flow[v.id]="result";toast("danger","Broadcast failed",e.message);render()})}

  if(d==="reset"){api("/api/actions/cancel",{id:v.id}).catch(function(){});S.flow[v.id]="form";delete S.result[v.id];delete S.review[v.id];render()}
});
function fail(e){toast(e.status===423?"warn":"danger",e.status===423?"Read-only":"Error",e.message)}
function val(id){var x=$("#"+id);return x?x.value.trim():null}
function doReview(v){S.errs={};var act=actOf(v);var req={action:act,granter:S.granter};var bad=false;
  if(act==="create"){var c={};["moniker","identity","website","security_contact","details","rate_percent","max_rate_percent","max_change_percent","min_self_delegation"].forEach(function(k){c[k]=val(k)||""});S.createDraft[v.id]=Object.assign({amount:val("amount")||""},c);req.amount=val("amount");req.create=c;var ea=validateAmount(req.amount,v);if(ea){setErr("amount",ea);bad=true}}
  if(act==="delegate"||act==="undelegate"){req.amount=val("amount");var e=validateAmount(req.amount,v);if(e){setErr("amount",e);bad=true}}
  if(act==="edit"){var vi=(S.hold[v.id]||{holdings:{validator:{}}}).holdings.validator,ed={};["moniker","website","identity","security_contact","details"].forEach(function(k){var x=val(k);if(x!==null&&x!==(vi[k]||""))ed[k]=x});var c=val("commission_percent");var now=(S.hold[v.id]||{}).rate_pct||"";if(c&&c+"%"!==now)ed.commission_percent=c;req.edit=ed}
  if(bad)return;
  api("/api/actions/review",{id:v.id,request:req}).then(function(r){S.review[v.id]=r.review;S.flow[v.id]="review";render()}).catch(function(e){var fe=e.body&&e.body.errors;if(fe){fe.forEach(function(x){S.errs[x.field]=x.message});render();toast("warn","Check the form",fe[0].message)}else fail(e)})}
var grantTimer=null;
function pollGrant(v){clearTimeout(grantTimer);if(S.flow[v.id]!=="grant"||S.tab!==v.id)return;
  api("/api/actions/grant?id="+encodeURIComponent(v.id)).then(function(g){var old=S.grant[v.id];if(old&&old.auth_id&&g.auth_id!==old.auth_id){toast("info","QR refreshed","The owner account changed; the old QR would not verify")}
    var changed=!old||old.auth_id!==g.auth_id||old.kind!==g.kind;if(old&&old.auth_id!==g.auth_id&&S.sig[v.id]&&S.sig[v.id].ok)S.sig[v.id]={reason:"The sign QR changed (sequence or expiry), so the earlier signature no longer applies. Sign the new QR.",mismatch:"sequence"};S.grant[v.id]=g;var ql=$("#qrleft");if(ql)ql.textContent=qrLeft(g);if(changed&&!$("#payload:focus"))render();else{var r=$(".ring i");if(r)r.style.width=Math.min(100,Math.max(0,(new Date(g.qr_expires_at)-Date.now())/6000))+"%"}}).catch(function(e){S.grant[v.id]={error:e.message};render()}).finally(function(){grantTimer=setTimeout(function(){pollGrant(v)},4000)})}
loadOwners();
function poll(){Promise.all([loadOwners(),api("/api/validators").catch(function(){return null}),api("/api/state").catch(function(){return null})]).then(function(r){
  if(r[1])S.vals=r[1].validators||[];if(r[2])S.phone=r[2];
  if(S.tab!=="overview"&&!cur())S.tab="overview";
  var a=document.activeElement;var typing=a&&(a.tagName==="INPUT"||a.tagName==="TEXTAREA");
  if(!typing)render();else{tabs();headerPills()}})}
poll();setInterval(poll,3000);
})();
</script></body></html>`

package uiserver

// moveJS draws the "Move validator" block in each validator's tab. The key
// itself moves phone-to-phone by QR; this console only freezes the slot,
// checks the old phone's retire proof and pins the new phone. Fingerprints
// are eight tiles (glyph = b&15, colour = (b>>4)&7); zigner draws the same.
const moveJS = `(function(){
var G=["●","▲","■","◆","★","♥","♠","♣","☀","☾","⚡","✿","☂","♪","✚","⬢"];
var C=["#2f7d6d","#c2603b","#3d63b8","#a5487f","#b8962e","#5b8a2f","#7a4fc4","#3a3a3a"];
var STAGES=[["retire","⇄","Phones"],["pair","⌁","Pair"],["finish","▶","Resume"]];
var M={},busy={};
function e(t){var d=document.createElement("span");d.textContent=t==null?"":String(t);return d.innerHTML}
function tiles(hex,label){if(!hex)return '<span class="sub">—</span>';var h='<span class="fp-tiles" title="'+e(label||"")+'" style="display:inline-flex;gap:3px">';
  for(var i=0;i+1<hex.length&&i<16;i+=2){var b=parseInt(hex.substr(i,2),16);h+='<span style="width:24px;height:24px;border-radius:7px;display:inline-flex;align-items:center;justify-content:center;font-size:14px;color:#fff;background:'+C[(b>>4)&7]+'">'+G[b&15]+'</span>'}return h+'</span>'}
window.fpTiles=tiles;
function lbl(t){return '<span style="font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--kicker);font-weight:600">'+t+'</span>'}
function chips(stage){var at=-1;STAGES.forEach(function(s,i){if(s[0]===stage)at=i});
  return '<div style="display:flex;gap:6px;flex-wrap:wrap;margin:8px 0">'+STAGES.map(function(s,i){var st=i<at?"background:var(--spring);color:#fff":i===at?"background:var(--accent);color:var(--accent-text)":"background:var(--accent-weak);color:var(--muted)";return '<span class="pill" style="'+st+';border:0">'+s[1]+' '+s[2]+'</span>'}).join("")+'</div>'}
function btn(label,attr,kind){return '<button class="btn '+(kind||"")+'" '+attr+'>'+label+'</button>'}
function who(k,hex){return '<div style="display:flex;gap:10px;align-items:center;margin:4px 0">'+lbl(k)+tiles(hex,k)+'</div>'}
function steps(list){return '<ol style="margin:6px 0 8px 18px;padding:0;color:var(--muted);font-size:var(--fs-sm);line-height:1.7">'+list.map(function(s){return '<li>'+s+'</li>'}).join("")+'</ol>'}
function body(v,st){var id=e(v.id),h="";
  if(st.err)h+='<div class="next danger">'+e(st.err)+'</div>';
  if(st.note)h+='<div class="next warn">'+e(st.note)+'</div>';
  if(st.stage==="idle")return h+'<div class="row">'+btn("⇄ Move to another phone",'data-move="start" data-id="'+id+'"',"ghost")+'</div><div class="sub">Key goes phone → phone by QR. Nothing crosses Bluetooth or the network.</div>';
  h+='<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span class="pill warn">❄ frozen · floor '+e(st.floor)+'</span>'+lbl("KMS")+tiles(st.kms_fp,"KMS identity")+'</div>'+chips(st.stage);
  var qr='<img alt="start QR" width="200" height="200" style="border-radius:12px;background:#fff;padding:6px" src="/api/handoff/qr.png?id='+encodeURIComponent(v.id)+'&n='+e(st.floor)+'">';
  var cancel=btn("✕ Cancel",'data-move="cancel" data-id="'+id+'"',"ghost");
  switch(st.stage){
  case "retire":return h+'<div class="qr">'+qr+'<div>'+who("old phone",st.old_fp)+steps([
      "📱 <b>old</b> · key → <b>Chain</b> tab → <b>Scan console QR</b> (this one)",
      "📱 <b>new</b> · Signer → <b>Receive a key</b> → shows its QR",
      "📱 <b>old</b> · <b>Scan new phone</b> → tiles match → <b>Show move QR</b>",
      "📱 <b>new</b> · <b>Scan move QR</b> → shows <b>Imported</b>",
      "📱 <b>old</b> · <b>Scan Imported QR</b> → shows <b>Retired</b>"])+
    '<div class="row">'+btn("📷 Scan retire proof",'data-move="scan" data-id="'+id+'"',"primary")+cancel+'</div></div></div>';
  case "pair":var ok=st.pending_fp&&st.pending_fp===st.target_fp;
    return h+'<div class="next ok">✓ old phone retired</div>'+who("new phone",st.target_fp)+who("asking",st.pending_fp)+
      '<div class="sub">📱 <b>new</b> · Signer → pair this KMS over Bluetooth. The tiles must match.</div><div class="row">'+
      (ok?btn("✓ Tiles match · Pin new phone",'data-move="pair" data-id="'+id+'"',"primary"):btn("⌁ Pin new phone",'data-move="pair" data-id="'+id+'"',"ghost"))+'</div>';
  case "finish":return h+'<div class="next ok">✓ old phone retired · new phone pinned</div>'+who("new phone",st.target_fp)+'<div class="row">'+btn("▶ Resume signing",'data-move="finish" data-id="'+id+'"',"primary")+'</div>';
  default:return h+'<div class="next warn">slot frozen</div><div class="row">'+(st.retired?btn("▶ Resume signing",'data-move="finish" data-id="'+id+'"',"primary"):btn("▶ Unfreeze",'data-move="cancel" data-id="'+id+'"',"ghost"))+'</div>'}}
function paint(v){var box=document.getElementById("move-"+v.id);if(box)box.innerHTML=body(v,M[v.id]||{stage:"idle"})}
function load(v){if(busy[v.id])return;busy[v.id]=1;fetch("/api/handoff/state?id="+encodeURIComponent(v.id)).then(function(r){return r.json()}).then(function(d){var o=M[v.id]||{};d.err=o.err;d.note=o.note;M[v.id]=d;d.t=Date.now();paint(v)}).catch(function(){}).then(function(){busy[v.id]=0})}
window.moveBlock=function(v){var st=M[v.id];if(!st||Date.now()-st.t>2000)setTimeout(function(){load(v)},0);
  return '<div class="review" style="margin:8px 0 16px">'+lbl("⇄ Move")+'<div id="move-'+e(v.id)+'">'+body(v,st||{stage:"idle"})+'</div></div>'};
function post(v,step,qr){var st=M[v.id]||{};st.err="";st.note="";M[v.id]=st;return fetch("/api/handoff/"+step,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:v.id,qr:qr||""})}).then(function(r){return r.text().then(function(t){if(!r.ok)throw new Error(t.trim()||r.statusText);try{var j=JSON.parse(t);if(j.note)st.note=j.note}catch(_){}})}).catch(function(x){st.err=x.message}).then(function(){st.t=0;load(v)})}
// Animated QR: frames "zc-anim:1:<i>/<n>:<part>"; plain QRs pass through.
function collector(done){var parts={},n=0;return function(t){var m=/^zc-anim:1:(\d+)\/(\d+):(.*)$/.exec(t);if(!m)return done(t);
  var i=+m[1],k=+m[2];if(!k||i>=k||k>64)return false;if(k!==n){parts={};n=k}parts[i]=m[3];var have=Object.keys(parts).length;if(window.scanSay)scanSay("frames "+have+"/"+n);
  if(have<n)return false;var s="";for(var j=0;j<n;j++)s+=parts[j];return done(s)}}
// One scanner for every move QR: route by prefix.
function route(v,s){
  if(/^zcinti-retired:2:/.test(s)){if(window.scanStop)scanStop();post(v,"retire",s);return true}
  if(/^zcinti-p2p:/.test(s)){if(window.scanSay)scanSay("That is the phone-to-phone move QR: scan it with the new phone, not here.");return false}
  if(/^zcinti-(recv|imported):/.test(s)){if(window.scanSay)scanSay("That QR is for the old phone. Hold the Retired QR here.");return false}
  if(window.scanSay)scanSay("Not a move QR. Hold the old phone's Retired QR in the frame.");return false}
document.addEventListener("click",function(ev){var t=ev.target.closest("[data-move]");if(!t)return;var id=t.dataset.id,v={id:id};
  var a=t.dataset.move;
  if(a==="scan"){if(!window.scanStart)return;scanStart(collector(function(s){return route(v,s)}),"Hold the old phone's Retired QR in the frame.");return}
  if(a==="cancel"&&!confirm("Cancel the move and unfreeze this slot? If the old phone already showed its move QR, cancel it on both phones too."))return;
  if(a==="pair"&&!confirm("Pin the new phone for this slot? Its tiles must match the new phone's screen."))return;
  t.disabled=true;post(v,a)});
})();`

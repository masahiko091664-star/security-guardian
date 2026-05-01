import { useState, useEffect, useRef, useCallback } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

// ─── STORAGE ──────────────────────────────────────────────────────────────────
const LS = {
  get:(k,f)=>{try{const v=localStorage.getItem(k);return v!==null?JSON.parse(v):f;}catch{return f;}},
  set:(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v));}catch{}},
};
function pushLog(type,msg,detail=""){
  const L=LS.get("sg_log",[]);
  L.unshift({id:Date.now(),type,msg,detail,time:new Date().toLocaleString("ja-JP")});
  LS.set("sg_log",L.slice(0,200));
}
function snapshotScore(score){
  const today=new Date().toLocaleDateString("ja-JP",{month:"2-digit",day:"2-digit"});
  const H=LS.get("sg_hist",[]);
  const idx=H.findIndex(h=>h.d===today);
  if(idx>=0)H[idx].s=score; else H.push({d:today,s:score});
  LS.set("sg_hist",H.slice(-14));
}

// ─── CRYPTO / APIs ────────────────────────────────────────────────────────────
async function sha1Hex(s){
  const h=await crypto.subtle.digest("SHA-1",new TextEncoder().encode(s));
  return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();
}
async function checkHIBP(pw){
  const h=await sha1Hex(pw),p=h.slice(0,5),s=h.slice(5);
  const r=await fetch(`https://api.pwnedpasswords.com/range/${p}`,{headers:{"Add-Padding":"true"}});
  if(!r.ok)throw new Error("HIBP接続失敗");
  const m=(await r.text()).split("\n").find(l=>l.startsWith(s));
  return m?parseInt(m.split(":")[1].trim(),10):0;
}
async function scanVT(url,key){
  const s=await fetch("https://www.virustotal.com/api/v3/urls",{method:"POST",headers:{"x-apikey":key,"Content-Type":"application/x-www-form-urlencoded"},body:`url=${encodeURIComponent(url)}`});
  if(!s.ok)throw new Error(`VT ${s.status}`);
  const id=(await s.json()).data?.id;
  if(!id)throw new Error("分析IDなし");
  for(let i=0;i<3;i++){
    await new Promise(r=>setTimeout(r,3500));
    const r=await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`,{headers:{"x-apikey":key}});
    if(!r.ok)continue;
    const d=await r.json();
    if(d.data?.attributes?.status==="completed"){
      const s2=d.data.attributes.stats;
      return{malicious:s2.malicious||0,suspicious:s2.suspicious||0,harmless:s2.harmless||0,undetected:s2.undetected||0,total:Object.values(s2).reduce((a,b)=>a+b,0)};
    }
  }
  throw new Error("タイムアウト");
}
async function lookupHash(hash,key){
  const r=await fetch(`https://www.virustotal.com/api/v3/files/${hash}`,{headers:{"x-apikey":key}});
  if(r.status===404)return{found:false};
  if(!r.ok)throw new Error(`VT ${r.status}`);
  const d=await r.json(),s=d.data?.attributes?.last_analysis_stats;
  if(!s)return{found:false};
  return{found:true,malicious:s.malicious||0,suspicious:s.suspicious||0,harmless:s.harmless||0,total:Object.values(s).reduce((a,b)=>a+b,0),name:d.data?.attributes?.meaningful_name||"unknown",type:d.data?.attributes?.type_description||"不明"};
}
function detectWebRTC(){
  return new Promise(res=>{
    const ips=new Set();
    try{
      const pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"},{urls:"stun:stun1.l.google.com:19302"}]});
      pc.createDataChannel("");
      pc.createOffer().then(o=>pc.setLocalDescription(o));
      pc.onicecandidate=e=>{
        if(e.candidate){(e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g)||[]).forEach(ip=>ips.add(ip));}
        else{try{pc.close();}catch{}res([...ips]);}
      };
      setTimeout(()=>{try{pc.close();}catch{}res([...ips]);},5000);
    }catch{res([]);}
  });
}
async function callClaude(prompt,maxTokens=1500){
  const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:maxTokens,messages:[{role:"user",content:prompt}]})});
  const d=await r.json();
  return d.content?.map(b=>b.text||"").join("")||"";
}

// ─── PASSWORD ─────────────────────────────────────────────────────────────────
function entropy(pw){let p=0;if(/[a-z]/.test(pw))p+=26;if(/[A-Z]/.test(pw))p+=26;if(/[0-9]/.test(pw))p+=10;if(/[^a-zA-Z0-9]/.test(pw))p+=32;return Math.floor(pw.length*Math.log2(p||1));}
function pwScore(pw){
  if(!pw)return{score:0,label:"",color:"",feedback:[],entropy:0,crackTime:""};
  let s=0;const f=[];
  if(pw.length>=8)s+=10;else f.push("8文字以上が必要");
  if(pw.length>=12)s+=10;else if(pw.length>=8)f.push("12文字以上を推奨");
  if(pw.length>=16)s+=10;
  if(/[a-z]/.test(pw))s+=10;else f.push("小文字を追加してください");
  if(/[A-Z]/.test(pw))s+=10;else f.push("大文字を追加してください");
  if(/[0-9]/.test(pw))s+=10;else f.push("数字を追加してください");
  if(/[^a-zA-Z0-9]/.test(pw))s+=15;else f.push("記号（!@#$等）を追加してください");
  if(["password","123456","qwerty","abc123","letmein","admin","welcome","monkey","dragon","master"].some(c=>pw.toLowerCase().includes(c))){s=Math.min(s,20);f.push("よく使われる単語が含まれています");}
  if(/(.)\1{2,}/.test(pw)){s-=10;f.push("同じ文字の繰り返しがあります");}
  s=Math.max(0,Math.min(100,s));
  const L=[{m:0,l:"非常に弱い",c:"#ff2244"},{m:25,l:"弱い",c:"#ff6600"},{m:45,l:"普通",c:"#ffcc00"},{m:65,l:"強い",c:"#44ff88"},{m:85,l:"非常に強い",c:"#00ffcc"}];
  const lv=[...L].reverse().find(l=>s>=l.m);
  const e=entropy(pw);
  const crack=e<40?"数秒":e<60?"数時間":e<80?"数年":e<100?"数百年":"事実上解読不能";
  return{score:s,label:lv.l,color:lv.c,feedback:f,entropy:e,crackTime:crack};
}
function genPw(len=24){const c="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}";return Array.from({length:len},()=>c[Math.floor(Math.random()*c.length)]).join("");}
const WL=["abandon","ability","access","achieve","action","adapt","address","adjust","adult","advance","advice","afford","agent","alarm","alert","allow","alter","anchor","anger","animal","answer","apple","arise","armor","army","arrive","arrow","artist","asset","assume","attack","attend","author","avoid","balance","battle","beach","become","behave","beyond","bitter","blame","blast","blend","bless","blind","blood","blossom","board","bonus","borrow","brave","break","brief","bright","broken","bronze","build","burst","cabin","camera","cancel","capital","capture","carbon","castle","casual","cause","chain","chaos","chapter","charge","chase","choice","circle","claim","class","clean","clear","clever","close","cloud","coffee","collect","combine","comfort","complex","copy","core","correct","crash","create","crisp","crush","culture","cycle","damage","dance","danger","dawn","debate","decide","degree","deny","design","detail","differ","digital","direct","domain","dragon","drive","earth","edge","elite","empty","enable","enjoy","enter","equal","escape","event","exact","exist","expand","expert","faith","family","fancy","feature","field","final","finish","focus","force","forest","formal","fresh","frost","frozen","fuel","garden","gather","ghost","giant","global","grace","grade","grant","grass","green","group","guard","guide","harbor","harvest","heart","heavy","hero","hollow","honey","human","island","jungle","layer","learn","level","logic","lunar","magic","major","manor","marble","market","match","medal","merge","minor","model","monster","moon","moral","mountain","nature","noble","normal","novel","ocean","offer","option","orbit","palace","panic","paper","peace","pilot","pixel","planet","plate","power","prime","probe","proud","pulse","quest","quick","quiet","radar","raise","reach","ready","realm","rebel","record","reflect","remote","repair","river","robot","rocky","royal","saint","scene","silver","skill","smart","solar","south","speed","split","stone","storm","style","super","swift","teach","theme","tight","title","torch","tower","track","trade","train","treat","trial","truth","twist","ultra","unity","urban","valid","vault","venture","verse","vital","vivid","vocal","water","watch","while","wild","winter","wise","world","young","youth","zero","zone"];
function genPhrase(n=5){return Array.from({length:n},()=>WL[Math.floor(Math.random()*WL.length)]).join("-");}
function localHints(url){
  const h=[];
  try{const u=new URL(url.startsWith("http")?url:"https://"+url),host=u.hostname;
    if(/\d{1,3}(\.\d{1,3}){3}/.test(host))h.push("IPアドレスURLは危険な場合が多い");
    if((host.match(/-/g)||[]).length>3)h.push("ハイフン過多（偽装ドメインの特徴）");
    if(/paypal|amazon|google|apple|microsoft|bank|secure|login|account|verify/.test(host)&&!/\.(com|co\.jp|jp)$/.test(host))h.push("有名サービス名を含む疑わしいドメイン");
    if(url.length>100)h.push("URLが異常に長い");
    if((url.match(/\./g)||[]).length>5)h.push("サブドメイン過多");
    if(u.protocol==="http:")h.push("HTTPSでない（暗号化なし）");
  }catch{h.push("URLの形式が不正");}
  return h;
}
function getBrowserInfo(){return{https:location.protocol==="https:",cookies:navigator.cookieEnabled,dnt:navigator.doNotTrack==="1",lang:navigator.language,platform:navigator.platform||"不明",cores:navigator.hardwareConcurrency||"?",tz:Intl.DateTimeFormat().resolvedOptions().timeZone,webgl:(()=>{try{return!!document.createElement("canvas").getContext("webgl");}catch{return false;}})(),touch:navigator.maxTouchPoints>0,memory:navigator.deviceMemory||"?"};}

// ─── CHECKLIST ────────────────────────────────────────────────────────────────
const ITEMS=[
  {id:"pw1",label:"パスワードマネージャーを使用中",w:20,cat:"pw"},{id:"pw2",label:"全サービスで異なるパスワード",w:15,cat:"pw"},
  {id:"pw3",label:"2段階認証（2FA）を設定済み",w:20,cat:"pw"},{id:"pw4",label:"漏洩チェックを実施済み",w:10,cat:"pw"},
  {id:"nw1",label:"ルーターのデフォルトPWを変更済み",w:10,cat:"nw"},{id:"nw2",label:"VPNを使用中（外出時）",w:8,cat:"nw"},
  {id:"nw3",label:"ファイアウォールを有効化済み",w:7,cat:"nw"},{id:"nw4",label:"不審な接続デバイスなし",w:5,cat:"nw"},
  {id:"dv1",label:"OSを最新状態に保っている",w:15,cat:"dv"},{id:"dv2",label:"ディスク暗号化を有効化済み",w:10,cat:"dv"},
  {id:"dv3",label:"定期バックアップを実施中",w:10,cat:"dv"},{id:"dv4",label:"バックアップをオフラインに保存",w:5,cat:"dv"},
];
const MAX_W=ITEMS.reduce((s,i)=>s+i.w,0);

// ─── CSS ─────────────────────────────────────────────────────────────────────
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
:root{--g:#00ffaa;--c:#00ccff;--y:#ffcc00;--r:#ff3355;--bg:#020c0f;--bg2:#071520;--bg3:#0a1d28;--bd:#00ffaa15;}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:#c8fff0;font-family:'Rajdhani',sans-serif;font-size:15px}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:#00ffaa33;border-radius:2px}

/* Matrix canvas */
#mx{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.18}

/* Ticker */
.ticker{background:#000a0f;border-bottom:1px solid #00ffaa22;padding:6px 0;overflow:hidden;position:relative;z-index:10}
.ticker-inner{display:flex;gap:60px;white-space:nowrap;animation:tick 40s linear infinite;width:max-content}
.ticker-inner:hover{animation-play-state:paused}
@keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
.ticker-item{font-family:'Share Tech Mono',monospace;font-size:11px;color:#00ffaa88;letter-spacing:1px}
.ticker-dot{color:#00ffaa;margin-right:8px}

/* Header */
.hdr{display:flex;align-items:center;gap:16px;padding:16px 24px;border-bottom:1px solid var(--bd);background:linear-gradient(90deg,#020c0f,#071a14);position:relative;z-index:10}
.logo{font-family:'Share Tech Mono',monospace;font-size:22px;letter-spacing:5px;background:linear-gradient(90deg,#00ffaa,#00ccff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 0 10px #00ffaa88)}
.ver{font-family:'Share Tech Mono',monospace;font-size:10px;color:#00ffaa44;letter-spacing:3px;margin-top:2px}
.live{margin-left:auto;display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:11px;color:#00ffaa66}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--g);box-shadow:0 0 8px var(--g);animation:blink 1.5s ease infinite}
@keyframes blink{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.8)}}

/* Tabs */
.tabs{display:flex;gap:0;border-bottom:1px solid var(--bd);background:var(--bg2);position:relative;z-index:10;overflow-x:auto}
.tab{padding:12px 18px;font-size:12px;letter-spacing:1.5px;cursor:pointer;font-family:'Share Tech Mono',monospace;color:#00ffaa44;background:transparent;border:none;border-bottom:2px solid transparent;transition:all .2s;text-transform:uppercase;white-space:nowrap;flex-shrink:0}
.tab:hover{color:#00ffaacc;background:#00ffaa08}
.tab.on{color:var(--g);border-bottom-color:var(--g);background:#00ffaa0a;text-shadow:0 0 12px #00ffaa66}

/* Layout */
.wrap{padding:24px;max-width:960px;margin:0 auto;position:relative;z-index:5}

/* Cards */
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;padding:22px;margin-bottom:18px;position:relative;overflow:hidden;animation:fadeUp .3s ease}
.card::after{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#00ffaa55,transparent)}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.card-sub{background:var(--bg3);border:1px solid #00ffaa0d;border-radius:4px;padding:16px;margin-bottom:10px}
.ct{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:3px;color:#00ffaa77;text-transform:uppercase;margin-bottom:14px}
.sh{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.si{font-size:18px}
.st{font-size:18px;font-weight:700;color:#c8fff0;letter-spacing:.5px}

/* Grid */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
@media(max-width:650px){.g2,.g3{grid-template-columns:1fr}.tabs{padding-right:12px}.wrap{padding:14px}}

/* Score ring */
.ring-wrap{position:relative;width:150px;height:150px;margin:0 auto 16px}
.ring-wrap svg{transform:rotate(-90deg)}
.ring-val{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-family:'Share Tech Mono',monospace;font-size:36px;letter-spacing:-1px}
.ring-sub{text-align:center;font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:4px;color:#00ffaa55;text-transform:uppercase;margin-top:6px}

/* Stat cards */
.stat{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;padding:14px 18px}
.sv{font-family:'Share Tech Mono',monospace;font-size:30px;color:var(--g);text-shadow:0 0 12px #00ffaa55}
.sl{font-size:12px;color:#00ffaa55;letter-spacing:1px;margin-top:2px;font-family:'Share Tech Mono',monospace}

/* Progress */
.prog{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.pl{font-size:12px;color:#00ffaa77;width:110px;flex-shrink:0;font-family:'Share Tech Mono',monospace}
.pb{flex:1;height:5px;background:#071018;border-radius:3px;overflow:hidden;border:1px solid #00ffaa0f}
.pf{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--g),var(--c));transition:width .6s cubic-bezier(.34,1.56,.64,1)}
.pv{font-family:'Share Tech Mono',monospace;font-size:11px;color:#00ffaa55;width:35px;text-align:right}

/* Checklist */
.ci{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid #00ffaa08;cursor:pointer;transition:all .15s;border-radius:3px;padding-left:4px}
.ci:hover{background:#00ffaa07;padding-left:8px}
.ci:last-child{border-bottom:none}
.cb{width:20px;height:20px;border:1px solid #00ffaa33;border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0;transition:all .2s}
.cb.on{background:#00ffaa22;border-color:var(--g);color:var(--g);box-shadow:0 0 10px #00ffaa33}
.cl{font-size:14px;color:#c8fff0bb;font-weight:600;letter-spacing:.3px}
.cl.on{color:var(--g)}
.cw{margin-left:auto;font-family:'Share Tech Mono',monospace;font-size:11px;color:#00ffaa33}

/* Inputs */
.inp{width:100%;background:var(--bg3);border:1px solid #00ffaa22;border-radius:4px;color:var(--g);font-family:'Share Tech Mono',monospace;font-size:14px;padding:11px 14px;outline:none;transition:all .2s;letter-spacing:1px}
.inp:focus{border-color:#00ffaa55;box-shadow:0 0 16px #00ffaa0d}
.inp::placeholder{color:#00ffaa22}
.uinp{width:100%;background:var(--bg3);border:1px solid #00ffaa22;border-radius:4px;color:#c8fff0;font-family:'Share Tech Mono',monospace;font-size:13px;padding:11px 14px;outline:none;transition:all .2s}
.uinp:focus{border-color:#00ffaa44}
.uinp::placeholder{color:#00ffaa22}

/* Buttons */
.btn{padding:10px 20px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;cursor:pointer;transition:all .2s;text-transform:uppercase;border:1px solid}
.btn-g{background:#00ffaa11;border-color:#00ffaa44;color:var(--g)}
.btn-g:hover:not(:disabled){background:#00ffaa1e;box-shadow:0 0 16px #00ffaa33}
.btn-c{background:#00ccff11;border-color:#00ccff44;color:var(--c)}
.btn-c:hover:not(:disabled){background:#00ccff1e}
.btn-r{background:#ff335511;border-color:#ff335533;color:var(--r)}
.btn-r:hover:not(:disabled){background:#ff33551e}
.btn:disabled{opacity:.35;cursor:not-allowed}
.btn-full{width:100%;padding:12px;font-size:12px;letter-spacing:3px}

/* Results */
.rbox{margin-top:14px;padding:16px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:13px;line-height:1.8;animation:fadeUp .25s ease}
.rs{background:#00ffaa08;border:1px solid #00ffaa33;color:var(--g)}
.rw{background:#ffcc0008;border:1px solid #ffcc0033;color:var(--y)}
.rd{background:#ff335508;border:1px solid #ff335533;color:var(--r)}
.ru{background:#00ccff08;border:1px solid #00ccff33;color:var(--c)}
.hint{font-size:12px;color:#ff884477;margin-top:4px}
.hint::before{content:'⚠ '}

/* VT stats */
.vt4{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px}
.vtb{padding:10px;border-radius:4px;text-align:center;font-family:'Share Tech Mono',monospace}
.vtn{font-size:22px;font-weight:700}
.vtl{font-size:10px;opacity:.55;margin-top:3px;letter-spacing:1px}

/* Password */
.sbar{height:3px;background:var(--bg3);border-radius:2px;margin:12px 0;overflow:hidden}
.sfill{height:100%;border-radius:2px;transition:all .4s}
.entropy-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-family:'Share Tech Mono',monospace;font-size:12px;margin-top:8px}

/* Gen pw */
.genpw{font-family:'Share Tech Mono',monospace;font-size:13px;padding:11px 14px;background:var(--bg3);border:1px solid #00ccff22;border-radius:4px;margin-top:10px;word-break:break-all;cursor:pointer;transition:all .2s;color:var(--c);letter-spacing:.5px}
.genpw:hover{border-color:#00ccff55;background:#071020}

/* HIBP */
.hbox{margin-top:12px;padding:12px 16px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:13px;line-height:1.7}
.hok{background:#00ffaa08;border:1px solid #00ffaa33;color:var(--g)}
.hng{background:#ff335508;border:1px solid #ff335533;color:var(--r)}

/* Network */
.dr{display:flex;align-items:center;gap:12px;padding:10px 12px;background:var(--bg3);border:1px solid #00ffaa0f;border-radius:4px;margin-bottom:6px;transition:all .2s}
.dr:hover{border-color:#00ffaa22}
.ddot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dn{font-family:'Share Tech Mono',monospace;font-size:13px;color:#c8fff0;flex:1}
.dip{font-family:'Share Tech Mono',monospace;font-size:11px;color:#00ffaa44}
.dtag{font-size:10px;padding:2px 8px;border-radius:10px;font-family:'Share Tech Mono',monospace;letter-spacing:1px}
.adr{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.sinp{flex:1;background:var(--bg3);border:1px solid #00ffaa22;border-radius:4px;color:#c8fff0;font-family:'Share Tech Mono',monospace;font-size:12px;padding:9px 12px;outline:none;min-width:110px}

/* WebRTC */
.terminal{background:#000a08;border:1px solid #00ffaa22;border-radius:4px;padding:16px;font-family:'Share Tech Mono',monospace;font-size:12px;margin-top:12px;line-height:2}
.term-line{animation:fadeUp .2s ease}
.term-prompt{color:#00ffaa55;margin-right:8px}
.term-ok{color:var(--g)}
.term-warn{color:var(--y)}
.term-err{color:var(--r)}
.term-info{color:var(--c)}

/* Browser info */
.brow-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}
.bi{background:var(--bg3);border:1px solid #00ffaa0d;border-radius:4px;padding:10px 12px}
.bi-key{font-family:'Share Tech Mono',monospace;font-size:10px;color:#00ffaa55;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}
.bi-val{font-size:13px;font-weight:600;color:#c8fff0}

/* Log */
.log-entry{display:flex;gap:12px;padding:10px 12px;border-bottom:1px solid #00ffaa08;font-family:'Share Tech Mono',monospace;font-size:12px;animation:fadeUp .2s ease}
.log-icon{flex-shrink:0;font-size:14px}
.log-time{color:#00ffaa33;font-size:11px;flex-shrink:0}
.log-msg{color:#c8fff0cc;flex:1}
.log-detail{color:#00ffaa55;font-size:11px}

/* Threat feed */
.threat-card{background:var(--bg3);border:1px solid #ff335522;border-radius:4px;padding:16px;margin-bottom:10px;animation:fadeUp .3s ease}
.threat-lvl{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;padding:2px 8px;border-radius:10px;display:inline-block;margin-bottom:8px}
.threat-title{font-size:15px;font-weight:700;color:#c8fff0;margin-bottom:6px}
.threat-body{font-size:13px;color:#c8fff077;line-height:1.7}

/* Settings */
.api-row{background:var(--bg3);border:1px solid #00ccff18;border-radius:4px;padding:16px;margin-bottom:10px}
.api-lbl{font-family:'Share Tech Mono',monospace;font-size:10px;color:#00ccff77;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}

/* Chart */
.chart-wrap{height:120px;margin-top:8px}
.recharts-tooltip-wrapper .recharts-default-tooltip{background:var(--bg3)!important;border:1px solid var(--bd)!important;font-family:'Share Tech Mono',monospace!important;font-size:12px!important}
.recharts-cartesian-axis-tick text{fill:#00ffaa44!important;font-family:'Share Tech Mono',monospace!important;font-size:10px!important}

/* Misc */
.scan{animation:sc 1s ease infinite}
@keyframes sc{0%,100%{opacity:.3}50%{opacity:1}}
.ntc{font-size:11px;color:#ffcc0055;font-family:'Share Tech Mono',monospace;margin-top:8px;padding:6px 10px;background:#ffcc000a;border:1px solid #ffcc0015;border-radius:3px}
.tip{font-size:11px;color:#00ffaa33;font-family:'Share Tech Mono',monospace;margin-top:8px}
.badge{font-size:10px;font-family:'Share Tech Mono',monospace;padding:2px 7px;border-radius:10px;display:inline-block}
.badge-g{background:#00ffaa11;color:#00ffaa77;border:1px solid #00ffaa33}
.badge-r{background:#ff335511;color:#ff335577;border:1px solid #ff335533}
.badge-y{background:#ffcc0011;color:#ffcc0077;border:1px solid #ffcc0033}
.saved-anim{font-size:11px;color:#00ffaa88;font-family:'Share Tech Mono',monospace;animation:fadeUp .3s ease}
.sep{height:1px;background:linear-gradient(90deg,transparent,#00ffaa22,transparent);margin:16px 0}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
`;

// ─── MATRIX RAIN ─────────────────────────────────────────────────────────────
function MatrixRain(){
  const ref=useRef();
  useEffect(()=>{
    const c=ref.current;if(!c)return;
    const ctx=c.getContext("2d");
    const resize=()=>{c.width=window.innerWidth;c.height=window.innerHeight;};
    resize();window.addEventListener("resize",resize);
    const cols=Math.floor(c.width/18),drops=Array(cols).fill(1);
    const chars="01アイウエオカキクケコサシスセソ0110010111000110";
    const draw=()=>{
      ctx.fillStyle="rgba(2,12,15,0.08)";ctx.fillRect(0,0,c.width,c.height);
      drops.forEach((y,i)=>{
        const ch=chars[Math.floor(Math.random()*chars.length)];
        const alpha=Math.random()*0.2+0.05;
        ctx.fillStyle=`rgba(0,255,170,${alpha})`;
        ctx.font=`14px 'Share Tech Mono',monospace`;
        ctx.fillText(ch,i*18,y*18);
        if(y*18>c.height&&Math.random()>.97)drops[i]=0;
        drops[i]++;
      });
    };
    const id=setInterval(draw,60);
    return()=>{clearInterval(id);window.removeEventListener("resize",resize);};
  },[]);
  return <canvas id="mx" ref={ref}/>;
}

// ─── SCORE RING ───────────────────────────────────────────────────────────────
function Ring({score,size=150}){
  const r=58,circ=2*Math.PI*r,dash=(score/100)*circ;
  const col=score>=80?"#00ffaa":score>=55?"#ffcc00":"#ff3355";
  return(
    <div className="ring-wrap" style={{width:size,height:size}}>
      <svg width={size} height={size} viewBox="0 0 150 150">
        <circle cx="75" cy="75" r={r} fill="none" stroke="#071018" strokeWidth="10"/>
        <circle cx="75" cy="75" r={r} fill="none" stroke={col} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{filter:`drop-shadow(0 0 10px ${col})`,transition:"all .7s cubic-bezier(.34,1.56,.64,1)"}}/>
      </svg>
      <div className="ring-val" style={{color:col}}>{score}</div>
    </div>
  );
}

// ─── CHECKLIST ────────────────────────────────────────────────────────────────
function CL({items,chk,toggle}){
  return<div>{items.map(it=>(
    <div key={it.id} className="ci" onClick={()=>toggle(it.id)}>
      <div className={`cb ${chk[it.id]?"on":""}`}>{chk[it.id]?"✓":""}</div>
      <span className={`cl ${chk[it.id]?"on":""}`}>{it.label}</span>
      <span className="cw">+{it.w}pt</span>
    </div>
  ))}</div>;
}

// ─── TICKER DATA ──────────────────────────────────────────────────────────────
const TICKS=["⬡ 最新の脅威情報を監視中","⬡ フィッシング攻撃が増加傾向","⬡ ランサムウェア: 警戒レベル HIGH","⬡ パスワード漏洩データベース更新済み","⬡ ゼロデイ脆弱性: パッチ適用を推奨","⬡ ソーシャルエンジニアリング攻撃に注意","⬡ DNSスプーフィング: VPN使用を推奨","⬡ MFA バイパス攻撃の新手法を検出","⬡ サプライチェーン攻撃: 依存関係を確認","⬡ AIを利用したフィッシングメールが増加"];

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function App(){
  const [tab,setTab]=useState("dash");
  const [chk,setChk]=useState(()=>LS.get("sg_chk",{}));
  const [vtKey,setVtKey]=useState(()=>LS.get("sg_vtk",""));
  const [vtIn,setVtIn]=useState(()=>LS.get("sg_vtk",""));
  const [vtSaved,setVtSaved]=useState(false);
  const [devices,setDevices]=useState(()=>LS.get("sg_dev",[
    {id:1,name:"自分のPC",ip:"192.168.1.2",safe:true},
    {id:2,name:"スマートフォン",ip:"192.168.1.3",safe:true},
    {id:3,name:"不明なデバイス",ip:"192.168.1.99",safe:false},
  ]));
  const [ndv,setNdv]=useState({name:"",ip:""});
  // Password tab
  const [pw,setPw]=useState("");
  const [genLen,setGenLen]=useState(24);
  const [genPwVal,setGenPwVal]=useState("");
  const [genPhVal,setGenPhVal]=useState("");
  const [copied,setCopied]=useState("");
  const [hibp,setHibp]=useState(null);
  const [hibpErr,setHibpErr]=useState("");
  // Network tab
  const [rtcResult,setRtcResult]=useState(null);
  const [rtcLoading,setRtcLoading]=useState(false);
  const [browserInfo]=useState(()=>getBrowserInfo());
  // URL tab
  const [url,setUrl]=useState("");
  const [urlRes,setUrlRes]=useState(null);
  const [urlLoad,setUrlLoad]=useState(false);
  const [urlHist,setUrlHist]=useState(()=>LS.get("sg_urlhist",[]));
  // Files tab
  const [hashVal,setHashVal]=useState("");
  const [hashRes,setHashRes]=useState(null);
  const [hashLoad,setHashLoad]=useState(false);
  // Threat intel
  const [threatFeed,setThreatFeed]=useState(()=>LS.get("sg_threats",null));
  const [threatLoad,setThreatLoad]=useState(false);
  // Log
  const [logs,setLogs]=useState(()=>LS.get("sg_log",[]));
  // Score
  const [hist,setHist]=useState(()=>LS.get("sg_hist",[]));

  const score=Math.round(ITEMS.filter(i=>chk[i.id]).reduce((s,i)=>s+i.w,0)/MAX_W*100);
  const catScore=cat=>{ const it=ITEMS.filter(i=>i.cat===cat);return Math.round(it.filter(i=>chk[i.id]).reduce((s,i)=>s+i.w,0)/it.reduce((s,i)=>s+i.w,0)*100||0);};
  const toggle=id=>{setChk(p=>{const n={...p,[id]:!p[id]};LS.set("sg_chk",n);return n;});};

  // Snapshot score daily
  useEffect(()=>{snapshotScore(score);setHist(LS.get("sg_hist",[]));},  [score]);
  useEffect(()=>{LS.set("sg_dev",devices);},[devices]);

  const refreshLogs=()=>setLogs(LS.get("sg_log",[]));

  // Password
  const pwr=pwScore(pw);
  const doPwned=async()=>{
    if(!pw)return;
    setHibp("loading");setHibpErr("");
    try{const n=await checkHIBP(pw);setHibp({n});const msg=n===0?"漏洩なし":`${n.toLocaleString()}件の漏洩で発見`;pushLog(n===0?"✅":"⚠️",`パスワード HIBP チェック`,msg);refreshLogs();}
    catch(e){setHibpErr("HIBP APIに接続できませんでした");setHibp(null);}
  };
  const doCopy=async(val,key)=>{try{await navigator.clipboard.writeText(val);}catch{}setCopied(key);setTimeout(()=>setCopied(""),2000);};

  // WebRTC
  const doRTC=async()=>{
    setRtcLoading(true);setRtcResult(null);
    const ips=await detectWebRTC();
    const locals=ips.filter(ip=>/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip));
    const publics=ips.filter(ip=>!locals.includes(ip));
    setRtcResult({ips,locals,publics});
    pushLog(publics.length>0?"⚠️":"✅","WebRTC IPリーク検査",publics.length>0?`公開IP検出: ${publics.join(", ")}`:"公開IPは検出されませんでした");
    refreshLogs();setRtcLoading(false);
  };

  // URL
  const doUrl=async()=>{
    if(!url.trim())return;
    setUrlLoad(true);setUrlRes(null);
    const lh=localHints(url);
    let vt=null;
    if(vtKey){try{vt=await scanVT(url,vtKey);}catch(e){vt={error:e.message};}}
    try{
      const txt=await callClaude(`サイバーセキュリティ専門家としてURLを詳細分析してください。\nURL: ${url}\nローカルヒント: ${lh.join(", ")||"なし"}\n${vt&&!vt.error?`VT結果: 悪意${vt.malicious}/疑${vt.suspicious}/安全${vt.harmless}/${vt.total}エンジン`:""}\nJSONのみ回答（他テキスト不要）:\n{"verdict":"safe"|"warning"|"danger"|"unknown","riskScore":0-100,"category":"フィッシング"|"マルウェア"|"スキャム"|"安全"|"不明","summary":"3行以内","reasons":["理由1","理由2"],"recommendation":"対処法"}`);
      const obj=JSON.parse(txt.replace(/```json|```/g,"").trim());
      const result={...obj,lh,vt,url,time:new Date().toLocaleString("ja-JP")};
      setUrlRes(result);
      const newHist=[result,...urlHist].slice(0,20);
      setUrlHist(newHist);LS.set("sg_urlhist",newHist);
      pushLog(obj.verdict==="safe"?"✅":obj.verdict==="danger"?"⛔":"⚠️",`URL検査: ${url.slice(0,40)}`,`リスク${obj.riskScore}/100`);
      refreshLogs();
    }catch{setUrlRes({verdict:"unknown",riskScore:50,summary:"AI分析に失敗しました。",reasons:[],lh,vt,recommendation:"手動で確認してください"});}
    setUrlLoad(false);
  };

  // Hash
  const doHash=async()=>{
    if(!hashVal.trim())return;
    if(!vtKey){setHashRes({error:"VirusTotal APIキーが必要です"});return;}
    setHashLoad(true);setHashRes(null);
    try{const r=await lookupHash(hashVal.trim(),vtKey);setHashRes(r);pushLog(r.found&&r.malicious>0?"⛔":r.found?"✅":"❓","ファイルハッシュ検索",r.found?`${r.name} - 悪意:${r.malicious}/${r.total}`:"データベースに未登録");refreshLogs();}
    catch(e){setHashRes({error:e.message});}
    setHashLoad(false);
  };

  // Threats
  const doThreats=async()=>{
    setThreatLoad(true);
    try{
      const txt=await callClaude(`セキュリティアナリストとして、現在の主なサイバー脅威トップ5を日本語でJSONのみで回答（他テキスト不要）:\n[{"title":"脅威名","level":"HIGH"|"MEDIUM"|"LOW","body":"詳細説明（2文）","action":"推奨対処法"}]`,1500);
      const parsed=JSON.parse(txt.replace(/```json|```/g,"").trim());
      const data={threats:parsed,updated:new Date().toLocaleString("ja-JP")};
      setThreatFeed(data);LS.set("sg_threats",data);
    }catch{setThreatFeed({threats:[],updated:"取得失敗",error:true});}
    setThreatLoad(false);
  };

  const saveVtKey=()=>{setVtKey(vtIn);LS.set("sg_vtk",vtIn);setVtSaved(true);setTimeout(()=>setVtSaved(false),2000);};
  const vcls={safe:"rs",warning:"rw",danger:"rd",unknown:"ru"};
  const vlbl={safe:"✓ 安全と思われます",warning:"⚠ 注意が必要です",danger:"✖ 危険なURLです",unknown:"? 判定不明"};
  const lvlColor={HIGH:"#ff3355",MEDIUM:"#ffcc00",LOW:"#00ccff"};

  return(
    <>
      <style>{CSS}</style>
      <MatrixRain/>

      {/* Ticker */}
      <div className="ticker">
        <div className="ticker-inner">
          {[...TICKS,...TICKS].map((t,i)=><span key={i} className="ticker-item"><span className="ticker-dot">◈</span>{t}</span>)}
        </div>
      </div>

      {/* Header */}
      <div className="hdr">
        <div>
          <div className="logo">SECURITY GUARDIAN</div>
          <div className="ver">PERSONAL CYBER DEFENSE SYSTEM v3.0 — MAXIMUM</div>
        </div>
        <div className="live"><div className="live-dot"/>ACTIVE</div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        {[["dash","◈ ダッシュボード"],["pw","🔑 パスワード"],["nw","📡 ネットワーク"],["url","🔍 URL検査"],["files","📁 ファイル"],["threats","⚡ 脅威情報"],["log","📋 ログ"],["cfg","⚙ 設定"]].map(([id,lbl])=>(
          <button key={id} className={`tab ${tab===id?"on":""}`} onClick={()=>setTab(id)}>{lbl}</button>
        ))}
      </div>

      <div className="wrap">

        {/* ── DASHBOARD ─────────────────────────────────────────────────────── */}
        {tab==="dash"&&<>
          <div className="card" style={{textAlign:"center"}}>
            <div className="ct">総合セキュリティスコア</div>
            <Ring score={score}/>
            <div className="ring-sub">{score>=80?"PROTECTED":score>=55?"AT RISK":"VULNERABLE"}</div>
            {hist.length>1&&(
              <>
                <div className="sep"/>
                <div className="ct" style={{textAlign:"left"}}>スコア履歴（直近{hist.length}日）</div>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={hist.map(h=>({日付:h.d,スコア:h.s}))}>
                      <defs>
                        <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00ffaa" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#00ffaa" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="日付" tick={{fontSize:10}}/>
                      <YAxis domain={[0,100]} tick={{fontSize:10}}/>
                      <Tooltip contentStyle={{background:"#071520",border:"1px solid #00ffaa22",fontFamily:"'Share Tech Mono',monospace",fontSize:12}}/>
                      <Area type="monotone" dataKey="スコア" stroke="#00ffaa" strokeWidth={2} fill="url(#g1)"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}
          </div>
          <div className="card">
            <div className="ct">カテゴリ別</div>
            {[["パスワード管理","pw"],["ネットワーク","nw"],["デバイス保護","dv"]].map(([l,k])=>(
              <div className="prog" key={k}>
                <div className="pl">{l}</div>
                <div className="pb"><div className="pf" style={{width:`${catScore(k)}%`}}/></div>
                <div className="pv">{catScore(k)}%</div>
              </div>
            ))}
          </div>
          <div className="g3">
            <div className="stat">
              <div className="sv">{ITEMS.filter(i=>chk[i.id]).length}<span style={{fontSize:14,color:"#00ffaa44"}}>/{ITEMS.length}</span></div>
              <div className="sl">完了チェック</div>
            </div>
            <div className="stat">
              <div className="sv" style={{color:devices.some(d=>!d.safe)?"#ff3355":"var(--g)"}}>{devices.filter(d=>!d.safe).length}</div>
              <div className="sl">不審デバイス</div>
            </div>
            <div className="stat">
              <div className="sv" style={{color:"var(--c)"}}>{urlHist.length}</div>
              <div className="sl">URL検査履歴</div>
            </div>
          </div>
          {logs.length>0&&(
            <div className="card">
              <div className="ct">最近のセキュリティイベント</div>
              {logs.slice(0,5).map(l=>(
                <div className="log-entry" key={l.id}>
                  <span className="log-icon">{l.type}</span>
                  <div style={{flex:1}}>
                    <div className="log-msg">{l.msg}</div>
                    {l.detail&&<div className="log-detail">{l.detail}</div>}
                  </div>
                  <span className="log-time">{l.time}</span>
                </div>
              ))}
            </div>
          )}
        </>}

        {/* ── PASSWORD ──────────────────────────────────────────────────────── */}
        {tab==="pw"&&<>
          <div className="card">
            <div className="sh"><span className="si">🔑</span><span className="st">パスワード強度 + エントロピー分析</span></div>
            <input className="inp" type="password" placeholder="パスワードを入力…" value={pw} onChange={e=>{setPw(e.target.value);setHibp(null);setHibpErr("");}}/>
            {pw&&<>
              <div className="sbar"><div className="sfill" style={{width:`${pwr.score}%`,background:pwr.color,boxShadow:`0 0 8px ${pwr.color}`}}/></div>
              <div className="row" style={{marginBottom:8}}>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:14,color:pwr.color,fontWeight:700}}>{pwr.label}</span>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:"#00ffaa55"}}>スコア {pwr.score}/100</span>
              </div>
              <div className="g2" style={{marginBottom:10}}>
                <div className="card-sub">
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#00ccff55",letterSpacing:2,marginBottom:4}}>エントロピー</div>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:22,color:"var(--c)"}}>{pwr.entropy} <span style={{fontSize:12,opacity:.5}}>bits</span></div>
                </div>
                <div className="card-sub">
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#00ccff55",letterSpacing:2,marginBottom:4}}>推定解読時間</div>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:16,color:pwr.color,fontWeight:700}}>{pwr.crackTime}</div>
                </div>
              </div>
              {pwr.feedback.map((f,i)=><div key={i} style={{fontSize:12,color:"#ff8844",fontFamily:"'Share Tech Mono',monospace",padding:"2px 0"}}>▶ {f}</div>)}
              {pwr.feedback.length===0&&<div style={{fontSize:12,color:"var(--g)",fontFamily:"'Share Tech Mono',monospace"}}>✓ 改善点なし — 非常に強固なパスワードです</div>}
            </>}
            <div style={{marginTop:12}}>
              <button className="btn btn-c" onClick={doPwned} disabled={!pw||hibp==="loading"}>
                {hibp==="loading"?<span className="scan">◈ Have I Been Pwned 照合中…</span>:"◈ Have I Been Pwned で漏洩チェック"}
              </button>
            </div>
            {hibpErr&&<div style={{fontSize:12,color:"#ff8844",fontFamily:"'Share Tech Mono',monospace",marginTop:8}}>{hibpErr}</div>}
            {hibp&&hibp!=="loading"&&(
              <div className={`hbox ${hibp.n===0?"hok":"hng"}`}>
                {hibp.n===0?"✓ このパスワードは既知の漏洩DBに存在しません":`⚠ ${hibp.n.toLocaleString()} 件の漏洩で発見されました。今すぐ変更してください！`}
                <div style={{fontSize:11,opacity:.5,marginTop:4}}>k-匿名性方式：パスワード本体はAPIに送信されません</div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="sh"><span className="si">⚡</span><span className="st">パスワードジェネレーター</span></div>
            <div className="row" style={{marginBottom:12}}>
              <span style={{fontSize:12,color:"#00ffaa55",fontFamily:"'Share Tech Mono',monospace",flexShrink:0}}>長さ: {genLen}</span>
              <input type="range" min={12} max={64} value={genLen} onChange={e=>setGenLen(+e.target.value)} style={{flex:1,accentColor:"var(--g)"}}/>
            </div>
            <div className="g2">
              <button className="btn btn-g" onClick={()=>setGenPwVal(genPw(genLen))}>🔀 ランダム生成</button>
              <button className="btn btn-c" onClick={()=>setGenPhVal(genPhrase(4))}>📖 パスフレーズ生成</button>
            </div>
            {genPwVal&&<div className="genpw" onClick={()=>doCopy(genPwVal,"pw")}>{genPwVal}<span style={{fontSize:10,color:"var(--c)",marginLeft:8,opacity:.5}}>{copied==="pw"?"✓ コピー済み":"クリックでコピー"}</span></div>}
            {genPhVal&&<div className="genpw" style={{color:"#00ffaa",borderColor:"#00ffaa22"}} onClick={()=>doCopy(genPhVal,"ph")}>{genPhVal}<span style={{fontSize:10,color:"var(--g)",marginLeft:8,opacity:.5}}>{copied==="ph"?"✓ コピー済み":"クリックでコピー"}</span></div>}
            <div className="tip">パスフレーズ: 覚えやすく高エントロピー（ランダム4単語 ≈ 52bits）</div>
          </div>

          <div className="card">
            <div className="ct">アカウント保護チェックリスト</div>
            <CL items={ITEMS.filter(i=>i.cat==="pw")} chk={chk} toggle={toggle}/>
          </div>
        </>}

        {/* ── NETWORK ───────────────────────────────────────────────────────── */}
        {tab==="nw"&&<>
          <div className="card">
            <div className="sh"><span className="si">🔬</span><span className="st">WebRTC IPリークテスト</span></div>
            <div style={{fontSize:13,color:"#c8fff077",marginBottom:14,lineHeight:1.7}}>VPN使用中でも、ブラウザのWebRTC APIによってローカルIPや実際のIPアドレスが漏洩する場合があります。</div>
            <button className="btn btn-g btn-full" onClick={doRTC} disabled={rtcLoading}>
              {rtcLoading?<span className="scan">◈ ICE候補を収集中…（最大5秒）</span>:"◈ リークテストを実行する"}
            </button>
            {rtcResult&&(
              <div className="terminal">
                <div className="term-line"><span className="term-prompt">$</span><span className="term-info">WebRTC ICE Candidate Analysis</span></div>
                <div className="term-line"><span className="term-prompt">$</span>検出されたIPアドレス: <span className="term-ok">{rtcResult.ips.length}件</span></div>
                {rtcResult.locals.map((ip,i)=><div key={i} className="term-line"><span className="term-prompt">  ↳</span><span className="term-ok">LOCAL  {ip}</span> <span style={{opacity:.5}}>（プライベートIP）</span></div>)}
                {rtcResult.publics.map((ip,i)=><div key={i} className="term-line"><span className="term-prompt">  ↳</span><span className="term-warn">PUBLIC {ip}</span> <span style={{color:"var(--r)"}}>← VPNリーク検出！</span></div>)}
                {rtcResult.ips.length===0&&<div className="term-line"><span className="term-ok">✓ IPアドレスは検出されませんでした</span></div>}
                <div className="term-line"><span className="term-prompt">$</span>
                  {rtcResult.publics.length>0
                    ?<span className="term-warn">⚠ 公開IPが漏洩しています。VPNを確認するかWebRTCをブロックしてください</span>
                    :<span className="term-ok">✓ 公開IPの漏洩なし — 良好な状態です</span>}
                </div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="sh"><span className="si">🧬</span><span className="st">ブラウザフィンガープリント情報</span></div>
            <div className="brow-grid">
              {[
                ["HTTPS接続",browserInfo.https?"✓ 暗号化済み":"✗ 未暗号化",browserInfo.https?"var(--g)":"var(--r)"],
                ["Cookie",browserInfo.cookies?"有効":"無効","var(--y)"],
                ["Do Not Track",browserInfo.dnt?"ON":"OFF",browserInfo.dnt?"var(--g)":"#00ffaa44"],
                ["言語",browserInfo.lang,"var(--c)"],
                ["プラットフォーム",browserInfo.platform,"var(--c)"],
                ["CPUコア数",String(browserInfo.cores),"var(--c)"],
                ["タイムゾーン",browserInfo.tz,"var(--c)"],
                ["WebGL",browserInfo.webgl?"利用可能":"不可","var(--y)"],
                ["RAM",`${browserInfo.memory}GB`,"var(--c)"],
                ["タッチ",browserInfo.touch?"あり":"なし","#00ffaa44"],
              ].map(([k,v,c])=>(
                <div className="bi" key={k}>
                  <div className="bi-key">{k}</div>
                  <div className="bi-val" style={{color:c}}>{v}</div>
                </div>
              ))}
            </div>
            <div className="tip">⚠ これらの情報はウェブサイトに公開されており、トラッキングに使用される可能性があります</div>
          </div>

          <div className="card">
            <div className="sh"><span className="si">📡</span><span className="st">接続デバイス管理</span></div>
            {devices.map(d=>(
              <div className="dr" key={d.id}>
                <div className="ddot" style={{background:d.safe?"var(--g)":"var(--r)",boxShadow:`0 0 6px ${d.safe?"#00ffaa":"#ff3355"}`}}/>
                <span className="dn">{d.name}</span>
                <span className={`badge ${d.safe?"badge-g":"badge-r"}`}>{d.safe?"既知":"不審"}</span>
                <span className="dip">{d.ip}</span>
                <button onClick={()=>setDevices(dv=>dv.filter(x=>x.id!==d.id))} style={{background:"none",border:"none",color:"#ff335544",cursor:"pointer",fontSize:14,paddingLeft:8,flexShrink:0}}>✕</button>
              </div>
            ))}
            <div className="adr">
              <input className="sinp" placeholder="デバイス名" value={ndv.name} onChange={e=>setNdv(p=>({...p,name:e.target.value}))}/>
              <input className="sinp" placeholder="IPアドレス" value={ndv.ip} onChange={e=>setNdv(p=>({...p,ip:e.target.value}))}/>
              <button className="btn btn-g" style={{padding:"9px 14px",fontSize:11}} onClick={()=>{if(!ndv.name||!ndv.ip)return;setDevices(d=>[...d,{id:Date.now(),...ndv,safe:true}]);setNdv({name:"",ip:""});}}>追加</button>
            </div>
          </div>

          <div className="card">
            <div className="ct">ネットワーク保護チェックリスト</div>
            <CL items={ITEMS.filter(i=>i.cat==="nw")} chk={chk} toggle={toggle}/>
          </div>
        </>}

        {/* ── URL ───────────────────────────────────────────────────────────── */}
        {tab==="url"&&<>
          <div className="card">
            <div className="sh"><span className="si">🔍</span><span className="st">URL安全性検査 — AI ×{vtKey?" VirusTotal":"ローカル"}</span></div>
            <input className="uinp" placeholder="https://example.com を入力…" value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!urlLoad&&doUrl()}/>
            <button className="btn btn-g btn-full" style={{marginTop:10}} onClick={doUrl} disabled={urlLoad||!url.trim()}>
              {urlLoad?<span className="scan">◈ AI分析{vtKey?" + VirusTotal":""} 処理中…</span>:`◈ 安全性を分析する ${vtKey?"[AI + VT]":"[AI]"}`}
            </button>
            {!vtKey&&<div className="ntc">💡 設定でVT APIキーを登録すると70+エンジンで追加検査されます</div>}

            {urlRes&&(
              <>
                <div className={`rbox ${vcls[urlRes.verdict]}`}>
                  <div style={{fontSize:16,fontWeight:700,marginBottom:8}}>{vlbl[urlRes.verdict]}</div>
                  <div className="g2" style={{marginBottom:10}}>
                    <div>リスクスコア: <strong>{urlRes.riskScore}/100</strong></div>
                    {urlRes.category&&<div>カテゴリ: <strong>{urlRes.category}</strong></div>}
                  </div>
                  <div style={{fontSize:13,lineHeight:1.8,marginBottom:8}}>{urlRes.summary}</div>
                  {urlRes.reasons?.map((r,i)=><div key={i} style={{fontSize:12}}>▶ {r}</div>)}
                  {urlRes.recommendation&&<div style={{marginTop:10,padding:"8px 12px",background:"rgba(0,0,0,.2)",borderRadius:3,fontSize:12}}>💡 {urlRes.recommendation}</div>}
                  {urlRes.lh?.map((h,i)=><div key={i} className="hint">{h}</div>)}
                </div>
                {urlRes.vt&&!urlRes.vt.error&&(
                  <>
                    <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:"#00ccff55",letterSpacing:2,margin:"14px 0 8px"}}>VIRUSTOTAL — {urlRes.vt.total} ENGINES</div>
                    <div className="vt4">
                      <div className="vtb" style={{background:"#ff33550a",border:"1px solid #ff335533"}}><div className="vtn" style={{color:"var(--r)"}}>{urlRes.vt.malicious}</div><div className="vtl">MALICIOUS</div></div>
                      <div className="vtb" style={{background:"#ffcc000a",border:"1px solid #ffcc0033"}}><div className="vtn" style={{color:"var(--y)"}}>{urlRes.vt.suspicious}</div><div className="vtl">SUSPICIOUS</div></div>
                      <div className="vtb" style={{background:"#00ffaa0a",border:"1px solid #00ffaa33"}}><div className="vtn" style={{color:"var(--g)"}}>{urlRes.vt.harmless}</div><div className="vtl">HARMLESS</div></div>
                      <div className="vtb" style={{background:"#00ccff0a",border:"1px solid #00ccff33"}}><div className="vtn" style={{color:"var(--c)"}}>{urlRes.vt.undetected}</div><div className="vtl">UNDETECTED</div></div>
                    </div>
                  </>
                )}
                {urlRes.vt?.error&&<div style={{fontSize:11,color:"#ff884466",fontFamily:"'Share Tech Mono',monospace",marginTop:8}}>VT: {urlRes.vt.error}</div>}
              </>
            )}
          </div>

          {urlHist.length>0&&(
            <div className="card">
              <div className="ct">URL検査履歴 ({urlHist.length}件)</div>
              {urlHist.slice(0,10).map((h,i)=>(
                <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 0",borderBottom:"1px solid #00ffaa08",cursor:"pointer"}} onClick={()=>setUrl(h.url)}>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:h.verdict==="safe"?"var(--g)":h.verdict==="danger"?"var(--r)":"var(--y)"}}>{h.verdict==="safe"?"✓":h.verdict==="danger"?"✗":"⚠"}</span>
                  <span style={{flex:1,fontSize:12,color:"#c8fff077",fontFamily:"'Share Tech Mono',monospace",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.url}</span>
                  <span style={{fontSize:11,color:"#00ffaa33",fontFamily:"'Share Tech Mono',monospace",flexShrink:0}}>{h.riskScore}/100</span>
                </div>
              ))}
              <button className="btn btn-r" style={{marginTop:12,padding:"7px 14px",fontSize:11}} onClick={()=>{setUrlHist([]);LS.set("sg_urlhist",[]);}}>履歴削除</button>
            </div>
          )}
        </>}

        {/* ── FILES ─────────────────────────────────────────────────────────── */}
        {tab==="files"&&<>
          <div className="card">
            <div className="sh"><span className="si">📁</span><span className="st">ファイルハッシュ検索（VirusTotal）</span></div>
            <div style={{fontSize:13,color:"#c8fff077",marginBottom:14,lineHeight:1.7}}>MD5 / SHA-1 / SHA-256 ハッシュ値を入力すると、VirusTotalの70以上のエンジンでスキャン済みのファイルと照合します。</div>
            {!vtKey&&<div className="ntc">⚠ VirusTotal APIキーが必要です（設定タブで登録）</div>}
            <input className="uinp" placeholder="MD5 / SHA-1 / SHA-256 ハッシュ値を入力…" value={hashVal} onChange={e=>setHashVal(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!hashLoad&&doHash()}/>
            <button className="btn btn-g btn-full" style={{marginTop:10}} onClick={doHash} disabled={hashLoad||!hashVal.trim()||!vtKey}>
              {hashLoad?<span className="scan">◈ VirusTotal データベースを照合中…</span>:"◈ ハッシュを検索する"}
            </button>
            {hashRes&&(
              <>
                {hashRes.error&&<div className="rbox ru" style={{marginTop:12}}>{hashRes.error}</div>}
                {!hashRes.error&&!hashRes.found&&<div className="rbox rs" style={{marginTop:12}}>✓ このハッシュはVirusTotalのデータベースに登録されていません<div style={{fontSize:11,opacity:.5,marginTop:4}}>初めてのファイルの可能性があります。不明なファイルは実行しないでください。</div></div>}
                {hashRes.found&&(
                  <div className={`rbox ${hashRes.malicious>0?"rd":"rs"}`} style={{marginTop:12}}>
                    <div style={{fontSize:15,fontWeight:700,marginBottom:8}}>{hashRes.malicious>0?"⛔ マルウェア検出":"✓ 安全なファイルと思われます"}</div>
                    <div>ファイル名: <strong>{hashRes.name}</strong></div>
                    {hashRes.type&&<div>タイプ: <strong>{hashRes.type}</strong></div>}
                    <div className="vt4" style={{marginTop:12}}>
                      <div className="vtb" style={{background:"#ff33550a",border:"1px solid #ff335533"}}><div className="vtn" style={{color:"var(--r)"}}>{hashRes.malicious}</div><div className="vtl">MALICIOUS</div></div>
                      <div className="vtb" style={{background:"#ffcc000a",border:"1px solid #ffcc0033"}}><div className="vtn" style={{color:"var(--y)"}}>{hashRes.suspicious}</div><div className="vtl">SUSPICIOUS</div></div>
                      <div className="vtb" style={{background:"#00ffaa0a",border:"1px solid #00ffaa33"}}><div className="vtn" style={{color:"var(--g)"}}>{hashRes.harmless}</div><div className="vtl">HARMLESS</div></div>
                      <div className="vtb" style={{background:"#00ccff0a",border:"1px solid #00ccff33"}}><div className="vtn" style={{color:"var(--c)"}}>{hashRes.total}</div><div className="vtl">TOTAL</div></div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
          <div className="card">
            <div className="sh"><span className="si">🛡</span><span className="st">デバイス保護チェックリスト</span></div>
            <CL items={ITEMS.filter(i=>i.cat==="dv")} chk={chk} toggle={toggle}/>
          </div>
          <div className="card">
            <div className="ct">バックアップ戦略（3-2-1ルール）</div>
            {[{n:"3",t:"コピーを3つ作成",d:"本体 + 外付けHDD + クラウドの3箇所"},{n:"2",t:"2種類のメディア",d:"例：SSD（本体）＋ HDD（外付け）"},{n:"1",t:"1つはオフサイト",d:"クラウドまたは別の物理場所に保管"}].map(r=>(
              <div key={r.n} style={{display:"flex",gap:16,padding:"12px 0",borderBottom:"1px solid #00ffaa08"}}>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:28,color:"var(--g)",opacity:.35,width:24,flexShrink:0,lineHeight:1}}>{r.n}</div>
                <div><div style={{fontSize:15,color:"#c8fff0",fontWeight:600}}>{r.t}</div><div style={{fontSize:12,color:"#c8fff055",marginTop:2}}>{r.d}</div></div>
              </div>
            ))}
          </div>
        </>}

        {/* ── THREATS ───────────────────────────────────────────────────────── */}
        {tab==="threats"&&<>
          <div className="card">
            <div className="sh"><span className="si">⚡</span><span className="st">リアルタイム脅威インテリジェンス</span></div>
            <div style={{fontSize:13,color:"#c8fff077",marginBottom:14,lineHeight:1.7}}>AIが現在の主要なサイバー脅威を分析し、対処法と共に提示します。</div>
            <button className="btn btn-g btn-full" onClick={doThreats} disabled={threatLoad}>
              {threatLoad?<span className="scan">◈ 脅威データをAIが分析中…</span>:"◈ 最新の脅威情報を取得する"}
            </button>
            {threatFeed?.updated&&<div className="tip">最終更新: {threatFeed.updated}</div>}
          </div>
          {threatFeed?.threats?.map((t,i)=>(
            <div className="threat-card" key={i} style={{borderColor:`${lvlColor[t.level]||"#00ffaa"}33`}}>
              <div className="threat-lvl" style={{background:`${lvlColor[t.level]||"#00ffaa"}15`,color:lvlColor[t.level]||"#00ffaa",border:`1px solid ${lvlColor[t.level]||"#00ffaa"}44`}}>
                {t.level}
              </div>
              <div className="threat-title">{t.title}</div>
              <div className="threat-body">{t.body}</div>
              {t.action&&<div style={{marginTop:10,fontSize:12,color:"var(--c)",fontFamily:"'Share Tech Mono',monospace"}}>→ {t.action}</div>}
            </div>
          ))}
          {threatFeed?.error&&<div className="rbox ru">脅威情報の取得に失敗しました。再度お試しください。</div>}
        </>}

        {/* ── LOG ───────────────────────────────────────────────────────────── */}
        {tab==="log"&&<>
          <div className="card">
            <div className="row" style={{marginBottom:16}}>
              <span className="ct" style={{margin:0}}>セキュリティイベントログ（{logs.length}件）</span>
              <button className="btn btn-c" style={{marginLeft:"auto",padding:"6px 14px",fontSize:10}} onClick={()=>{const t=logs.map(l=>`[${l.time}] ${l.msg} ${l.detail}`).join("\n");navigator.clipboard.writeText(t).catch(()=>{});}}>📋 コピー</button>
              <button className="btn btn-r" style={{padding:"6px 14px",fontSize:10}} onClick={()=>{if(window.confirm("ログを全削除しますか？")){LS.set("sg_log",[]);setLogs([]);;}}}>削除</button>
            </div>
            {logs.length===0&&<div style={{textAlign:"center",color:"#00ffaa33",fontFamily:"'Share Tech Mono',monospace",fontSize:13,padding:"24px 0"}}>ログはありません<br/>各タブで操作を行うとここに記録されます</div>}
            {logs.map(l=>(
              <div className="log-entry" key={l.id}>
                <span className="log-icon">{l.type}</span>
                <div style={{flex:1}}>
                  <div className="log-msg">{l.msg}</div>
                  {l.detail&&<div className="log-detail">{l.detail}</div>}
                </div>
                <span className="log-time">{l.time}</span>
              </div>
            ))}
          </div>
        </>}

        {/* ── SETTINGS ──────────────────────────────────────────────────────── */}
        {tab==="cfg"&&<>
          <div className="card">
            <div className="sh"><span className="si">⚙</span><span className="st">API設定</span></div>
            <div className="api-row">
              <div className="api-lbl">VirusTotal APIキー <span className="badge badge-g">URL検査 + ファイル検索</span></div>
              <input className="uinp" type="password" placeholder="VTのAPIキーを入力…" value={vtIn} onChange={e=>setVtIn(e.target.value)}/>
              <div className="row" style={{marginTop:10}}>
                <button className="btn btn-c" style={{padding:"8px 16px",fontSize:11}} onClick={saveVtKey}>保存</button>
                {vtSaved&&<span className="saved-anim">✓ 保存しました</span>}
                {vtKey&&<button className="btn btn-r" style={{padding:"8px 14px",fontSize:11}} onClick={()=>{setVtKey("");setVtIn("");LS.set("sg_vtk","");}}>削除</button>}
              </div>
              <div className="ntc">⚠ APIキーはlocalStorageに保存されます。共有PCでは使用しないでください。</div>
              <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener" style={{display:"block",fontSize:11,color:"var(--c)",opacity:.5,fontFamily:"'Share Tech Mono',monospace",marginTop:8}}>→ VirusTotal 無料アカウント登録</a>
            </div>
          </div>
          <div className="card">
            <div className="ct">アプリ情報</div>
            {[
              ["VERSION","3.0.0 — MAXIMUM"],
              ["HIBP","k-匿名性方式 / SHA-1 / パスワード非送信"],
              ["VIRUSTOTAL","70+エンジンURL検査 + ファイルハッシュ検索"],
              ["WEBRTC LEAK","リアルタイムIPリーク検出"],
              ["AI ANALYSIS","Claude Sonnet — URL / 脅威分析"],
              ["ENTROPY","Shannon Entropy計算（bits）"],
              ["PASSPHRASE","EFFスタイルダイスウェア（200語）"],
              ["STORAGE","localStorage（ローカルのみ・非送信）"],
              ["LOG","最大200件の操作ログを保持"],
            ].map(([k,v])=>(
              <div key={k} style={{display:"flex",gap:12,padding:"8px 0",borderBottom:"1px solid #00ffaa08"}}>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:"#00ccff55",width:140,flexShrink:0}}>{k}</span>
                <span style={{fontSize:12,color:"#c8fff077"}}>{v}</span>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="ct">データ管理</div>
            <div style={{fontSize:13,color:"#c8fff077",marginBottom:14}}>全データはlocalStorageに保存されます（サーバーに送信されません）</div>
            <button className="btn btn-r" onClick={()=>{if(window.confirm("全データをリセットしますか？この操作は取り消せません。")){["sg_chk","sg_dev","sg_log","sg_hist","sg_urlhist","sg_threats"].forEach(k=>LS.set(k,null));setChk({});setDevices([]);setLogs([]);setHist([]);setUrlHist([]);setThreatFeed(null);}}}>⚠ 全データをリセット</button>
          </div>
        </>}

      </div>
    </>
  );
}

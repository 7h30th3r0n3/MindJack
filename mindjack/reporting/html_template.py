"""Self-contained interactive HTML pentest report for MindJack v2.

Tabs:
- Executive Summary: risk overview, stats, top findings
- Attack Paths: BloodHound-style chains with MITRE ATT&CK, exploits, remediation
- Trust Graph: vis.js network with full filters and node detail
"""

from __future__ import annotations

import json as _json
from datetime import datetime, timezone


def render_html(graph_json: dict, paths_json: dict) -> str:
    if graph_json is None:
        graph_json = {"nodes": [], "edges": []}
    if paths_json is None:
        paths_json = {"metadata": {}, "attack_chains": [], "privilege_escalation": [],
                      "lateral_movement": [], "kill_chains": []}

    all_paths = (
        (paths_json.get("kill_chains") or [])
        + (paths_json.get("attack_chains") or [])
        + (paths_json.get("privilege_escalation") or [])
        + (paths_json.get("lateral_movement") or [])
    )
    all_paths.sort(key=lambda p: -p.get("risk_score", 0))

    seen: set[str] = set()
    deduped: list[dict] = []
    for p in all_paths:
        # Deduplicate by (type, entry, target, depth) to preserve multi-hop variants
        entry = p.get("entry") or (p["steps"][0]["label"] if p.get("steps") else "")
        target = p.get("target_tool") or p.get("to_tool") or p.get("final_target") or ""
        key = f"{p.get('type')}|{entry}|{target}|{len(p.get('steps', []))}"
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    # Compute exec summary stats
    nodes = graph_json.get("nodes", [])
    existing_tools = set()
    existing_artifacts = 0
    creatable_artifacts = 0
    for n in nodes:
        if n.get("type") == "artifact":
            if n.get("metadata", {}).get("exists"):
                existing_artifacts += 1
                ts = n.get("metadata", {}).get("tool_slug")
                if ts:
                    existing_tools.add(ts)
            else:
                creatable_artifacts += 1

    meta = paths_json.get("metadata", {})
    bysev = meta.get("by_severity", {})

    summary = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "tools_detected": sorted(existing_tools),
        "existing_artifacts": existing_artifacts,
        "creatable_artifacts": creatable_artifacts,
        "total_surfaces": sum(1 for n in nodes if n.get("type") == "trust_surface"),
        "critical_paths": bysev.get("critical", 0),
        "high_paths": bysev.get("high", 0),
        "medium_paths": bysev.get("medium", 0),
        "total_paths": meta.get("total_chains", len(deduped)),
        "top_findings": deduped[:5],
    }

    viewer_data = {
        "metadata": meta,
        "paths": deduped,
        "summary": summary,
    }

    html = _HTML
    html = html.replace("%%GRAPH_DATA%%", _json.dumps(graph_json))
    html = html.replace("%%PATHS_DATA%%", _json.dumps(viewer_data))
    return html


_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MindJack - AI Agent Attack Surface Report</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
:root{--bg:#0d1117;--s1:#161b22;--s2:#1c2128;--s3:#21262d;--bd:#30363d;
--t1:#e6edf3;--t2:#c9d1d9;--t3:#8b949e;--ac:#58a6ff;
--red:#f85149;--org:#f0883e;--ylw:#e3b341;--grn:#3fb950;--prp:#bc8cff;--cyan:#39d5ff}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--t2);overflow:hidden}

/* ===== TOP BAR ===== */
#bar{position:fixed;top:0;left:0;right:0;z-index:30;min-height:48px;background:var(--s1);border-bottom:1px solid var(--bd);display:flex;align-items:center;padding:8px 16px;gap:14px;flex-wrap:wrap}
#bar h1{font-size:14px;color:var(--red);letter-spacing:2px;font-weight:800;font-family:monospace}
.tabs{display:flex;gap:0;margin-left:20px}
.tabs button{background:0;color:var(--t3);border:0;padding:10px 18px;font-size:12px;cursor:pointer;border-bottom:2px solid transparent;transition:.15s;font-weight:600}
.tabs button:hover{color:var(--t1);background:var(--s2)}
.tabs button.on{color:var(--ac);border-bottom-color:var(--ac)}
.bar-r{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.bar-r select,.bar-r input[type=text]{background:var(--bg);color:var(--t2);border:1px solid var(--bd);border-radius:4px;padding:4px 8px;font-size:11px}
.bar-r input[type=text]{width:180px}
.bar-r label{font-size:11px;color:var(--t3);display:flex;align-items:center;gap:3px;cursor:pointer}
.bar-r input[type=checkbox]{accent-color:var(--ac)}
#stats{font-size:11px;color:var(--t3)}
.btn{background:var(--s3);color:var(--t2);border:1px solid var(--bd);border-radius:5px;padding:4px 12px;font-size:11px;cursor:pointer;transition:.1s}
.btn:hover{border-color:var(--ac);color:var(--ac)}
.btn-red{border-color:var(--red);color:var(--red)}
.btn-red:hover{background:var(--red);color:#fff}

/* ===== VIS.JS NAV BUTTONS ===== */
div.vis-network div.vis-navigation div.vis-button{background-color:var(--s2)!important;border:1px solid var(--bd)!important;border-radius:8px!important;opacity:.85;transition:.15s}
div.vis-network div.vis-navigation div.vis-button:hover{background-color:var(--ac)!important;border-color:var(--ac)!important;opacity:1}
div.vis-network div.vis-navigation div.vis-button:active{background-color:#1f6feb!important}
div.vis-network div.vis-navigation div.vis-button.vis-up,
div.vis-network div.vis-navigation div.vis-button.vis-down,
div.vis-network div.vis-navigation div.vis-button.vis-left,
div.vis-network div.vis-navigation div.vis-button.vis-right,
div.vis-network div.vis-navigation div.vis-button.vis-zoomIn,
div.vis-network div.vis-navigation div.vis-button.vis-zoomOut,
div.vis-network div.vis-navigation div.vis-button.vis-zoomExtends{filter:invert(1) brightness(1.5)!important}

/* ===== GRAPH CONTROLS ===== */
.gctrls{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.rels{display:flex;gap:3px;flex-wrap:wrap}
.rels label{font-size:10px;padding:4px 9px;border-radius:14px;border:none;display:flex;align-items:center;gap:4px;cursor:pointer;transition:.2s;color:var(--t3);background:var(--s2)}
.rels label:hover{background:var(--s3);color:var(--t1)}
.rels label.on{background:rgba(88,166,255,.12);color:var(--ac);box-shadow:inset 0 0 0 1px var(--ac)}
.rels input{display:none}
.rdot{width:7px;height:7px;border-radius:50%;display:inline-block;flex-shrink:0}
.vtog{display:flex;gap:0;background:var(--s2);border-radius:8px;padding:2px}
.vtog button{background:transparent;color:var(--t3);border:none;border-radius:6px;padding:4px 12px;font-size:10px;cursor:pointer;transition:.2s;font-weight:600}
.vtog button:hover{color:var(--t2)}
.vtog button.on{background:var(--ac);color:#fff;box-shadow:0 1px 4px rgba(88,166,255,.3)}

/* ===== LAYOUT ===== */
#content{position:absolute;left:0;right:0;bottom:0}
.tab-pane{display:none;position:absolute;top:0;left:0;right:0;bottom:0}
.tab-pane.active{display:flex}

/* ===== EXEC SUMMARY ===== */
#summary-pane{flex-direction:column;overflow-y:auto;padding:30px 40px}
.exec-hd{font-size:20px;color:var(--t1);font-weight:700;margin-bottom:20px;display:flex;align-items:center;gap:12px}
.exec-hd .gen{font-size:11px;color:var(--t3);font-weight:400}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:30px}
.stat-card{background:var(--s1);border:1px solid var(--bd);border-radius:8px;padding:16px}
.stat-card .num{font-size:28px;font-weight:700;font-family:monospace}
.stat-card .lbl{font-size:11px;color:var(--t3);margin-top:2px}
.stat-card.crit .num{color:var(--red)}
.stat-card.high .num{color:var(--org)}
.stat-card.med .num{color:var(--ylw)}
.stat-card.info .num{color:var(--ac)}
.stat-card.ok .num{color:var(--grn)}
.exec-section{margin-bottom:24px}
.exec-section h3{font-size:13px;color:var(--ac);margin-bottom:10px;text-transform:uppercase;letter-spacing:1px}
.tool-chip{display:inline-block;background:var(--s2);border:1px solid var(--bd);border-radius:4px;padding:3px 10px;font-size:12px;margin:2px 4px 2px 0;font-family:monospace}
.finding-row{background:var(--s1);border:1px solid var(--bd);border-radius:6px;padding:12px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start}
.finding-row .sev{flex-shrink:0;width:70px;text-align:center;font-size:10px;font-weight:700;padding:3px;border-radius:3px;text-transform:uppercase}
.sev-critical{background:var(--red);color:#fff}
.sev-high{background:var(--org);color:#fff}
.sev-medium{background:var(--ylw);color:#000}
.finding-row .body{flex:1}
.finding-row .title{font-size:13px;color:var(--t1);margin-bottom:3px}
.finding-row .desc{font-size:11px;color:var(--t3)}
.mitre-tag{display:inline-block;background:var(--s3);border:1px solid var(--bd);border-radius:3px;padding:1px 6px;font-size:9px;font-family:monospace;color:var(--cyan);margin:2px 2px 0 0}
.exploit-box{background:var(--bg);border:1px solid var(--bd);border-radius:4px;padding:8px 10px;font-size:11px;font-family:monospace;color:var(--org);margin-top:6px;white-space:pre-wrap;word-break:break-all}
.remed-box{background:rgba(56,211,80,.05);border:1px solid rgba(56,211,80,.2);border-radius:4px;padding:8px 10px;font-size:11px;color:var(--grn);margin-top:6px}

/* ===== ATTACK PATHS ===== */
#paths-pane{flex-direction:row}
#paths-graph{flex:1}
#paths-panel{width:420px;background:var(--s1);border-left:1px solid var(--bd);display:flex;flex-direction:column}
.pan-hd{padding:12px 14px;border-bottom:1px solid var(--bd)}
.pan-hd h2{font-size:13px;color:var(--ac)}
.pan-hd .sum{font-size:11px;color:var(--t3);margin-top:4px}
.fbar{padding:8px 14px;border-bottom:1px solid var(--bd);display:flex;gap:5px;flex-wrap:wrap}
.fchip{font-size:10px;padding:2px 8px;border-radius:10px;border:1px solid var(--bd);cursor:pointer;color:var(--t3);transition:.1s}
.fchip:hover,.fchip.on{border-color:var(--ac);color:var(--ac);background:rgba(88,166,255,.06)}
.search-bar{padding:6px 14px;border-bottom:1px solid var(--bd)}
.search-bar input{width:100%;background:var(--bg);color:var(--t2);border:1px solid var(--bd);border-radius:4px;padding:5px 8px;font-size:11px}
.pan-ct{flex:1;overflow-y:auto}

/* path cards */
.pc{border-bottom:1px solid var(--bd);padding:10px 14px;cursor:pointer;transition:background .1s}
.pc:hover{background:var(--s2)}
.pc.sel{background:rgba(88,166,255,.06);border-left:3px solid var(--ac)}
.pc .hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:3px}
.badge{font-size:9px;padding:1px 6px;border-radius:3px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.b-kill_chain{background:var(--red);color:#fff}
.b-direct_attack{background:var(--org);color:#fff}
.b-privilege_escalation{background:var(--ylw);color:#000}
.b-lateral_movement{background:var(--prp);color:#000}
.b-scope_escalation{background:var(--cyan);color:#000}
.b-execution_escalation{background:#f97583;color:#000}
.b-persistence_chain{background:#56d364;color:#000}
.b-cross_tool_kill_chain{background:#f85149;color:#fff}
.b-full_kill_chain{background:#da3633;color:#fff;border:1px solid #f97583}
.pc .sc{font-size:12px;font-weight:700;font-family:monospace}
.sc-c{color:var(--red)}.sc-h{color:var(--org)}.sc-m{color:var(--ylw)}
.pc .imp{font-size:11px;color:var(--t3);margin-bottom:4px}
.pc .mitre{margin-bottom:4px}
.chn{font-size:11px;font-family:monospace}
.cs{display:flex;align-items:flex-start;gap:6px;padding:2px 0}
.cs .ic{flex-shrink:0;width:16px;text-align:center;font-weight:700;font-size:12px}
.ic-cr{color:var(--red)}.ic-sf{color:var(--prp)}.ic-ex{color:var(--org)}
.ic-ov{color:var(--ylw)}.ic-lt{color:var(--grn)}.ic-pv{color:var(--t3)}.ic-pe{color:var(--cyan)}
.cs .dt{color:var(--t3);font-size:10px}
.cc{border-left:1px dashed var(--bd);margin-left:7px;height:5px}
.empty{padding:30px;text-align:center;color:var(--t3);font-size:12px}

/* ===== TRUST GRAPH ===== */
#graph-pane{flex-direction:row}
#graph-gfx{flex:1}
#graph-panel{width:400px;background:var(--s1);border-left:1px solid var(--bd);display:flex;flex-direction:column}
#ndet{display:none;padding:14px;border-bottom:1px solid var(--bd);max-height:50vh;overflow-y:auto}
#ndet.vis{display:block}
#ndet h3{font-size:13px;color:var(--ac);margin-bottom:6px;word-break:break-all}
#ndet table{width:100%;border-collapse:collapse}
#ndet td{padding:2px 6px;font-size:11px;border-bottom:1px solid var(--bg)}
#ndet td:first-child{color:var(--t3);width:35%}
.egrp{margin:6px 0}
.egrp-t{font-size:11px;font-weight:600;margin-bottom:2px}
.egrp a{display:block;font-size:11px;color:var(--ac);cursor:pointer;padding:1px 0;text-decoration:none}
.egrp a:hover{text-decoration:underline}
#graph-panel .pan-ct{flex:1;overflow-y:auto}
#owasp-pane{flex-direction:column;overflow-y:auto}
</style>
</head>
<body>

<div id="bar">
  <h1>MINDJACK</h1>
  <div class="tabs" id="tabs">
    <button class="on" data-t="summary">Executive Summary</button>
    <button data-t="paths">Attack Paths</button>
    <button data-t="owasp">OWASP Compliance</button>
    <button data-t="graph">Trust Graph</button>
  </div>
  <div class="bar-r">
    <div class="gctrls" id="gctrls" style="display:none">
      <label>Tool:<select id="tfilt" style="background:var(--bg);color:var(--t2);border:1px solid var(--bd);border-radius:6px;padding:4px 8px;font-size:11px"><option value="all">All</option></select></label>
      <div class="rels" id="rfilt"></div>
      <div class="vtog" id="vtog">
        <button class="on" data-v="full">Full</button>
        <button data-v="existing">Existing</button>
        <button data-v="critical">Critical</button>
      </div>
      <label style="font-size:11px;color:var(--t3);cursor:pointer;display:flex;align-items:center;gap:3px"><input type="checkbox" id="ckSurf" style="accent-color:var(--ac)">Hide surfaces</label>
    </div>
    <span id="stats"></span>
    <button class="btn" onclick="exportJSON()">Export JSON</button>
    <button class="btn" onclick="exportMD()">Export MD</button>
  </div>
</div>

<div id="content">
  <!-- EXEC SUMMARY -->
  <div class="tab-pane active" id="summary-pane"></div>

  <!-- ATTACK PATHS -->
  <div class="tab-pane" id="paths-pane">
    <div id="paths-graph"></div>
    <div id="paths-panel">
      <div class="pan-hd"><h2 id="ptitle">Attack Paths</h2><div class="sum" id="psum"></div></div>
      <div class="fbar" id="pfilt"></div>
      <div class="search-bar"><input type="text" id="psearch" placeholder="Search paths (file, tool, technique...)"></div>
      <div class="pan-ct" id="pan-ct"></div>
    </div>
  </div>

  <!-- OWASP COMPLIANCE -->
  <div class="tab-pane" id="owasp-pane"></div>

  <!-- TRUST GRAPH -->
  <div class="tab-pane" id="graph-pane">
    <div id="graph-gfx"></div>
    <div id="graph-panel">
      <div class="pan-hd"><h2>Node Detail</h2><div class="sum">Click a node to inspect</div></div>
      <div id="ndet"></div>
      <div class="pan-ct" id="graph-ct"></div>
    </div>
  </div>
</div>

<script>
var G=%%GRAPH_DATA%%,PD=%%PATHS_DATA%%;

/* === CONSTANTS === */
var NC={tool:{bg:'#da3633',bd:'#f85149'},artifact:{bg:'#1f6feb',bd:'#58a6ff'},trust_surface:{bg:'#8957e5',bd:'#d2a8ff'},scope:{bg:'#238636',bd:'#56d364'},project:{bg:'#9e6a03',bd:'#e3b341'}};
var SC={critical:'#f85149',high:'#f0883e',medium:'#e3b341',low:'#8b949e'};
var EC={belongs_to:'#484f58',persists_across:'#2ea043',influences:'#bc8cff',executes:'#f97583',overrides:'#9e6a03',shared_by:'#f0883e',reachable_from:'#3fb950'};
var RELDEF={belongs_to:true,influences:true,executes:true,shared_by:true,reachable_from:false,persists_across:false,overrides:false};
var ICONS={create:{i:'✚',c:'ic-cr'},escalate_to_surface:{i:'⚠',c:'ic-sf'},executes:{i:'▶',c:'ic-ex'},influences:{i:'∼',c:'ic-ex'},overrides:{i:'↑',c:'ic-ov'},shared_by:{i:'↔',c:'ic-lt'},lateral_via_shared:{i:'⇄',c:'ic-lt'},compromise:{i:'★',c:'ic-cr'},pivot:{i:'│',c:'ic-pv'},persist:{i:'ὑ2',c:'ic-pe'},modify_config:{i:'⚙',c:'ic-ov'},scope_escalate:{i:'⬆',c:'ic-pe'},config_write:{i:'⚙',c:'ic-ov'},permission_grant:{i:'🔓',c:'ic-pe'},mcp_register:{i:'⊕',c:'ic-cr'},memory_write:{i:'💾',c:'ic-pe'},session_persist:{i:'📌',c:'ic-pe'},cross_tool_pivot:{i:'⇄',c:'ic-lt'},persists_across:{i:'∞',c:'ic-pe'}};

/* === STATE === */
var net=null,curTab='summary',selIdx=-1,aFilt='all',activeView='full',activeRels={},hideSurfaces=false,searchQ='';
Object.keys(RELDEF).forEach(function(r){activeRels[r]=RELDEF[r]});

/* === INDEX === */
var BI={};
G.nodes.forEach(function(n){BI[n.id]=n;if(n.type==='artifact')n._s=n.label.replace(/\/home\/[^\/]+\//,'~/');if(n.type==='tool')n._s=n.label.toUpperCase();if(n.type==='project')n._s=n.label.replace(/\/home\/[^\/]+/,'~');if(n.type==='scope')n._s=n.label.toUpperCase()});
var SP={};G.edges.forEach(function(e){if(e.relation==='reachable_from'){var s=BI[e.source],t=BI[e.target];if(s&&s.type==='trust_surface'&&t&&t.type==='artifact')SP[e.source]=t}});
var ET={};G.nodes.forEach(function(n){if(n.type==='artifact'&&n.metadata&&n.metadata.exists){var t=n.metadata.tool_slug;if(t)ET[t]=true}});

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

/* === TABS === */
document.querySelectorAll('.tabs button').forEach(function(b){b.addEventListener('click',function(){
  document.querySelectorAll('.tabs button').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on');curTab=b.dataset.t;
  document.querySelectorAll('.tab-pane').forEach(function(p){p.classList.remove('active')});
  if(curTab==='summary'){document.getElementById('summary-pane').classList.add('active');document.getElementById('gctrls').style.display='none'}
  else if(curTab==='paths'){document.getElementById('paths-pane').classList.add('active');document.getElementById('gctrls').style.display='none';initPaths()}
  else if(curTab==='owasp'){document.getElementById('owasp-pane').classList.add('active');document.getElementById('gctrls').style.display='none';renderOWASP()}
  else{document.getElementById('graph-pane').classList.add('active');document.getElementById('gctrls').style.display='flex';initGraph()}
  setTimeout(adjustContent,10)
})});

/* ================================================================ */
/*  EXECUTIVE SUMMARY                                                */
/* ================================================================ */
function renderSummary(){
  var s=PD.summary||{};var el=document.getElementById('summary-pane');
  var h='<div class="exec-hd">AI Agent Attack Surface Assessment <span class="gen">'+esc(s.generated||'')+'</span></div>';

  h+='<div class="stat-grid">';
  h+='<div class="stat-card crit"><div class="num">'+(s.critical_paths||0)+'</div><div class="lbl">Critical Attack Paths</div></div>';
  h+='<div class="stat-card high"><div class="num">'+(s.high_paths||0)+'</div><div class="lbl">High Risk Paths</div></div>';
  h+='<div class="stat-card info"><div class="num">'+(s.total_paths||0)+'</div><div class="lbl">Total Attack Chains</div></div>';
  h+='<div class="stat-card ok"><div class="num">'+(s.tools_detected||[]).length+'</div><div class="lbl">AI Tools Detected</div></div>';
  h+='<div class="stat-card info"><div class="num">'+(s.existing_artifacts||0)+'</div><div class="lbl">Existing Artifacts</div></div>';
  h+='<div class="stat-card high"><div class="num">'+(s.creatable_artifacts||0)+'</div><div class="lbl">Creatable (Attack Surface)</div></div>';
  h+='<div class="stat-card info"><div class="num">'+(s.total_surfaces||0)+'</div><div class="lbl">Trust Surfaces</div></div>';
  h+='</div>';

  h+='<div class="exec-section"><h3>Detected AI Tools</h3>';
  (s.tools_detected||[]).forEach(function(t){h+='<span class="tool-chip">'+esc(t)+'</span>'});
  h+='</div>';

  h+='<div class="exec-section"><h3>Top Findings</h3>';
  (s.top_findings||[]).forEach(function(f){
    var sev=f.severity||'high';
    h+='<div class="finding-row"><div class="sev sev-'+sev+'">'+sev+'</div><div class="body">';
    h+='<div class="title">'+esc(f.type||'').replace(/_/g,' ').toUpperCase()+' - '+esc(f.impact||'')+'</div>';
    h+='<div class="desc">Risk score: '+((f.risk_score||0).toFixed?f.risk_score.toFixed(1):f.risk_score)+' · '+((f.steps||[]).length)+' steps · Target: '+esc(f.target_tool||f.to_tool||f.final_target||'?')+'</div>';
    if(f.mitre_techniques&&f.mitre_techniques.length){h+='<div style="margin-top:4px">';f.mitre_techniques.forEach(function(t){h+='<span class="mitre-tag">'+esc(t)+'</span>'});h+='</div>'}
    if(f.exploit_hint){h+='<div class="exploit-box">'+esc(f.exploit_hint)+'</div>'}
    if(f.remediation){h+='<div class="remed-box">Remediation: '+esc(f.remediation)+'</div>'}
    h+='</div></div>';
  });
  h+='</div>';

  h+='<div class="exec-section"><h3>Risk Matrix</h3>';
  h+='<table style="width:100%;border-collapse:collapse;background:var(--s1);border:1px solid var(--bd);border-radius:6px;overflow:hidden">';
  h+='<tr style="background:var(--s2)"><th style="padding:8px;text-align:left;font-size:11px;color:var(--t3)">Attack Type</th><th style="padding:8px;text-align:center;font-size:11px;color:var(--t3)">Count</th><th style="padding:8px;text-align:center;font-size:11px;color:var(--t3)">Max Risk</th><th style="padding:8px;text-align:left;font-size:11px;color:var(--t3)">Primary Target</th></tr>';
  var byType={};(PD.paths||[]).forEach(function(p){var t=p.type||'?';if(!byType[t])byType[t]={count:0,maxRisk:0,targets:{}};byType[t].count++;if(p.risk_score>byType[t].maxRisk)byType[t].maxRisk=p.risk_score;var tgt=p.target_tool||p.to_tool||p.final_target||'?';byType[t].targets[tgt]=(byType[t].targets[tgt]||0)+1});
  Object.keys(byType).sort(function(a,b){return byType[b].maxRisk-byType[a].maxRisk}).forEach(function(t){
    var d=byType[t];var topTgt=Object.keys(d.targets).sort(function(a,b){return d.targets[b]-d.targets[a]})[0]||'?';
    var rc=d.maxRisk>=8?'var(--red)':d.maxRisk>=6?'var(--org)':'var(--ylw)';
    h+='<tr style="border-top:1px solid var(--bd)"><td style="padding:8px;font-size:12px">'+esc(t.replace(/_/g,' '))+'</td><td style="padding:8px;text-align:center;font-size:12px;font-family:monospace">'+d.count+'</td><td style="padding:8px;text-align:center;font-family:monospace;color:'+rc+'">'+d.maxRisk.toFixed(1)+'</td><td style="padding:8px;font-size:12px;font-family:monospace">'+esc(topTgt)+'</td></tr>';
  });
  h+='</table></div>';

  el.innerHTML=h;
}

/* ================================================================ */
/*  ATTACK PATHS                                                     */
/* ================================================================ */
var _pInit=false;
function initPaths(){
  if(_pInit){return}
  _pInit=true;
  var m=PD.metadata||{};var bys=m.by_severity||{};
  document.getElementById('ptitle').textContent='Attack Paths';
  document.getElementById('psum').innerHTML='<span style="color:var(--red)">'+(bys.critical||0)+' critical</span> · <span style="color:var(--org)">'+(bys.high||0)+' high</span> · '+(m.total_chains||0)+' chains';

  /* Build filter chips dynamically from actual data */
  var types=new Set();(PD.paths||[]).forEach(function(p){if(p.type)types.add(p.type)});
  var pfilt=document.getElementById('pfilt');
  pfilt.innerHTML='<span class="fchip on" data-f="all">All</span>';
  var labels={kill_chain:'Kill Chains',direct_attack:'Direct',privilege_escalation:'Priv Esc',lateral_movement:'Lateral',scope_escalation:'Scope Esc',execution_escalation:'Exec Esc',persistence_chain:'Persist',cross_tool_kill_chain:'Cross-Tool KC',full_kill_chain:'Full KC'};
  types.forEach(function(t){pfilt.innerHTML+='<span class="fchip" data-f="'+t+'">'+(labels[t]||t.replace(/_/g,' '))+'</span>'});
  pfilt.querySelectorAll('.fchip').forEach(function(c){c.addEventListener('click',function(){pfilt.querySelectorAll('.fchip').forEach(function(x){x.classList.remove('on')});c.classList.add('on');aFilt=c.dataset.f;selIdx=-1;renderPL();renderPG(null)})});

  document.getElementById('psearch').addEventListener('input',function(){searchQ=this.value.toLowerCase();renderPL()});

  renderPL();renderPG(null);
}

function getPaths(){return PD.paths||[]}

function renderPL(){
  var ct=document.getElementById('pan-ct');
  var ps=getPaths();
  if(aFilt!=='all')ps=ps.filter(function(p){return p.type===aFilt});
  if(searchQ)ps=ps.filter(function(p){return JSON.stringify(p).toLowerCase().indexOf(searchQ)!==-1});
  ps=ps.slice(0,200);
  document.getElementById('stats').textContent=ps.length+' paths';
  ct._ps=ps;
  if(!ps.length){ct.innerHTML='<div class="empty">No attack paths match filters.</div>';return}
  var h='';
  ps.forEach(function(p,i){
    var sc=p.severity==='critical'?'sc-c':p.severity==='high'?'sc-h':'sc-m';
    var mitre='';
    if(p.mitre_techniques&&p.mitre_techniques.length){p.mitre_techniques.forEach(function(t){mitre+='<span class="mitre-tag">'+esc(t)+'</span>'})}
    var steps='';
    (p.steps||[]).forEach(function(s){
      var si=ICONS[s.action]||{i:'?',c:'ic-ex'};
      steps+='<div class="cs"><span class="ic '+si.c+'">'+si.i+'</span><div><div>'+esc(s.label)+'</div><div class="dt">'+esc(s.detail||'')+'</div></div></div><div class="cc"></div>';
    });
    h+='<div class="pc'+(i===selIdx?' sel':'')+'" data-i="'+i+'"><div class="hdr"><span class="badge b-'+(p.type||'direct_attack')+'">'+esc((p.type||'').replace(/_/g,' '))+'</span><span class="sc '+sc+'">'+(p.risk_score||0)+'</span></div>';
    if(mitre)h+='<div class="mitre">'+mitre+'</div>';
    h+='<div class="imp">'+esc(p.impact||'')+'</div><div class="chn">'+steps+'</div></div>';
  });
  ct.innerHTML=h;
  ct.querySelectorAll('.pc').forEach(function(el){el.addEventListener('click',function(){
    var idx=parseInt(el.dataset.i);selIdx=idx;
    ct.querySelectorAll('.pc').forEach(function(c){c.classList.remove('sel')});el.classList.add('sel');
    renderPG(ct._ps[idx]);
  })});
}

function renderPG(path){
  var c=document.getElementById('paths-graph');
  if(!path){
    var ps=getPaths(),tc={};
    ps.forEach(function(p){var t=p.target_tool||p.to_tool||p.final_target;if(t)tc[t]=(tc[t]||0)+1});
    var vn=[];
    Object.keys(ET).sort().forEach(function(tool){vn.push({id:'tool:'+tool,label:tool.toUpperCase()+'\n'+(tc[tool]||0)+' attack paths',shape:'hexagon',size:40,color:{background:'#da3633',border:'#f85149'},font:{color:'#fff',size:14,face:'monospace',multi:'md',bold:true}})});
    if(net)net.destroy();
    net=new vis.Network(c,{nodes:new vis.DataSet(vn),edges:new vis.DataSet([])},{physics:{solver:'repulsion',repulsion:{nodeDistance:300,springLength:200}},interaction:{hover:true}});
    return;
  }
  var vn=[],ve=[],seen={};
  (path.steps||[]).forEach(function(s,i){
    if(s.node_type==='separator')return;var nid=s.node_id||('s'+i);if(seen[nid])return;seen[nid]=true;
    var bg,bd,shape='box',sz=25,fsz=12;
    switch(s.action){
      case'create':case'compromise':bg='#da3633';bd='#f85149';break;
      case'escalate_to_surface':bg='#8957e5';bd='#d2a8ff';shape='triangle';sz=22;break;
      case'executes':case'influences':bg='#da3633';bd='#f85149';shape='hexagon';sz=35;fsz=15;break;
      case'overrides':case'modify_config':bg='#9e6a03';bd='#e3b341';break;
      case'shared_by':case'lateral_via_shared':bg='#238636';bd='#3fb950';shape='dot';sz=20;break;
      case'persist':case'scope_escalate':bg='#1f6feb';bd='#58a6ff';break;
      default:bg='#484f58';bd='#6e7681';sz=18;
    }
    vn.push({id:nid,label:s.label+(s.detail?'\n'+s.detail:''),shape:shape,size:sz,color:{background:bg,border:bd},font:{color:'#fff',size:fsz,face:'monospace',multi:'md'},shadow:{enabled:true,size:4,color:'rgba(0,0,0,.3)'}});
  });
  var real=(path.steps||[]).filter(function(s){return s.node_type!=='separator'});
  for(var i=0;i<real.length-1;i++){
    var f=real[i].node_id||('s'+(path.steps||[]).indexOf(real[i]));
    var t=real[i+1].node_id||('s'+(path.steps||[]).indexOf(real[i+1]));
    if(!seen[f]||!seen[t])continue;
    var lat=real[i+1].action==='lateral_via_shared'||real[i+1].action==='shared_by';
    ve.push({from:f,to:t,color:{color:lat?'#3fb950':'#f85149',opacity:.9},width:3,arrows:{to:{enabled:true,scaleFactor:.6}},smooth:{type:'curvedCW',roundness:.1},dashes:lat?[8,4]:false,label:(real[i+1].action||'').replace(/_/g,' '),font:{color:'#8b949e',size:9,strokeWidth:3,strokeColor:'#0d1117',align:'top'}});
  }
  if(net)net.destroy();
  net=new vis.Network(c,{nodes:new vis.DataSet(vn),edges:new vis.DataSet(ve)},{layout:{hierarchical:{enabled:true,direction:'LR',sortMethod:'directed',levelSeparation:350,nodeSpacing:150,treeSpacing:200}},physics:false,interaction:{hover:true,zoomView:true},edges:{font:{align:'top'}}});
}

/* ================================================================ */
/*  TRUST GRAPH                                                      */
/* ================================================================ */
var _gInit=false;
function initGraph(){
  if(!_gInit){
    _gInit=true;
    var sel=document.getElementById('tfilt');
    Object.keys(ET).sort().forEach(function(t){var o=document.createElement('option');o.value=t;o.textContent=t;sel.appendChild(o)});
    sel.addEventListener('change',renderTG);
    var rd=document.getElementById('rfilt');
    Object.keys(RELDEF).forEach(function(r){
      var l=document.createElement('label');if(RELDEF[r])l.classList.add('on');
      var cb=document.createElement('input');cb.type='checkbox';cb.checked=RELDEF[r];cb.dataset.r=r;
      cb.addEventListener('change',function(){activeRels[r]=cb.checked;l.classList.toggle('on',cb.checked);renderTG()});
      var d=document.createElement('span');d.className='rdot';d.style.background=EC[r]||'#484f58';
      l.append(cb,d,document.createTextNode(' '+r));rd.appendChild(l);
    });
    document.querySelectorAll('#vtog button').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('#vtog button').forEach(function(x){x.classList.remove('on')});b.classList.add('on');activeView=b.dataset.v;renderTG()})});
    document.getElementById('ckSurf').addEventListener('change',function(){hideSurfaces=this.checked;renderTG()});
  }
  renderTG();
}

function renderTG(){
  var tool=document.getElementById('tfilt').value;
  var nodes=G.nodes.slice(),edges=G.edges.slice();
  var rmIds={};
  nodes=nodes.filter(function(n){if(n.type==='tool'&&!ET[n.label]){rmIds[n.id]=true;return false}if(n.type==='artifact'&&n.metadata){var ts=n.metadata.tool_slug;if(ts&&!ET[ts]){rmIds[n.id]=true;return false}}return true});
  edges=edges.filter(function(e){return!rmIds[e.source]&&!rmIds[e.target]});
  if(tool!=='all'){var tid='tool:'+tool,keep={};nodes.forEach(function(n){if(n.id===tid||(n.metadata&&n.metadata.tool_slug===tool))keep[n.id]=true});edges=edges.filter(function(e){return keep[e.source]||keep[e.target]});var conn=Object.assign({},keep);edges.forEach(function(e){conn[e.source]=true;conn[e.target]=true});nodes=nodes.filter(function(n){return conn[n.id]})}
  if(activeView==='existing'){var rm2={};nodes=nodes.filter(function(n){if(n.type==='artifact'&&n.metadata&&!n.metadata.exists){rm2[n.id]=true;return false}return true});edges=edges.filter(function(e){return!rm2[e.source]&&!rm2[e.target]})}
  else if(activeView==='critical'){var cs={};nodes.forEach(function(n){if(n.type==='trust_surface'&&n.metadata&&n.metadata.severity==='critical')cs[n.id]=true});var cc=Object.assign({},cs);edges.forEach(function(e){if(cc[e.source]||cc[e.target]){cc[e.source]=true;cc[e.target]=true}});nodes.forEach(function(n){if(n.type==='tool'||n.type==='scope'||n.type==='project')cc[n.id]=true});nodes=nodes.filter(function(n){return cc[n.id]});edges=edges.filter(function(e){return cc[e.source]&&cc[e.target]})}
  if(hideSurfaces){var sIds={};nodes=nodes.filter(function(n){if(n.type==='trust_surface'){sIds[n.id]=true;return false}return true});edges=edges.filter(function(e){return!sIds[e.source]&&!sIds[e.target]})}
  edges=edges.filter(function(e){return activeRels[e.relation]});
  var fin={};edges.forEach(function(e){fin[e.source]=true;fin[e.target]=true});nodes.forEach(function(n){if(n.type==='tool'||n.type==='scope'||n.type==='project')fin[n.id]=true});nodes=nodes.filter(function(n){return fin[n.id]});

  var vn=nodes.map(function(n){var c=NC[n.type]||NC.artifact;var label=n._s||n.label;if(n.type==='trust_surface'){var p=SP[n.id];if(p)label=n.label+'\n'+((p._s||p.label).split('/').pop())}var sz=n.type==='tool'?35:n.type==='scope'?20:n.type==='trust_surface'?10:14;var sh=n.type==='tool'?'hexagon':n.type==='scope'?'diamond':n.type==='trust_surface'?'triangle':'box';var ex=!n.metadata||n.metadata.exists!==false;return{id:n.id,label:label,shape:sh,size:sz,color:{background:n.type==='trust_surface'?(SC[n.metadata&&n.metadata.severity]||c.bg):c.bg,border:c.bd,highlight:{background:'#58a6ff',border:'#79c0ff'},hover:{background:'#58a6ff',border:'#79c0ff'}},font:{color:'#e6edf3',size:n.type==='tool'?14:10,face:'monospace',multi:'md'},opacity:ex?1:.4,borderWidth:ex?2:1,_raw:n}});
  var ve=edges.map(function(e,i){return{id:'e'+i,from:e.source,to:e.target,color:{color:EC[e.relation]||'#484f58',opacity:.5},arrows:{to:{enabled:true,scaleFactor:.4}},width:e.relation==='executes'?2:1,smooth:{type:'curvedCW',roundness:.15},_raw:e}});

  document.getElementById('stats').textContent=vn.length+' nodes / '+ve.length+' edges';
  var container=document.getElementById('graph-gfx');
  var ds={nodes:new vis.DataSet(vn),edges:new vis.DataSet(ve)};
  var nLen=vn.length;
  if(net)net.destroy();
  net=new vis.Network(container,ds,{physics:{solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:nLen>200?-120:nLen>80?-200:-400,centralGravity:.003,springLength:nLen>200?150:nLen>80?220:300,springConstant:.01,damping:.8,avoidOverlap:.5},stabilization:{iterations:300,fit:true},maxVelocity:20},interaction:{hover:true,navigationButtons:true,keyboard:true},layout:{improvedLayout:nLen<150},nodes:{shadow:{enabled:true,size:4,x:2,y:2,color:'rgba(0,0,0,.3)'}}});
  net.on('click',function(ev){if(ev.nodes.length){var vnode=ds.nodes.get(ev.nodes[0]);if(vnode&&vnode._raw)showND(vnode._raw,edges)}else{document.getElementById('ndet').className=''}});
}

function showND(node,allEdges){
  var det=document.getElementById('ndet');det.className='vis';
  var m=node.metadata||{};var h='<h3>'+esc(node._s||node.label)+'</h3>';
  var tc=(NC[node.type]||{}).bg||'#484f58';
  h+='<div style="margin-bottom:8px"><span style="background:'+tc+';color:#fff;padding:1px 8px;border-radius:4px;font-size:10px">'+node.type+'</span></div>';
  if(Object.keys(m).length){h+='<table>';Object.keys(m).forEach(function(k){var v=m[k];if(k==='severity')v='<span style="color:'+(SC[v]||'#8b949e')+'">'+String(v).toUpperCase()+'</span>';else if(k==='exists')v=v?'<span style="color:var(--grn)">YES</span>':'<span style="color:var(--t3)">creatable</span>';else if(k==='composite')v=Number(v).toFixed(2);else v=esc(v);h+='<tr><td>'+k+'</td><td>'+v+'</td></tr>'});h+='</table>'}
  else if(node.type==='tool'){var arts=G.nodes.filter(function(n){return n.type==='artifact'&&n.metadata&&n.metadata.tool_slug===node.label});var ex=arts.filter(function(a){return a.metadata&&a.metadata.exists});h+='<table><tr><td>Artifacts</td><td>'+arts.length+'</td></tr><tr><td>Existing</td><td style="color:var(--grn)">'+ex.length+'</td></tr><tr><td>Creatable</td><td>'+(arts.length-ex.length)+'</td></tr></table>'}
  var conn=(allEdges||[]).filter(function(e){return e.source===node.id||e.target===node.id});
  if(conn.length){var grp={};conn.forEach(function(e){var r=e.relation||'?';if(!grp[r])grp[r]=[];var oid=e.source===node.id?e.target:e.source;var o=BI[oid];grp[r].push({id:oid,label:o?((o._s||o.label).split('\n')[0]):oid,type:o?o.type:'?',dir:e.source===node.id?'→':'←'})});
  h+='<div style="margin-top:10px">';Object.keys(grp).forEach(function(r){var items=grp[r];var col=EC[r]||'#484f58';h+='<div class="egrp"><div class="egrp-t" style="color:'+col+'">'+r+' ('+items.length+')</div>';items.slice(0,12).forEach(function(it){var c2=(NC[it.type]||{}).bd||'#8b949e';h+='<a style="color:'+c2+'" onclick="focN(\''+it.id+'\')">'+it.dir+' '+esc(it.label)+'</a>'});if(items.length>12)h+='<span style="color:var(--t3);font-size:10px">… +'+(items.length-12)+'</span>';h+='</div>'});h+='</div>'}
  det.innerHTML=h;document.getElementById('graph-ct').innerHTML='';
}

window.focN=function(nid){if(net){net.focus(nid,{scale:1.5,animation:{duration:400}});net.selectNodes([nid]);var n=BI[nid];if(n)showND(n,G.edges)}};

/* ================================================================ */
/*  EXPORTS                                                          */
/* ================================================================ */
function exportJSON(){
  var data={graph:G,paths:PD,generated:new Date().toISOString()};
  var blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='mindjack_export.json';a.click();
}

function exportMD(){
  var ps=getPaths();var md='# MindJack Attack Surface Report\n\n';
  md+='Generated: '+(PD.summary&&PD.summary.generated||new Date().toISOString())+'\n\n';
  md+='## Summary\n\n';
  md+='| Metric | Value |\n|--------|-------|\n';
  var s=PD.summary||{};
  md+='| Tools Detected | '+(s.tools_detected||[]).join(', ')+' |\n';
  md+='| Existing Artifacts | '+(s.existing_artifacts||0)+' |\n';
  md+='| Creatable Artifacts | '+(s.creatable_artifacts||0)+' |\n';
  md+='| Critical Paths | '+(s.critical_paths||0)+' |\n';
  md+='| High Paths | '+(s.high_paths||0)+' |\n';
  md+='| Total Paths | '+(s.total_paths||0)+' |\n\n';
  md+='## Attack Paths\n\n';
  ps.slice(0,50).forEach(function(p,i){
    md+='### '+(i+1)+'. ['+((p.severity||'?').toUpperCase())+'] '+(p.type||'?').replace(/_/g,' ')+' (risk: '+(p.risk_score||0)+')\n\n';
    md+='**Impact:** '+esc(p.impact||'')+'\n\n';
    if(p.mitre_techniques&&p.mitre_techniques.length)md+='**MITRE:** '+p.mitre_techniques.join(', ')+'\n\n';
    if(p.exploit_hint)md+='**Exploit:** `'+p.exploit_hint+'`\n\n';
    if(p.remediation)md+='**Remediation:** '+p.remediation+'\n\n';
    md+='| Step | Action | Target |\n|------|--------|--------|\n';
    (p.steps||[]).forEach(function(st,j){md+='| '+(j+1)+' | '+(st.action||'')+' | '+(st.label||'')+' |\n'});
    md+='\n';
  });
  var blob=new Blob([md],{type:'text/markdown'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='mindjack_report.md';a.click();
}

/* ================================================================ */
/*  OWASP COMPLIANCE                                                 */
/* ================================================================ */
var OWASP_LLM = [
  {id:'LLM01',title:'Prompt Injection',surfaces:['prompt_injection'],desc:'Instruction files (CLAUDE.md, AGENTS.md, .cursorrules) enable direct and indirect prompt injection'},
  {id:'LLM02',title:'Sensitive Information Disclosure',surfaces:['execution_hook','tool_control'],desc:'Hook-based exfiltration and MCP server data leakage'},
  {id:'LLM03',title:'Supply Chain Vulnerabilities',surfaces:['prompt_injection','config_override'],desc:'Poisoned instruction files in cloned repositories'},
  {id:'LLM04',title:'Data and Model Poisoning',surfaces:['context_poisoning'],desc:'Persistent memory corruption across sessions'},
  {id:'LLM05',title:'Improper Output Handling',surfaces:['execution_hook'],desc:'Forced output format manipulation for data embedding'},
  {id:'LLM06',title:'Excessive Agency',surfaces:['permission_escalation','tool_control'],desc:'Auto-approval of tools and unrestricted allowedTools'},
  {id:'LLM07',title:'System Prompt Leakage',surfaces:['prompt_injection'],desc:'Full prompt recovery through conversation extraction'},
  {id:'LLM09',title:'Misinformation',surfaces:['prompt_injection','context_poisoning'],desc:'Model deception and behavioral misdirection'},
  {id:'LLM10',title:'Unbounded Consumption',surfaces:['config_override'],desc:'Silent model downgrade affecting quality and cost'}
];

var OWASP_AGENTIC = [
  {id:'ASI01',title:'Agent Goal Hijack',surfaces:['prompt_injection'],desc:'Instruction file overrides redirecting agent objectives'},
  {id:'ASI02',title:'Tool Misuse',surfaces:['permission_escalation','tool_control'],desc:'Auto-approval and unintended tool execution patterns'},
  {id:'ASI03',title:'Identity & Privilege Abuse',surfaces:['permission_escalation','config_override'],desc:'Permission escalation via configuration poisoning'},
  {id:'ASI04',title:'Agentic Supply Chain',surfaces:['tool_control'],desc:'Malicious MCP server injection and tool compromise'},
  {id:'ASI05',title:'Unexpected Code Execution',surfaces:['execution_hook','tool_control'],desc:'Hooks and MCP servers executing arbitrary commands'},
  {id:'ASI06',title:'Memory & Context Poisoning',surfaces:['context_poisoning','prompt_injection'],desc:'Cross-session memory manipulation and fake context'},
  {id:'ASI07',title:'Insecure Inter-Agent Communication',surfaces:['prompt_injection'],desc:'Multi-tool compromise via shared instruction files'},
  {id:'ASI08',title:'Cascading Failures',surfaces:['config_override','prompt_injection'],desc:'Poisoned instructions breaking downstream processes'},
  {id:'ASI09',title:'Human-Agent Trust Exploitation',surfaces:['prompt_injection'],desc:'Social engineering and gaslighting techniques'},
  {id:'ASI10',title:'Rogue Agents',surfaces:['execution_hook','tool_control','context_poisoning'],desc:'Persistent malicious behavior across sessions'}
];

function renderOWASP(){
  var el=document.getElementById('owasp-pane');
  if(el.innerHTML)return;

  /* Count surfaces by type from graph */
  var surfCounts={};
  G.nodes.forEach(function(n){if(n.type==='trust_surface'){var l=n.label||'';surfCounts[l]=(surfCounts[l]||0)+1}});

  /* Count attack paths by surface type */
  var pathsBySurface={};
  (PD.paths||[]).forEach(function(p){
    var st=p.surface_type||'';if(st)pathsBySurface[st]=(pathsBySurface[st]||0)+1;
    (p.steps||[]).forEach(function(s){if(s.action==='escalate_to_surface'){pathsBySurface[s.label]=(pathsBySurface[s.label]||0)+1}});
  });

  function renderTable(items, title){
    var h='<div class="exec-section"><h3>'+esc(title)+'</h3>';
    var covered=0;
    h+='<table style="width:100%;border-collapse:collapse;background:var(--s1);border:1px solid var(--bd);border-radius:6px;overflow:hidden">';
    h+='<tr style="background:var(--s2)"><th style="padding:10px;text-align:left;font-size:11px;color:var(--t3);width:80px">ID</th><th style="padding:10px;text-align:left;font-size:11px;color:var(--t3)">Category</th><th style="padding:10px;text-align:center;font-size:11px;color:var(--t3);width:80px">Status</th><th style="padding:10px;text-align:center;font-size:11px;color:var(--t3);width:80px">Surfaces</th><th style="padding:10px;text-align:center;font-size:11px;color:var(--t3);width:100px">Attack Paths</th><th style="padding:10px;text-align:left;font-size:11px;color:var(--t3)">Finding</th></tr>';
    items.forEach(function(item){
      var totalSurf=0;var totalPaths=0;
      item.surfaces.forEach(function(s){totalSurf+=(surfCounts[s]||0);totalPaths+=(pathsBySurface[s]||0)});
      var status,statusColor;
      if(totalPaths>0){status='EXPOSED';statusColor='var(--red)';covered++}
      else if(totalSurf>0){status='AT RISK';statusColor='var(--org)';covered++}
      else{status='N/A';statusColor='var(--t3)'}
      h+='<tr style="border-top:1px solid var(--bd)"><td style="padding:10px;font-size:12px;font-weight:700;font-family:monospace;color:var(--cyan)">'+item.id+'</td>';
      h+='<td style="padding:10px;font-size:12px;color:var(--t1)">'+esc(item.title)+'</td>';
      h+='<td style="padding:10px;text-align:center"><span style="background:'+(status==='EXPOSED'?'var(--red)':status==='AT RISK'?'var(--org)':'var(--s3)')+';color:'+(status==='N/A'?'var(--t3)':'#fff')+';padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700">'+status+'</span></td>';
      h+='<td style="padding:10px;text-align:center;font-family:monospace;color:'+(totalSurf>0?'var(--org)':'var(--t3)')+'">'+totalSurf+'</td>';
      h+='<td style="padding:10px;text-align:center;font-family:monospace;color:'+(totalPaths>0?'var(--red)':'var(--t3)')+'">'+totalPaths+'</td>';
      h+='<td style="padding:10px;font-size:11px;color:var(--t3)">'+esc(item.desc)+'</td></tr>';
    });
    h+='</table>';
    h+='<div style="margin-top:8px;font-size:12px;color:var(--t3)">Coverage: <span style="color:var(--ac);font-weight:700">'+covered+'/'+items.length+'</span> ('+Math.round(covered/items.length*100)+'%) categories with findings</div>';
    h+='</div>';
    return h;
  }

  var h='<div style="padding:30px 40px;overflow-y:auto;height:100%">';
  h+='<div class="exec-hd">OWASP Compliance Assessment</div>';

  /* Summary cards */
  var llmExposed=0,llmRisk=0,asiExposed=0,asiRisk=0;
  OWASP_LLM.forEach(function(item){var tp=0;item.surfaces.forEach(function(s){tp+=(pathsBySurface[s]||0)});if(tp>0)llmExposed++;else{var ts=0;item.surfaces.forEach(function(s){ts+=(surfCounts[s]||0)});if(ts>0)llmRisk++}});
  OWASP_AGENTIC.forEach(function(item){var tp=0;item.surfaces.forEach(function(s){tp+=(pathsBySurface[s]||0)});if(tp>0)asiExposed++;else{var ts=0;item.surfaces.forEach(function(s){ts+=(surfCounts[s]||0)});if(ts>0)asiRisk++}});

  h+='<div class="stat-grid">';
  h+='<div class="stat-card crit"><div class="num">'+llmExposed+'/'+OWASP_LLM.length+'</div><div class="lbl">LLM Top 10 - Exposed</div></div>';
  h+='<div class="stat-card high"><div class="num">'+llmRisk+'/'+OWASP_LLM.length+'</div><div class="lbl">LLM Top 10 - At Risk</div></div>';
  h+='<div class="stat-card crit"><div class="num">'+asiExposed+'/'+OWASP_AGENTIC.length+'</div><div class="lbl">Agentic AI - Exposed</div></div>';
  h+='<div class="stat-card high"><div class="num">'+asiRisk+'/'+OWASP_AGENTIC.length+'</div><div class="lbl">Agentic AI - At Risk</div></div>';
  h+='</div>';

  h+=renderTable(OWASP_LLM,'OWASP Top 10 for LLM Applications (2025)');
  h+=renderTable(OWASP_AGENTIC,'OWASP Top 10 for Agentic AI Applications (2025)');
  h+='</div>';

  el.innerHTML=h;
}

/* ======== LAYOUT ======== */
function adjustContent(){document.getElementById('content').style.top=document.getElementById('bar').offsetHeight+'px'}
adjustContent();
window.addEventListener('resize',adjustContent);
var _barObs=new MutationObserver(adjustContent);
_barObs.observe(document.getElementById('bar'),{childList:true,subtree:true,attributes:true});

/* ======== INIT ======== */
renderSummary();
</script>
</body>
</html>"""

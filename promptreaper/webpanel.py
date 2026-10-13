"""Panel web local de PromptReaper.

Servidor HTTP sin dependencias (solo stdlib) que sirve una SPA para configurar un
objetivo, lanzar el escaneo y ver los resultados en vivo (progreso por SSE),
reutilizando el mismo motor (consentimiento, payloads, juez, informe) que la CLI.

Por defecto escucha SOLO en 127.0.0.1 (local). La PUERTA DE CONSENTIMIENTO sigue
siendo obligatoria: el panel no escanea nada sin `authorized` + nota + allowlist.
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import Engagement, ConsentError
from .llm import get_llm
from .owasp import CATALOG
from .payloads import load_payloads
from .runner import Scanner

_JOBS: dict[str, queue.Queue] = {}
_PREFER = None
_NO_LLM = False


def _build_engagement(form: dict) -> Engagement:
    """Construye un Engagement desde el formulario del panel."""
    name = (form.get("target_name") or "objetivo").strip()
    kind = form.get("kind") or "http"
    url = (form.get("url") or "").strip()
    allow = [a.strip() for a in (form.get("allowlist") or "").replace(",", "\n").splitlines()
             if a.strip()]
    # Auto-incluye el nombre del objetivo y el host de la URL en la allowlist.
    allow.append(name)
    if kind == "http" and url:
        host = urlparse(url).hostname or ""
        if host:
            allow.append(host)
    if kind == "callable" and form.get("callable"):
        allow.append(form["callable"].strip())

    headers = {}
    raw_headers = (form.get("headers") or "").strip()
    if raw_headers:
        headers = json.loads(raw_headers)  # debe ser un objeto JSON

    target = {
        "name": name, "kind": kind,
        "url": url, "method": form.get("method") or "POST",
        "headers": headers,
        "body_template": form.get("body_template") or '{"message": "{PROMPT}"}',
        "response_path": form.get("response_path") or "",
        "timeout": int(form.get("timeout") or 30),
        "retries": int(form.get("retries") or 2),
        "callable": (form.get("callable") or "").strip(),
        "known_canaries": [c.strip() for c in (form.get("known_canaries") or "").splitlines()
                           if c.strip()],
    }
    raw = {
        "project": (form.get("project") or "panel").strip(),
        "authorized": bool(form.get("authorized")),
        "authorization_note": (form.get("authorization_note") or "").strip(),
        "allowlist": sorted(set(a.lower() for a in allow)),
        "langs": form.get("langs") or ["es", "en"],
        "max_turns": int(form.get("max_turns") or 3),
        "use_llm_attacker": bool(form.get("use_llm")),
        "use_llm_judge": bool(form.get("use_llm")),
        "forbidden_markers": [m.strip() for m in (form.get("forbidden_markers") or "").splitlines()
                              if m.strip()],
        "targets": [target],
    }
    return Engagement.from_dict(raw)


def _run_scan(form: dict, q: "queue.Queue") -> None:
    try:
        eng = _build_engagement(form)
        try:
            eng.enforce_consent()
        except ConsentError as exc:
            q.put({"type": "error", "msg": f"Consentimiento no válido: {exc}"})
            return

        attacker = judge = None
        if not _NO_LLM and form.get("use_llm"):
            attacker = get_llm(_PREFER)
            judge = get_llm(_PREFER)

        only = [c.strip() for c in (form.get("only_owasp") or "").split(",") if c.strip()] or None
        scanner = Scanner(
            eng, attacker_llm=attacker, judge_llm=judge,
            forbidden_markers=eng.forbidden_markers,
            progress=lambda m: q.put({"type": "progress", "msg": m}),
            jobs=int(form.get("jobs") or 1), only_owasp=only,
            min_severity=form.get("min_severity") or None,
        )
        q.put({"type": "progress", "msg": f"Atacante: {attacker.provider if attacker else 'estatico'} · "
                                          f"Juez: {judge.provider if judge else 'heuristico'}"})
        tcfg = eng.targets[0]
        report = scanner.scan_target(tcfg)
        grade, pts = report.score()
        q.put({
            "type": "result",
            "grade": grade, "points": pts,
            "report": report.to_dict(),
            "downloads": {
                "json": report.to_json(),
                "md": report.to_markdown(),
                "html": report.to_html(),
                "sarif": report.to_sarif(),
            },
        })
    except Exception as exc:  # noqa: BLE001 - cualquier fallo se reporta a la UI
        q.put({"type": "error", "msg": f"{type(exc).__name__}: {exc}"})
    finally:
        q.put({"type": "done"})


class _Handler(BaseHTTPRequestHandler):
    server_version = "PromptReaper"

    def log_message(self, *_):  # silencia el log por request
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            return self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        if path == "/api/info":
            cats = {c: CATALOG[c].title_es for c in sorted(CATALOG) if CATALOG[c].blackbox_testable}
            payloads = load_payloads(["es", "en"])
            info = {"payloads": len(payloads),
                    "es": sum(1 for p in payloads if p.lang == "es"),
                    "en": sum(1 for p in payloads if p.lang == "en"),
                    "categories": cats}
            return self._send(200, json.dumps(info, ensure_ascii=False))
        if path.startswith("/api/scan/") and path.endswith("/stream"):
            job_id = path.split("/")[3]
            return self._stream(job_id)
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                form = json.loads(raw)
            except ValueError:
                return self._send(400, json.dumps({"error": "JSON inválido"}))
            job_id = uuid.uuid4().hex
            q: queue.Queue = queue.Queue()
            _JOBS[job_id] = q
            threading.Thread(target=_run_scan, args=(form, q), daemon=True).start()
            return self._send(200, json.dumps({"job_id": job_id}))
        return self._send(404, json.dumps({"error": "not found"}))

    def _stream(self, job_id: str):
        q = _JOBS.get(job_id)
        if q is None:
            return self._send(404, json.dumps({"error": "job desconocido"}))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                msg = q.get()
                self.wfile.write(f"data: {json.dumps(msg, ensure_ascii=False)}\n\n".encode("utf-8"))
                self.wfile.flush()
                if msg.get("type") == "done":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            _JOBS.pop(job_id, None)


def serve(host: str = "127.0.0.1", port: int = 8765, prefer=None, no_llm: bool = False) -> None:
    global _PREFER, _NO_LLM
    _PREFER, _NO_LLM = prefer, no_llm
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"
    print(f"\nPanel PromptReaper en {url}")
    print("Escuchando solo en local. Ctrl+C para parar.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nPanel detenido.")
    finally:
        httpd.server_close()


INDEX_HTML = r"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PromptReaper — Panel</title>
<style>
 :root{color-scheme:dark;--bg:#0b0f14;--pan:#111827;--bd:#1f2937;--fg:#e5e7eb;--mut:#9ca3af;--acc:#93c5fd;--amber:#fbbf24;}
 *{box-sizing:border-box;}
 body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;}
 header{padding:1rem 1.5rem;border-bottom:1px solid var(--bd);display:flex;align-items:baseline;gap:1rem;flex-wrap:wrap;}
 h1{margin:0;font-size:1.3rem;} .tag{color:var(--mut);font-size:.85rem;}
 .wrap{max-width:1100px;margin:auto;padding:1.5rem;display:grid;grid-template-columns:380px 1fr;gap:1.5rem;}
 @media(max-width:860px){.wrap{grid-template-columns:1fr;}}
 .card{background:var(--pan);border:1px solid var(--bd);border-radius:12px;padding:1rem 1.1rem;}
 label{display:block;font-size:.8rem;color:var(--mut);margin:.6rem 0 .2rem;}
 input,select,textarea{width:100%;background:#0b0f14;border:1px solid var(--bd);color:var(--fg);border-radius:8px;padding:.5rem;font:inherit;font-size:.9rem;}
 textarea{resize:vertical;min-height:2.4rem;font-family:ui-monospace,monospace;}
 .row{display:flex;gap:.6rem;} .row>*{flex:1;}
 .chk{display:flex;align-items:center;gap:.4rem;margin:.5rem 0;} .chk input{width:auto;}
 button{cursor:pointer;background:#2563eb;color:#fff;border:0;border-radius:8px;padding:.65rem 1rem;font-weight:700;font-size:.95rem;margin-top:.8rem;width:100%;}
 button:disabled{opacity:.5;cursor:not-allowed;}
 .danger{background:#7f1d1d;border:1px solid #b91c1c;border-radius:8px;padding:.5rem .7rem;font-size:.8rem;color:#fecaca;margin-bottom:.6rem;}
 .log{background:#0b0f14;border:1px solid var(--bd);border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace;font-size:.78rem;max-height:160px;overflow:auto;white-space:pre-wrap;color:#cbd5e1;}
 .grade{display:inline-block;font-size:2.4rem;font-weight:800;border:3px solid;border-radius:12px;padding:.1rem 1rem;}
 .stat{color:var(--mut);font-size:.9rem;margin:.5rem 0;}
 .pill{color:#fff;font-size:.7rem;font-weight:700;padding:.1rem .5rem;border-radius:999px;}
 .find{background:#0b0f14;border:1px solid var(--bd);border-radius:10px;padding:.7rem .9rem;margin:.6rem 0;}
 .fh{display:flex;flex-wrap:wrap;gap:.45rem;align-items:center;}
 .ptitle{font-weight:700;} .meta{color:var(--mut);font-size:.78rem;margin-left:auto;}
 details{margin-top:.4rem;} summary{cursor:pointer;color:var(--acc);font-size:.82rem;}
 pre{white-space:pre-wrap;word-break:break-word;background:#05080b;border:1px solid var(--bd);border-radius:6px;padding:.5rem;font-size:.76rem;max-height:300px;overflow:auto;}
 .barrow{display:flex;align-items:center;gap:.5rem;margin:.3rem 0;} .blabel{width:2rem;font-weight:700;}
 .btrack{flex:1;background:var(--bd);border-radius:999px;height:12px;overflow:hidden;} .bfill{display:block;height:100%;}
 .bval{width:7rem;text-align:right;font-size:.8rem;color:#cbd5e1;}
 .dl{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.8rem;} .dl button{width:auto;flex:none;margin:0;background:#374151;padding:.4rem .7rem;font-size:.8rem;}
 code{color:var(--amber);} .muted{color:var(--mut);font-size:.85rem;} a{color:var(--acc);}
</style></head><body>
<header><h1>PromptReaper 🌾💀</h1><span class="tag">Panel local · OWASP LLM Top 10 · uso ético y autorizado</span></header>
<div class="wrap">
 <div class="card">
   <div class="danger">⚖️ Solo contra sistemas que te pertenezcan o labs consentidos. Marca la autorización: es un control técnico, no un aviso.</div>
   <label>Proyecto</label><input id="project" value="mi-bot">
   <label>Nota de autorización (obligatoria)</label><input id="note" placeholder="Bot propio de ejemplo.com">
   <div class="row"><div><label>Tipo</label><select id="kind"><option value="http">http</option><option value="callable">callable</option></select></div>
     <div><label>Nombre objetivo</label><input id="tname" value="widget"></div></div>
   <div id="http-fields">
     <label>URL del chatbot</label><input id="url" placeholder="https://ejemplo.com/api/chat">
     <div class="row"><div><label>Método</label><input id="method" value="POST"></div>
       <div><label>response_path (dot)</label><input id="rpath" placeholder="reply"></div></div>
     <label>body_template (usa {PROMPT})</label><textarea id="body">{"message": "{PROMPT}"}</textarea>
     <label>headers (JSON, opcional)</label><textarea id="headers" placeholder='{"Authorization": "Bearer ..."}'></textarea>
   </div>
   <div id="call-fields" style="display:none">
     <label>callable (modulo:funcion)</label><input id="callable" placeholder="labs.vulnerable_bot:respond">
   </div>
   <label>canarios conocidos (uno por línea, solo labs propios)</label><textarea id="canaries" placeholder="SECRET_..."></textarea>
   <div class="row"><div><label>Idiomas</label><select id="langs"><option value="es,en">es + en</option><option value="es">es</option><option value="en">en</option></select></div>
     <div><label>max_turns</label><input id="turns" type="number" value="3" min="1"></div>
     <div><label>jobs</label><input id="jobs" type="number" value="4" min="1"></div></div>
   <div class="row"><div><label>only-owasp</label><input id="owasp" placeholder="LLM01,LLM07"></div>
     <div><label>min-severity</label><select id="sev"><option value="">(todas)</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></div></div>
   <div class="chk"><input type="checkbox" id="usellm"><label for="usellm" style="margin:0">Usar LLM atacante/juez (si hay clave)</label></div>
   <div class="chk"><input type="checkbox" id="auth"><label for="auth" style="margin:0">Confirmo que tengo autorización sobre este objetivo</label></div>
   <button id="go">Escanear</button>
   <div class="muted" id="cat" style="margin-top:.6rem"></div>
 </div>
 <div class="card">
   <div id="empty" class="muted">Configura el objetivo y pulsa <b>Escanear</b>. El progreso y los hallazgos aparecerán aquí.</div>
   <div id="prog" style="display:none"><label>Progreso</label><div class="log" id="log"></div></div>
   <div id="results" style="display:none"></div>
 </div>
</div>
<script>
const $=id=>document.getElementById(id);
const SEVC={critical:'#dc2626',high:'#ea580c',medium:'#ca8a04',low:'#65a30d',info:'#6b7280'};
const STC={CONFIRMED:'#dc2626',PLAUSIBLE:'#ca8a04',REFUTED:'#16a34a',ERROR:'#6b7280'};
const GC={A:'#16a34a',B:'#65a30d',C:'#ca8a04',D:'#ea580c',F:'#dc2626'};
const SL={critical:'CRÍTICA',high:'ALTA',medium:'MEDIA',low:'BAJA',info:'INFO'};
$('kind').onchange=e=>{const h=e.target.value==='http';$('http-fields').style.display=h?'':'none';$('call-fields').style.display=h?'none':'';};
fetch('/api/info').then(r=>r.json()).then(d=>{$('cat').innerHTML=`Catálogo: <b>${d.payloads}</b> payloads (${d.es} es / ${d.en} en). Categorías: ${Object.keys(d.categories).join(', ')}`;}).catch(()=>{});
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function dl(name,content,type){const b=new Blob([content],{type});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;a.click();}
$('go').onclick=()=>{
  const form={project:$('project').value,authorization_note:$('note').value,authorized:$('auth').checked,
    kind:$('kind').value,target_name:$('tname').value,url:$('url').value,method:$('method').value,
    response_path:$('rpath').value,body_template:$('body').value,headers:$('headers').value,
    callable:$('callable').value,known_canaries:$('canaries').value,
    langs:$('langs').value.split(','),max_turns:+$('turns').value,jobs:+$('jobs').value,
    only_owasp:$('owasp').value,min_severity:$('sev').value,use_llm:$('usellm').checked};
  $('empty').style.display='none';$('prog').style.display='';$('results').style.display='none';$('log').textContent='';$('go').disabled=true;
  fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(form)})
   .then(r=>r.json()).then(({job_id})=>{
     const ev=new EventSource('/api/scan/'+job_id+'/stream');
     ev.onmessage=e=>{const m=JSON.parse(e.data);
       if(m.type==='progress'){$('log').textContent+=m.msg+'\n';$('log').scrollTop=1e9;}
       else if(m.type==='error'){$('log').textContent+='\n[ERROR] '+m.msg;$('go').disabled=false;ev.close();}
       else if(m.type==='result'){render(m);}
       else if(m.type==='done'){$('go').disabled=false;ev.close();}};
     ev.onerror=()=>{$('go').disabled=false;ev.close();};
   }).catch(err=>{$('log').textContent+='\n[ERROR] '+err;$('go').disabled=false;});
};
function bars(findings){
  const es=findings.filter(f=>f.lang==='es'),en=findings.filter(f=>f.lang==='en');
  if(!es.length||!en.length)return '';
  const hit=f=>f.status==='CONFIRMED'||f.status==='PLAUSIBLE';
  const er=es.filter(hit).length/es.length,nr=en.filter(hit).length/en.length;
  const bar=(l,h,t,r,c)=>`<div class="barrow"><span class="blabel">${l}</span><span class="btrack"><span class="bfill" style="width:${(r*100).toFixed(0)}%;background:${c}"></span></span><span class="bval">${h}/${t} (${(r*100).toFixed(0)}%)</span></div>`;
  let o='<h3>Español vs Inglés</h3>'+bar('ES',es.filter(hit).length,es.length,er,'#f59e0b')+bar('EN',en.filter(hit).length,en.length,nr,'#3b82f6');
  if(er>nr)o+='<div class="muted" style="color:#fbbf24">Los ataques en español penetraron más que en inglés.</div>';
  return o;
}
function render(m){
  const r=m.report,s=r.summary;const hits=r.findings.filter(f=>f.status==='CONFIRMED'||f.status==='PLAUSIBLE');
  hits.sort((a,b)=>(b.status==='CONFIRMED')-(a.status==='CONFIRMED'));
  let h=`<div class="grade" style="color:${GC[m.grade]};border-color:${GC[m.grade]}">${m.grade} · ${m.points}/100</div>`;
  h+=`<div class="stat">Pruebas: <b>${s.total_probes}</b> · con éxito: <b>${s.hits}</b> (confirmados: <b>${s.confirmed}</b>) · peor severidad: <b>${SL[s.worst_severity]||s.worst_severity}</b> · categorías: ${s.categories_hit.join(', ')||'—'}</div>`;
  h+=bars(r.findings);
  h+=`<h3>Hallazgos (${hits.length})</h3>`;
  if(!hits.length)h+='<div class="muted">El bot resistió todas las pruebas. 👏</div>';
  for(const f of hits){
    h+=`<div class="find"><div class="fh">
      <span class="pill" style="background:${SEVC[f.severity]}">${SL[f.severity]||f.severity}</span>
      <span class="pill" style="background:${STC[f.status]}">${f.status}</span>
      <span class="ptitle">${esc(f.owasp)} · ${esc(f.goal)}</span>
      <span class="meta">${f.lang} · ${esc(f.technique)} · ${f.turns_used} turno/s · conf ${(f.confidence*100).toFixed(0)}% · ${f.method}</span></div>
      <div style="margin:.4rem 0">${esc(f.reason)}</div>
      ${f.evidence?`<div class="muted">Evidencia: <code>${esc(f.evidence.slice(0,200))}</code></div>`:''}
      <details><summary>Ver transcripción (<code>${esc(f.payload_id)}</code>)</summary><pre>${esc(f.transcript||f.bot_response||'')}</pre></details></div>`;
  }
  const d=m.downloads,base=(r.project+'_'+r.target).replace(/[^a-z0-9._-]/gi,'_').toLowerCase();
  h+=`<div class="dl">
    <button onclick='dl("${base}.html",RP.html,"text/html")'>⬇ HTML</button>
    <button onclick='dl("${base}.json",RP.json,"application/json")'>⬇ JSON</button>
    <button onclick='dl("${base}.md",RP.md,"text/markdown")'>⬇ Markdown</button>
    <button onclick='dl("${base}.sarif",RP.sarif,"application/json")'>⬇ SARIF</button></div>`;
  window.RP=d;
  $('results').innerHTML=h;$('results').style.display='';
}
</script></body></html>"""

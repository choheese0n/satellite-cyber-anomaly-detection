"""
Step 5 — 보안관제 대시보드 (FastAPI)
------------------------------------
지금까지 만든 탐지 엔진(분류기 + 위협 점수)을 웹 화면으로 띄웁니다.
브라우저가 1초마다 서버에 "telemetry 한 건 더 줘"를 요청하면,
서버가 새 샘플을 만들어 위협 점수를 매겨 돌려주고, 화면이 실시간으로 갱신됩니다.

구성:
    GET  /            → 대시보드 HTML
    GET  /api/tick    → telemetry 1건 생성 + 점수화해서 JSON 반환
    GET  /api/stats   → 누적 통계

실행:
    python src\\05_dashboard.py
    → 브라우저에서 http://127.0.0.1:8000 접속
    (끄기: 터미널에서 Ctrl+C)
"""

from collections import deque
from datetime import datetime
import numpy as np
import pandas as pd
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from sklearn.ensemble import RandomForestClassifier
import uvicorn

rng = np.random.default_rng(7)

FEATURES = [
    "battery_voltage", "command_rate", "signal_strength",
    "temperature", "uplink_latency_ms", "packet_error_rate",
]
SEVERITY = {
    "normal": 0.0, "spoofing": 0.7, "command_injection": 1.0,
    "telemetry_manipulation": 0.9, "sensor_anomaly": 0.5,
}
COUNTS = {
    "normal": 1200, "spoofing": 180, "command_injection": 180,
    "telemetry_manipulation": 180, "sensor_anomaly": 180,
}
ATTACK_PROB = 0.15


def make_one(label: str) -> dict:
    g = rng.normal
    table = {
        "normal":  dict(battery_voltage=g(7.4,.05), command_rate=g(5.0,.8),
                        signal_strength=g(95,1.5), temperature=g(30,1.0),
                        uplink_latency_ms=g(40,5), packet_error_rate=g(.5,.2)),
        "spoofing": dict(battery_voltage=g(7.4,.06), command_rate=g(5.5,1.0),
                         signal_strength=g(70,8), temperature=g(30,1.2),
                         uplink_latency_ms=g(120,25), packet_error_rate=g(6.0,1.5)),
        "command_injection": dict(battery_voltage=g(7.4,.06), command_rate=g(30,5),
                                  signal_strength=g(94,2.0), temperature=g(31,1.5),
                                  uplink_latency_ms=g(45,6), packet_error_rate=g(1.0,.4)),
        "telemetry_manipulation": dict(battery_voltage=g(6.6,.15), command_rate=g(5.0,.9),
                                       signal_strength=g(95,1.6), temperature=g(40,1.5),
                                       uplink_latency_ms=g(42,5), packet_error_rate=g(.6,.2)),
        "sensor_anomaly": dict(battery_voltage=g(7.4,.07), command_rate=g(5.0,.9),
                               signal_strength=g(94,2.0), temperature=g(30,12.0),
                               uplink_latency_ms=g(43,6), packet_error_rate=g(.7,.3)),
    }
    row = table[label]
    row["packet_error_rate"] = max(0.0, row["packet_error_rate"])
    row["label"] = label
    return row


def make_batch(label: str, n: int) -> pd.DataFrame:
    return pd.DataFrame([make_one(label) for _ in range(n)])


def threat_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


# ---- 서버 시작 시 1회: 모델 학습 ----
print("[준비] 분류기를 학습합니다...")
_train = pd.concat([make_batch(l, n) for l, n in COUNTS.items()], ignore_index=True)
MODEL = RandomForestClassifier(n_estimators=300, random_state=1, n_jobs=-1)
MODEL.fit(_train[FEATURES], _train["label"])
CLASSES = list(MODEL.classes_)
WEIGHTS = np.array([SEVERITY[c] for c in CLASSES])
print("[준비] 완료. http://127.0.0.1:8000 에서 접속하세요.")

# ---- 누적 상태 ----
STATE = {"total": 0, "alerts": 0, "high": 0, "tick": 0}
RECENT = deque(maxlen=50)

app = FastAPI(title="Satellite Security Monitor")


@app.get("/api/tick")
def tick():
    lbl = "normal" if rng.random() > ATTACK_PROB else rng.choice(
        ["spoofing", "command_injection", "telemetry_manipulation", "sensor_anomaly"]
    )
    row = make_one(lbl)
    x = pd.DataFrame([row])[FEATURES]
    proba = MODEL.predict_proba(x)[0]
    score = round(float(proba @ WEIGHTS) * 100, 1)
    pred = str(MODEL.predict(x)[0])
    level = threat_level(score)

    STATE["tick"] += 1
    STATE["total"] += 1
    if level != "LOW":
        STATE["alerts"] += 1
    if level in ("HIGH", "CRITICAL"):
        STATE["high"] += 1

    item = {
        "t": STATE["tick"],
        "time": datetime.now().strftime("%H:%M:%S"),
        "score": score,
        "level": level,
        "pred_type": pred,
    }
    RECENT.appendleft(item)
    return JSONResponse(item)


@app.get("/api/stats")
def stats():
    return JSONResponse({**STATE, "recent": list(RECENT)[:12]})


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PAGE


HTML_PAGE = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Satellite Security Monitor</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root { --bg:#0b1020; --card:#141b33; --line:#263258; --txt:#e6ecff; --muted:#8ea0c8; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
         font-family:"Segoe UI",system-ui,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; }
  .dot { width:10px; height:10px; border-radius:50%; background:#2ec27e;
         box-shadow:0 0 8px #2ec27e; animation:pulse 1.4s infinite; }
  @keyframes pulse { 50% { opacity:.3; } }
  .wrap { padding:20px 24px; max-width:1100px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:18px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .card .k { color:var(--muted); font-size:12px; }
  .card .v { font-size:28px; font-weight:700; margin-top:6px; }
  .panel { background:var(--card); border:1px solid var(--line);
           border-radius:12px; padding:16px; margin-bottom:18px; }
  .panel h2 { font-size:14px; margin:0 0 12px; color:var(--muted); font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:600; }
  .badge { padding:2px 8px; border-radius:20px; font-size:11px; font-weight:700; }
  .LOW{background:#1b2a4a;color:#8ea0c8;} .MEDIUM{background:#4a3f12;color:#ffd84d;}
  .HIGH{background:#5a3210;color:#ff9f45;} .CRITICAL{background:#5a1420;color:#ff5a6e;}
  @media(max-width:720px){ .cards{grid-template-columns:repeat(2,1fr);} }
</style>
</head>
<body>
<header>
  <span class="dot"></span>
  <h1>🛰️ Satellite Security Monitor</h1>
  <span style="color:var(--muted);font-size:13px;">실시간 위성 Telemetry 위협 관제</span>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="k">수신 Telemetry</div><div class="v" id="c-total">0</div></div>
    <div class="card"><div class="k">총 경보</div><div class="v" id="c-alert">0</div></div>
    <div class="card"><div class="k">HIGH+CRITICAL</div><div class="v" id="c-high" style="color:#ff5a6e;">0</div></div>
    <div class="card"><div class="k">현재 위협 점수</div><div class="v" id="c-score">0</div></div>
  </div>
  <div class="panel">
    <h2>위협 점수 타임라인 (실시간)</h2>
    <canvas id="chart" height="90"></canvas>
  </div>
  <div class="panel">
    <h2>최근 경보</h2>
    <table>
      <thead><tr><th>#</th><th>시각</th><th>점수</th><th>등급</th><th>예측 유형</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>
<script>
const ctx = document.getElementById('chart');
const chart = new Chart(ctx, {
  type:'line',
  data:{ labels:[], datasets:[{ label:'Threat Score', data:[],
    borderColor:'#5aa9ff', backgroundColor:'rgba(90,169,255,.15)',
    fill:true, tension:.25, pointRadius:0 }]},
  options:{ animation:false, scales:{
      y:{min:0,max:100,ticks:{color:'#8ea0c8'},grid:{color:'#263258'}},
      x:{ticks:{color:'#8ea0c8',maxTicksLimit:10},grid:{display:false}} },
    plugins:{legend:{display:false}} }
});

async function loop(){
  try {
    const tick = await (await fetch('/api/tick')).json();
    chart.data.labels.push(tick.t);
    chart.data.datasets[0].data.push(tick.score);
    if (chart.data.labels.length > 60){ chart.data.labels.shift(); chart.data.datasets[0].data.shift(); }
    chart.update();

    const s = await (await fetch('/api/stats')).json();
    document.getElementById('c-total').textContent = s.total;
    document.getElementById('c-alert').textContent = s.alerts;
    document.getElementById('c-high').textContent = s.high;
    const sc = document.getElementById('c-score');
    sc.textContent = tick.score;
    sc.style.color = tick.level==='CRITICAL'?'#ff5a6e':tick.level==='HIGH'?'#ff9f45':
                     tick.level==='MEDIUM'?'#ffd84d':'#e6ecff';

    const rows = s.recent.filter(r=>r.level!=='LOW').map(r=>
      `<tr><td>${r.t}</td><td>${r.time}</td><td>${r.score}</td>
       <td><span class="badge ${r.level}">${r.level}</span></td><td>${r.pred_type}</td></tr>`).join('');
    document.getElementById('rows').innerHTML = rows || '<tr><td colspan=5 style="color:#8ea0c8">아직 경보 없음</td></tr>';
  } catch(e){ console.error(e); }
}
setInterval(loop, 1000);
loop();
</script>
</body>
</html>"""


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

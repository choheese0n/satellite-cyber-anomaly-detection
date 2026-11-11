"""
Step 4 — 실시간 스트림 탐지 + 경보
-----------------------------------
Step 3는 스트림 '전체'를 한 번에 점수화했습니다.
Step 4는 telemetry가 '한 건씩' 들어올 때마다 즉시 판정하고 경보를 띄웁니다.
(실제 지상국 보안관제가 하는 일의 축소판)

동작:
    1) 분류기를 미리 학습해 둠 (관제 시작 전 준비)
    2) telemetry를 1건씩 수신하는 것처럼 루프를 돌며:
        - 위협 점수(0~100) 즉시 계산
        - 최근 N건 이동평균으로 '지속 위협'도 감시
        - MEDIUM 이상이면 콘솔에 경보 출력
    3) 종료 시 경보 로그를 data\realtime_alert_log.csv 로 저장

실행:
    python src\\04_realtime_monitor.py
"""

from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
DATA_DIR.mkdir(exist_ok=True)

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

# ---- 실시간 흉내 설정 ----
STREAM_LEN = 150        # 수신할 telemetry 건수
TICK_SEC = 0.05         # 한 건 간격(초). 0 으로 하면 즉시 끝남
WINDOW = 10             # 이동평균 창 크기
ATTACK_PROB = 0.15      # 들어오는 데이터 중 공격 비율


def make_one(label: str) -> dict:
    """유형별 특성을 가진 telemetry 1건 생성."""
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


def main() -> None:
    print("[준비] 분류기를 학습합니다 (관제 시작 전)...")
    train = pd.concat([make_batch(l, n) for l, n in COUNTS.items()], ignore_index=True)
    clf = RandomForestClassifier(n_estimators=300, random_state=1, n_jobs=-1)
    clf.fit(train[FEATURES], train["label"])
    classes = list(clf.classes_)
    weights = np.array([SEVERITY[c] for c in classes])

    print(f"[시작] 실시간 telemetry 감시 시작 — {STREAM_LEN}건 수신 예정\n")
    print(f"{'time':8s} {'#':>4s} {'score':>6s} {'level':9s} {'pred_type':22s} avg{WINDOW}")
    print("-" * 70)

    clock = datetime.now().replace(microsecond=0)
    window = deque(maxlen=WINDOW)
    log = []
    n_alert = 0

    for i in range(STREAM_LEN):
        # 1건 수신
        lbl = "normal" if rng.random() > ATTACK_PROB else rng.choice(
            ["spoofing", "command_injection", "telemetry_manipulation", "sensor_anomaly"]
        )
        row = make_one(lbl)
        x = pd.DataFrame([row])[FEATURES]

        proba = clf.predict_proba(x)[0]
        score = float(proba @ weights) * 100
        pred = str(clf.predict(x)[0])
        level = threat_level(score)
        window.append(score)
        avg = sum(window) / len(window)

        ts = (clock + timedelta(seconds=i)).strftime("%H:%M:%S")

        if level != "LOW":
            n_alert += 1
            flag = "!!" if level in ("HIGH", "CRITICAL") else " ."
            print(f"{ts:8s} {i:>4d} {score:6.1f} {level:9s} {pred:22s} {avg:5.1f} {flag}")
            log.append({"time": ts, "idx": i, "threat_score": round(score, 1),
                        "level": level, "pred_type": pred, "true_label": lbl,
                        "moving_avg": round(avg, 1)})

        # 지속 위협 경고 (이동평균이 높게 유지되면)
        if len(window) == WINDOW and avg >= 40:
            print(f"         └─ ⚠ 지속 위협 감지: 최근 {WINDOW}건 평균 {avg:.1f}")

        if TICK_SEC:
            time.sleep(TICK_SEC)

    print("-" * 70)
    print(f"[종료] 총 {STREAM_LEN}건 중 경보 {n_alert}건")
    if log:
        log_df = pd.DataFrame(log)
        log_path = DATA_DIR / "realtime_alert_log.csv"
        log_df.to_csv(log_path, index=False)
        by_level = log_df["level"].value_counts()
        for lv in ["MEDIUM", "HIGH", "CRITICAL"]:
            print(f"    {lv:9s}: {int(by_level.get(lv, 0))}건")
        print(f"    경보 로그 저장 → {log_path}")
    else:
        print("    경보 없음 (조용한 구간이었습니다)")


if __name__ == "__main__":
    main()

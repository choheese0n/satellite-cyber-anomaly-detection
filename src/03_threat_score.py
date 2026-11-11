"""
Step 3 — Threat Score (위협 점수) 설계
--------------------------------------
Step 2의 분류기는 '어떤 공격인지'만 말했습니다.
Step 3는 그 결과를 '얼마나 위험한가'를 나타내는 0~100 위협 점수로 바꿉니다.

아이디어 (보안관제 SOC의 리스크 스코어링):
    threat_score = 100 * Σ ( P(공격유형) × 유형별_위험가중치 )

    - P(공격유형): RandomForest가 내놓는 각 공격일 확률 (predict_proba)
    - 위험가중치 : 공격마다 위험도가 다름 (명령 주입 > 상태조작 > 스푸핑 > 센서이상)

그리고 점수대에 따라 경보 등급을 매깁니다:
    0~20   LOW       정상
    20~50  MEDIUM    주의
    50~80  HIGH      경고
    80~100 CRITICAL  심각

실행:
    python src\\03_threat_score.py
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier

try:  # 콘솔/리다이렉트 한글 출력 안전장치 (cp949 → utf-8)
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
OUT_DIR = BASE / "outputs"
DATA_DIR.mkdir(exist_ok=True)
OUT_DIR.mkdir(exist_ok=True)

rng = np.random.default_rng(7)

FEATURES = [
    "battery_voltage", "command_rate", "signal_strength",
    "temperature", "uplink_latency_ms", "packet_error_rate",
]

# 공격 유형별 '위험 가중치' (0~1). 클수록 치명적.
SEVERITY = {
    "normal": 0.0,
    "spoofing": 0.7,
    "command_injection": 1.0,
    "telemetry_manipulation": 0.9,
    "sensor_anomaly": 0.5,
}

COUNTS = {
    "normal": 1200,
    "spoofing": 180,
    "command_injection": 180,
    "telemetry_manipulation": 180,
    "sensor_anomaly": 180,
}


def make_class(label: str, n: int) -> pd.DataFrame:
    """Step 2와 동일한 유형별 특성으로 샘플 생성."""
    if label == "normal":
        d = {
            "battery_voltage": rng.normal(7.4, 0.05, n),
            "command_rate": rng.normal(5.0, 0.8, n),
            "signal_strength": rng.normal(95, 1.5, n),
            "temperature": rng.normal(30, 1.0, n),
            "uplink_latency_ms": rng.normal(40, 5, n),
            "packet_error_rate": rng.normal(0.5, 0.2, n),
        }
    elif label == "spoofing":
        d = {
            "battery_voltage": rng.normal(7.4, 0.06, n),
            "command_rate": rng.normal(5.5, 1.0, n),
            "signal_strength": rng.normal(70, 8, n),
            "temperature": rng.normal(30, 1.2, n),
            "uplink_latency_ms": rng.normal(120, 25, n),
            "packet_error_rate": rng.normal(6.0, 1.5, n),
        }
    elif label == "command_injection":
        d = {
            "battery_voltage": rng.normal(7.4, 0.06, n),
            "command_rate": rng.normal(30.0, 5.0, n),
            "signal_strength": rng.normal(94, 2.0, n),
            "temperature": rng.normal(31, 1.5, n),
            "uplink_latency_ms": rng.normal(45, 6, n),
            "packet_error_rate": rng.normal(1.0, 0.4, n),
        }
    elif label == "telemetry_manipulation":
        d = {
            "battery_voltage": rng.normal(6.6, 0.15, n),
            "command_rate": rng.normal(5.0, 0.9, n),
            "signal_strength": rng.normal(95, 1.6, n),
            "temperature": rng.normal(40, 1.5, n),
            "uplink_latency_ms": rng.normal(42, 5, n),
            "packet_error_rate": rng.normal(0.6, 0.2, n),
        }
    elif label == "sensor_anomaly":
        d = {
            "battery_voltage": rng.normal(7.4, 0.07, n),
            "command_rate": rng.normal(5.0, 0.9, n),
            "signal_strength": rng.normal(94, 2.0, n),
            "temperature": rng.normal(30, 12.0, n),
            "uplink_latency_ms": rng.normal(43, 6, n),
            "packet_error_rate": rng.normal(0.7, 0.3, n),
        }
    else:
        raise ValueError(label)

    out = pd.DataFrame(d)
    out["packet_error_rate"] = out["packet_error_rate"].clip(lower=0)
    out["label"] = label
    return out


def threat_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


LEVEL_COLOR = {
    "LOW": "tab:blue",
    "MEDIUM": "gold",
    "HIGH": "darkorange",
    "CRITICAL": "red",
}


def main() -> None:
    print("[1/5] 학습용 라벨 데이터를 생성합니다...")
    train_df = pd.concat([make_class(l, n) for l, n in COUNTS.items()], ignore_index=True)

    print("[2/5] RandomForest 분류기를 학습합니다...")
    clf = RandomForestClassifier(n_estimators=300, random_state=1, n_jobs=-1)
    clf.fit(train_df[FEATURES], train_df["label"])
    classes = list(clf.classes_)  # predict_proba 열 순서

    print("[3/5] 실시간처럼 흘러오는 telemetry 스트림을 만듭니다...")
    # 대부분 정상 + 가끔 공격이 섞인 시간 순서 스트림
    stream_parts = []
    for i in range(300):
        r = rng.random()
        if r < 0.85:
            lbl = "normal"
        else:
            lbl = rng.choice(["spoofing", "command_injection",
                              "telemetry_manipulation", "sensor_anomaly"])
        stream_parts.append(make_class(lbl, 1))
    stream = pd.concat(stream_parts, ignore_index=True)
    stream["t"] = range(len(stream))  # 시간 인덱스

    print("[4/5] 위협 점수를 계산합니다...")
    proba = clf.predict_proba(stream[FEATURES])  # (N, n_classes)
    weights = np.array([SEVERITY[c] for c in classes])  # 클래스 순서 맞춤
    stream["threat_score"] = (proba @ weights) * 100     # 0~100
    stream["pred_type"] = clf.predict(stream[FEATURES])
    stream["level"] = stream["threat_score"].apply(threat_level)

    # 경보만 따로 저장 (MEDIUM 이상)
    alerts = stream[stream["threat_score"] >= 20].copy()
    alerts = alerts.sort_values("threat_score", ascending=False)
    alert_cols = ["t", "threat_score", "level", "pred_type", "label"] + FEATURES
    alerts[alert_cols].to_csv(DATA_DIR / "threat_alerts.csv", index=False)

    counts = stream["level"].value_counts()
    print("    경보 등급 분포:")
    for lv in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        print(f"        {lv:9s}: {int(counts.get(lv, 0))}개")
    print(f"    MEDIUM 이상 경보 {len(alerts)}건 → data\\threat_alerts.csv")

    print("[5/5] 위협 점수 타임라인을 그립니다...")
    fig, ax = plt.subplots(figsize=(12, 5.5))
    for lv, color in LEVEL_COLOR.items():
        sub = stream[stream["level"] == lv]
        ax.scatter(sub["t"], sub["threat_score"], s=18, color=color, label=lv)
    for y, c in [(20, "gold"), (50, "darkorange"), (80, "red")]:
        ax.axhline(y, color=c, ls="--", lw=0.8, alpha=0.7)
    ax.set_xlabel("Time (telemetry sample #)")
    ax.set_ylabel("Threat Score (0-100)")
    ax.set_ylim(0, 105)
    ax.set_title("Satellite Security — Real-time Threat Score Timeline")
    ax.legend(title="Alert level", loc="upper right")
    fig.tight_layout()
    out_path = OUT_DIR / "threat_timeline.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")

    print(f"\n완료! 저장 → {out_path}")
    print("점선 위로 튀는 빨강/주황 점이 '지금 위험한 순간'입니다.")
    plt.show()


if __name__ == "__main__":
    main()

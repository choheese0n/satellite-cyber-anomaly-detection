"""
Step 1 — 위성 Telemetry 사이버 공격 이상탐지
---------------------------------------------
정상 telemetry에 공격성 이상 샘플을 섞고, Isolation Forest로 이상을 탐지합니다.
(비지도 학습: '정상이 어떤 모습인지'만 보고 벗어난 것을 잡아냄)

실행:
    python src\\01_detect_anomalies.py
"""

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
OUT_DIR = BASE / "outputs"
DATA_DIR.mkdir(exist_ok=True)
OUT_DIR.mkdir(exist_ok=True)

rng = np.random.default_rng(7)
N_NORMAL = 1000
N_ATTACK = 50

FEATURES = ["battery_voltage", "command_rate", "signal_strength", "temperature"]

def main() -> None:
    print("[1/4] 정상 telemetry + 공격 샘플을 생성합니다...")
    # 정상: 각 값이 일정 범위에서 안정적
    normal = pd.DataFrame({
        "battery_voltage": rng.normal(7.4, 0.05, N_NORMAL),
        "command_rate":    rng.normal(5.0, 0.8, N_NORMAL),   # 분당 명령 수
        "signal_strength": rng.normal(95, 1.5, N_NORMAL),
        "temperature":     rng.normal(30, 1.0, N_NORMAL),
        "label": "normal",
    })
    # 공격: 비정상적으로 튀는 값 (전압 급변 / 명령 폭주 / 신호 조작)
    attack = pd.DataFrame({
        "battery_voltage": rng.normal(7.4, 0.5, N_ATTACK),
        "command_rate":    rng.normal(25.0, 5.0, N_ATTACK),  # 명령 주입 폭주
        "signal_strength": rng.normal(60, 10, N_ATTACK),     # 신호 조작
        "temperature":     rng.normal(45, 5.0, N_ATTACK),
        "label": "attack",
    })

    df = pd.concat([normal, attack], ignore_index=True)
    df = df.sample(frac=1, random_state=1).reset_index(drop=True)  # 섞기
    df.to_csv(DATA_DIR / "telemetry_security.csv", index=False)

    # [2] Isolation Forest 학습 & 예측
    print("[2/4] Isolation Forest로 이상을 탐지합니다...")
    model = IsolationForest(
        n_estimators=200,
        contamination=N_ATTACK / (N_NORMAL + N_ATTACK),  # 예상 이상 비율
        random_state=1,
    )
    df["pred"] = model.fit_predict(df[FEATURES])   # -1=이상, 1=정상
    df["is_anomaly"] = df["pred"] == -1

    # [3] 성능 평가
    print("[3/4] 탐지 성능을 평가합니다...")
    true_attack = df["label"] == "attack"
    detected = df["is_anomaly"]
    caught = int((true_attack & detected).sum())
    missed = int((true_attack & ~detected).sum())
    false_alarm = int((~true_attack & detected).sum())
    print(f"    실제 공격 {int(true_attack.sum())}개 중 탐지 {caught}개 / 놓침 {missed}개")
    print(f"    오탐(정상을 공격으로) {false_alarm}개")

    # [4] 시각화 (명령률 vs 신호세기)
    print("[4/4] 결과 그래프를 그립니다...")
    fig, ax = plt.subplots(figsize=(9, 7))
    ok = df[~df["is_anomaly"]]
    bad = df[df["is_anomaly"]]
    ax.scatter(ok["command_rate"], ok["signal_strength"], s=10, color="tab:blue", label="normal", alpha=0.5)
    ax.scatter(bad["command_rate"], bad["signal_strength"], s=30, color="red",
               marker="x", label="detected anomaly")
    ax.set_xlabel("Command Rate (/min)")
    ax.set_ylabel("Signal Strength")
    ax.set_title("Satellite Telemetry — Cyber Anomaly Detection (Isolation Forest)")
    ax.legend()
    fig.tight_layout()

    out_path = OUT_DIR / "anomaly_detection.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"완료! 그래프 저장 → {out_path}")
    print("빨간 X가 모델이 공격으로 탐지한 지점입니다.")
    plt.show()


if __name__ == "__main__":
    main()

"""
Step 2 — 위성 Telemetry 공격 '유형' 분류 (지도학습)
---------------------------------------------------
Step 1은 정상 vs 이상(비지도)만 구분했습니다.
Step 2는 공격을 '유형별'로 구분합니다 (지도학습 분류):

    normal                  정상
    spoofing                가짜 신호로 속이기 (신호/통신 조작)
    command_injection       비정상 명령 폭주 주입
    telemetry_manipulation  상태값(전압/온도) 조작
    sensor_anomaly          센서값 이상 (온도 센서 요동)

RandomForest 분류기로 학습 → 평가(리포트 + 혼동행렬) → 중요 피처까지 봅니다.

실행:
    python src\\02_classify_attacks.py
"""

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
OUT_DIR = BASE / "outputs"
DATA_DIR.mkdir(exist_ok=True)
OUT_DIR.mkdir(exist_ok=True)

rng = np.random.default_rng(7)

FEATURES = [
    "battery_voltage",    # 배터리 전압
    "command_rate",       # 분당 명령 수
    "signal_strength",    # 신호 세기
    "temperature",        # 온도
    "uplink_latency_ms",  # 업링크 지연(ms)
    "packet_error_rate",  # 패킷 오류율
]

# 클래스별 샘플 수 (정상을 많게, 공격은 유형별로)
COUNTS = {
    "normal": 1200,
    "spoofing": 180,
    "command_injection": 180,
    "telemetry_manipulation": 180,
    "sensor_anomaly": 180,
}


def make_class(label: str, n: int) -> pd.DataFrame:
    """유형별 특성(signature)을 가진 telemetry 샘플 생성."""
    if label == "normal":
        d = {
            "battery_voltage":   rng.normal(7.4, 0.05, n),
            "command_rate":      rng.normal(5.0, 0.8, n),
            "signal_strength":   rng.normal(95, 1.5, n),
            "temperature":       rng.normal(30, 1.0, n),
            "uplink_latency_ms": rng.normal(40, 5, n),
            "packet_error_rate": rng.normal(0.5, 0.2, n),
        }
    elif label == "spoofing":
        # 가짜 신호: 신호세기가 부자연스럽고 패킷오류/지연이 튄다
        d = {
            "battery_voltage":   rng.normal(7.4, 0.06, n),
            "command_rate":      rng.normal(5.5, 1.0, n),
            "signal_strength":   rng.normal(70, 8, n),     # 비정상 신호
            "temperature":       rng.normal(30, 1.2, n),
            "uplink_latency_ms": rng.normal(120, 25, n),   # 지연 증가
            "packet_error_rate": rng.normal(6.0, 1.5, n),  # 오류율 급증
        }
    elif label == "command_injection":
        # 명령 주입: 명령률 폭주
        d = {
            "battery_voltage":   rng.normal(7.4, 0.06, n),
            "command_rate":      rng.normal(30.0, 5.0, n),  # 폭주
            "signal_strength":   rng.normal(94, 2.0, n),
            "temperature":       rng.normal(31, 1.5, n),
            "uplink_latency_ms": rng.normal(45, 6, n),
            "packet_error_rate": rng.normal(1.0, 0.4, n),
        }
    elif label == "telemetry_manipulation":
        # 상태값 조작: 전압/온도가 그럴듯하지만 벗어난 값으로 고정 조작
        d = {
            "battery_voltage":   rng.normal(6.6, 0.15, n),  # 전압 조작
            "command_rate":      rng.normal(5.0, 0.9, n),
            "signal_strength":   rng.normal(95, 1.6, n),
            "temperature":       rng.normal(40, 1.5, n),    # 온도 조작
            "uplink_latency_ms": rng.normal(42, 5, n),
            "packet_error_rate": rng.normal(0.6, 0.2, n),
        }
    elif label == "sensor_anomaly":
        # 센서 이상: 온도 센서가 크게 요동(분산 큼)
        d = {
            "battery_voltage":   rng.normal(7.4, 0.07, n),
            "command_rate":      rng.normal(5.0, 0.9, n),
            "signal_strength":   rng.normal(94, 2.0, n),
            "temperature":       rng.normal(30, 12.0, n),   # 큰 요동
            "uplink_latency_ms": rng.normal(43, 6, n),
            "packet_error_rate": rng.normal(0.7, 0.3, n),
        }
    else:
        raise ValueError(label)

    out = pd.DataFrame(d)
    out["packet_error_rate"] = out["packet_error_rate"].clip(lower=0)
    out["label"] = label
    return out


def main() -> None:
    print("[1/5] 유형별 telemetry 데이터를 생성합니다...")
    df = pd.concat([make_class(lbl, n) for lbl, n in COUNTS.items()], ignore_index=True)
    df = df.sample(frac=1, random_state=1).reset_index(drop=True)
    df.to_csv(DATA_DIR / "telemetry_labeled.csv", index=False)
    print(f"    총 {len(df)}개 샘플, 클래스 {df['label'].nunique()}종")

    print("[2/5] 학습/평가 데이터로 나눕니다 (70/30, stratified)...")
    X = df[FEATURES]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=1, stratify=y
    )

    print("[3/5] RandomForest 분류기를 학습합니다...")
    clf = RandomForestClassifier(
        n_estimators=300, max_depth=None, random_state=1, n_jobs=-1
    )
    clf.fit(X_train, y_train)

    print("[4/5] 성능을 평가합니다...\n")
    y_pred = clf.predict(X_test)
    labels = sorted(y.unique())
    print(classification_report(y_test, y_pred, digits=3))

    # 혼동행렬 그림
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    fig, ax = plt.subplots(figsize=(8, 6.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Attack Type Classification — Confusion Matrix")
    thresh = cm.max() / 2 if cm.max() else 0
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, int(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    cm_path = OUT_DIR / "attack_confusion_matrix.png"
    plt.savefig(cm_path, dpi=150, bbox_inches="tight")

    # 피처 중요도 그림
    print("[5/5] 피처 중요도를 그립니다...")
    importances = pd.Series(clf.feature_importances_, index=FEATURES).sort_values()
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    ax2.barh(importances.index, importances.values, color="tab:green")
    ax2.set_xlabel("Importance")
    ax2.set_title("Which signals matter most for detecting attacks?")
    fig2.tight_layout()
    fi_path = OUT_DIR / "attack_feature_importance.png"
    plt.savefig(fi_path, dpi=150, bbox_inches="tight")

    print(f"\n완료! 저장:\n    혼동행렬 → {cm_path}\n    피처중요도 → {fi_path}")
    print("대각선이 진할수록 각 유형을 정확히 맞춘 것입니다.")
    plt.show()


if __name__ == "__main__":
    main()

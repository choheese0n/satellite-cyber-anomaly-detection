"""
공통 라이브러리 — telemetry 데이터 생성 + 모델 학습/저장/불러오기
----------------------------------------------------------------
Step 2~5가 각자 복붙하던 데이터 생성·모델 로직을 한 곳에 모았습니다.
핵심 추가 기능: 학습한 모델을 joblib로 '저장'해두고 다음엔 '불러쓰기'(빠른 시작).

이 파일은 직접 실행하지 않고, 다른 스크립트가 import 해서 씁니다.
    from telemetry_lib import load_or_train, make_one, threat_level, ...
"""

from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

BASE = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE / "models" / "attack_model.joblib"

FEATURES = [
    "battery_voltage", "command_rate", "signal_strength",
    "temperature", "uplink_latency_ms", "packet_error_rate",
]

# 공격 유형별 위험 가중치 (0~1). 위협 점수 계산에 사용.
SEVERITY = {
    "normal": 0.0, "spoofing": 0.7, "command_injection": 1.0,
    "telemetry_manipulation": 0.9, "sensor_anomaly": 0.5,
}

# 학습 데이터 클래스별 샘플 수
COUNTS = {
    "normal": 1200, "spoofing": 180, "command_injection": 180,
    "telemetry_manipulation": 180, "sensor_anomaly": 180,
}

ATTACK_TYPES = ["spoofing", "command_injection", "telemetry_manipulation", "sensor_anomaly"]


def make_one(label: str, rng: np.random.Generator) -> dict:
    """유형별 특성(signature)을 가진 telemetry 1건 생성."""
    g = rng.normal
    table = {
        "normal":  dict(battery_voltage=g(7.4, .05), command_rate=g(5.0, .8),
                        signal_strength=g(95, 1.5), temperature=g(30, 1.0),
                        uplink_latency_ms=g(40, 5), packet_error_rate=g(.5, .2)),
        "spoofing": dict(battery_voltage=g(7.4, .06), command_rate=g(5.5, 1.0),
                         signal_strength=g(70, 8), temperature=g(30, 1.2),
                         uplink_latency_ms=g(120, 25), packet_error_rate=g(6.0, 1.5)),
        "command_injection": dict(battery_voltage=g(7.4, .06), command_rate=g(30, 5),
                                  signal_strength=g(94, 2.0), temperature=g(31, 1.5),
                                  uplink_latency_ms=g(45, 6), packet_error_rate=g(1.0, .4)),
        "telemetry_manipulation": dict(battery_voltage=g(6.6, .15), command_rate=g(5.0, .9),
                                       signal_strength=g(95, 1.6), temperature=g(40, 1.5),
                                       uplink_latency_ms=g(42, 5), packet_error_rate=g(.6, .2)),
        "sensor_anomaly": dict(battery_voltage=g(7.4, .07), command_rate=g(5.0, .9),
                               signal_strength=g(94, 2.0), temperature=g(30, 12.0),
                               uplink_latency_ms=g(43, 6), packet_error_rate=g(.7, .3)),
    }
    row = table[label]
    row["packet_error_rate"] = max(0.0, row["packet_error_rate"])
    row["label"] = label
    return row


def make_batch(label: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    return pd.DataFrame([make_one(label, rng) for _ in range(n)])


def make_dataset(rng: np.random.Generator) -> pd.DataFrame:
    """학습용 라벨 데이터셋 전체 생성."""
    df = pd.concat([make_batch(l, n, rng) for l, n in COUNTS.items()], ignore_index=True)
    return df.sample(frac=1, random_state=1).reset_index(drop=True)


def threat_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def train_classifier(rng: np.random.Generator | None = None) -> dict:
    """RandomForest 학습 후, 모델+메타데이터 번들(dict) 반환."""
    if rng is None:
        rng = np.random.default_rng(7)
    df = make_dataset(rng)
    clf = RandomForestClassifier(n_estimators=300, random_state=1, n_jobs=-1)
    clf.fit(df[FEATURES], df["label"])
    classes = list(clf.classes_)
    weights = np.array([SEVERITY[c] for c in classes])
    return {"model": clf, "classes": classes, "weights": weights, "features": FEATURES}


def save_model(bundle: dict, path: Path = MODEL_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    return path


def load_or_train(path: Path = MODEL_PATH, verbose: bool = True) -> dict:
    """저장된 모델이 있으면 불러오고(빠름), 없으면 학습 후 저장한다."""
    if path.is_file():
        if verbose:
            print(f"[모델] 저장된 모델을 불러옵니다 → {path.name}")
        return joblib.load(path)
    if verbose:
        print("[모델] 저장된 모델이 없어 새로 학습합니다 (최초 1회)...")
    bundle = train_classifier()
    save_model(bundle, path)
    if verbose:
        print(f"[모델] 학습 완료 & 저장 → {path}")
    return bundle


def threat_score(bundle: dict, X: pd.DataFrame) -> np.ndarray:
    """번들 모델로 0~100 위협 점수 계산."""
    proba = bundle["model"].predict_proba(X[bundle["features"]])
    return (proba @ bundle["weights"]) * 100

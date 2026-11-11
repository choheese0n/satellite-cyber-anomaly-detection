"""
Step 7 — 모델 미리 학습해서 파일로 저장 (joblib)
------------------------------------------------
RandomForest를 학습해 models\\attack_model.joblib 로 저장합니다.
한 번 저장해두면 대시보드(05)와 다른 스크립트가 '불러쓰기'만 해서 즉시 시작됩니다.

실행:
    python src\\07_train_model.py
"""

import numpy as np
from sklearn.model_selection import cross_val_score
from telemetry_lib import train_classifier, save_model, make_dataset, FEATURES, MODEL_PATH


def main() -> None:
    print("[1/3] RandomForest를 학습합니다...")
    bundle = train_classifier()

    print("[2/3] 교차검증으로 성능을 확인합니다 (5-fold)...")
    rng = np.random.default_rng(7)
    df = make_dataset(rng)
    scores = cross_val_score(bundle["model"], df[FEATURES], df["label"], cv=5)
    print(f"    정확도: {scores.mean():.3f} ± {scores.std():.3f}")

    print("[3/3] 모델을 저장합니다...")
    path = save_model(bundle)
    size_kb = path.stat().st_size / 1024
    print(f"완료! 저장 → {path}  ({size_kb:.0f} KB)")
    print("이제 python src\\05_dashboard.py 가 이 모델을 즉시 불러옵니다.")


if __name__ == "__main__":
    main()

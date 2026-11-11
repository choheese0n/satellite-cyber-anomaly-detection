"""
Step 6 (옵션) — 실제 NASA 위성 데이터로 이상탐지
------------------------------------------------
지금까지는 합성 데이터였습니다. 이번엔 실제 우주선 텔레메트리로 검증합니다.

데이터: NASA SMAP/MSL telemetry (telemanom, Hundman et al. KDD 2018)
    - train/<채널>.npy : 정상 구간만
    - test/<채널>.npy  : 이상 포함
    - labeled_anomalies.csv : 채널별 실제 이상 '구간'(인덱스 범위) 라벨

⚠ 실제 데이터에서 배운 것 (중요):
    처음엔 Step 1처럼 Isolation Forest를 썼지만, 많은 실제 채널은
    train(정상)이 '거의 상수'라서 Isolation Forest가 분할을 못 만들고
    모든 점에 똑같은 점수를 줘 버립니다(무력화). 합성 데이터와 다른 지점입니다.
    → 그래서 여기선 '정상 기준선에서 벗어난 정도(residual)'로 탐지합니다:
         anomaly_score = |값 - 정상평균| + 국소변동성(rolling std)
      그리고 강건한 임계값(중앙값 + K·scale)을 넘으면 이상으로 판정합니다.
      (telemanom 논문의 nonparametric thresholding 아이디어를 단순화한 버전)

방식:
    1) train(정상)으로 '정상 기준선(평균)'을 학습
    2) test의 각 점에 anomaly_score 계산
    3) 강건 임계값을 넘는 점을 이상으로 탐지
    4) labeled_anomalies.csv의 실제 이상 구간과 비교해 평가

────────────────────────────────────────────────────────
📥 데이터 준비 (최초 1회) — HuggingFace 미러에서 채널 1개만 받으면 됩니다
────────────────────────────────────────────────────────
PowerShell에서 (예: 채널 A-1):

    cd "C:\\projects\\satellite-cyber-anomaly-detection"
    mkdir data\\nasa\\train, data\\nasa\\test -Force
    $base="https://huggingface.co/datasets/appleparan/telemanom/resolve/main"
    Invoke-WebRequest "$base/labeled_anomalies.csv" -OutFile "data\\nasa\\labeled_anomalies.csv"
    Invoke-WebRequest "$base/data/data/train/A-1.npy" -OutFile "data\\nasa\\train\\A-1.npy"
    Invoke-WebRequest "$base/data/data/test/A-1.npy"  -OutFile "data\\nasa\\test\\A-1.npy"

실행:
    python src\\06_nasa_real_data.py            # 라벨의 첫 채널 자동 사용
    python src\\06_nasa_real_data.py A-1        # 특정 채널 지정

(data\\ 는 .gitignore 대상이라 깃에 올라가지 않습니다.)
"""

from pathlib import Path
import sys
import ast
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent.parent
NASA_DIR = BASE / "data" / "nasa"
OUT_DIR = BASE / "outputs"
OUT_DIR.mkdir(exist_ok=True)

WINDOW = 50   # 국소 변동성(rolling std)을 보는 창 크기
K = 4         # 임계값 민감도 (작을수록 더 많이 탐지). 3~6 사이에서 결과 안정적.


def find_data_paths() -> tuple[Path, Path, Path]:
    labels = NASA_DIR / "labeled_anomalies.csv"
    for c in [NASA_DIR / "data", NASA_DIR]:  # 압축 해제 방식에 따라 두 경우 모두 탐색
        if (c / "train").is_dir() and (c / "test").is_dir():
            return c / "train", c / "test", labels
    return NASA_DIR / "train", NASA_DIR / "test", labels


def guide_and_exit() -> None:
    print("=" * 64)
    print("❗ NASA 데이터를 찾을 수 없습니다. 먼저 데이터를 준비하세요.")
    print("   (이 파일 상단 주석의 '데이터 준비' 명령을 PowerShell에 붙여넣기)")
    print(f"   기대 위치: {NASA_DIR}\\train, ...\\test, labeled_anomalies.csv")
    print("=" * 64)
    sys.exit(0)


def anomaly_score(series: np.ndarray, base_mean: float) -> np.ndarray:
    """정상 기준선 대비 편차 + 국소 변동성 = 이상 점수 (정상이면 0에 가까움)."""
    s = pd.Series(series.astype(float))
    dev = (s - base_mean).abs()
    vol = s.rolling(WINDOW, min_periods=1).std().fillna(0.0)
    return (dev + vol).values


def robust_threshold(score: np.ndarray, k: float) -> float:
    """중앙값 + k·scale. 정상이 거의 상수(MAD≈0)면 std로 scale을 보정."""
    med = float(np.median(score))
    mad = float(np.median(np.abs(score - med)))
    scale = max(1.4826 * mad, 0.5 * float(score.std()))
    return med + k * scale


def main() -> None:
    train_dir, test_dir, labels_path = find_data_paths()
    if not (train_dir.is_dir() and test_dir.is_dir() and labels_path.is_file()):
        guide_and_exit()

    labels = pd.read_csv(labels_path)
    chan_col = "chan_id" if "chan_id" in labels.columns else "channel_id"
    chan = sys.argv[1] if len(sys.argv) > 1 else str(labels.iloc[0][chan_col])
    row = labels[labels[chan_col] == chan]
    if row.empty:
        print(f"채널 '{chan}' 을(를) 라벨에서 찾지 못했습니다.")
        print("사용 가능 채널 예시:", ", ".join(labels[chan_col].astype(str).head(10)))
        sys.exit(0)
    row = row.iloc[0]

    print(f"[1/4] 채널 '{chan}' 데이터를 불러옵니다...")
    train_arr = np.load(train_dir / f"{chan}.npy")
    test_arr = np.load(test_dir / f"{chan}.npy")
    train_val = train_arr[:, 0] if train_arr.ndim > 1 else train_arr  # 열0 = 텔레메트리 값
    test_val = test_arr[:, 0] if test_arr.ndim > 1 else test_arr
    print(f"    train(정상) {len(train_val)}점 / test {len(test_val)}점")
    if train_val.std() < 1e-6:
        print("    (참고) train이 거의 상수 → Isolation Forest는 무력화됨. residual 방식 사용.")

    print("[2/4] 정상 기준선 학습 → test 이상 점수 계산 → 강건 임계값 판정...")
    base_mean = float(train_val.mean())
    score = anomaly_score(test_val, base_mean)
    thr = robust_threshold(score, K)
    detected = score > thr

    print("[3/4] 실제 라벨(이상 구간)과 비교해 평가합니다...")
    seqs = ast.literal_eval(row["anomaly_sequences"])
    truth = np.zeros(len(test_val), dtype=bool)
    for start, end in seqs:
        truth[int(start):int(end) + 1] = True

    tp = int((detected & truth).sum())
    fp = int((detected & ~truth).sum())
    fn = int((~detected & truth).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    caught_seg = sum(1 for s, e in seqs if detected[int(s):int(e) + 1].any())
    print(f"    실제 이상 구간 {len(seqs)}개 중 {caught_seg}개 탐지 (구간 기준, 핵심 지표)")
    print(f"    포인트 기준  precision {precision:.3f} / recall {recall:.3f} / F1 {f1:.3f}")
    print(f"    (이상으로 플래그한 점: {int(detected.sum())} / {len(test_val)})")

    print("[4/4] 결과 그래프를 그립니다...")
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 7), sharex=True,
                                   gridspec_kw={"height_ratios": [2, 1]})
    t = np.arange(len(test_val))
    ax1.plot(t, test_val, color="#5aa9ff", lw=0.8, label="telemetry (test)")
    for i, (s, e) in enumerate(seqs):
        ax1.axvspan(s, e, color="red", alpha=0.12,
                    label="true anomaly" if i == 0 else None)
    ax1.scatter(t[detected], test_val[detected], s=10, color="red",
                label="detected", zorder=3)
    ax1.set_ylabel("telemetry value")
    ax1.set_title(f"NASA {chan} ({row['spacecraft']}) — Real Telemetry Anomaly Detection")
    ax1.legend(loc="upper right")

    ax2.plot(t, score, color="#8ea0c8", lw=0.7, label="anomaly score")
    ax2.axhline(thr, color="orange", ls="--", lw=1, label=f"threshold (K={K})")
    for s, e in seqs:
        ax2.axvspan(s, e, color="red", alpha=0.12)
    ax2.set_ylabel("anomaly score")
    ax2.set_xlabel("time index")
    ax2.legend(loc="upper right")
    fig.tight_layout()

    out_path = OUT_DIR / f"nasa_{chan}_detection.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"\n완료! 저장 → {out_path}")
    print("위: 파란 선=텔레메트리, 빨간 음영=실제 이상, 빨간 점=탐지")
    print("아래: 이상 점수와 임계값(주황 점선) — 점수가 선을 넘으면 경보.")
    plt.show()


if __name__ == "__main__":
    main()

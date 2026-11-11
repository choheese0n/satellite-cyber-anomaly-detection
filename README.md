# 🔐 Satellite Telemetry Cyber Attack Detection

정상적인 위성 Telemetry와 **사이버 공격·이상 패턴**을 구분하는
**우주 시스템 보안 이상탐지 모델**을 만듭니다.

> **Cybersecurity + Data Science + Space Systems**를 동시에 보여주는, 희소성이 높은 포트폴리오 주제입니다.
> (2번 Telemetry Monitoring 프로젝트의 데이터 개념을 이어받습니다.)
> 명령어는 복사해서 **PowerShell**에 붙여넣으면 됩니다.

---

## 📦 0. 전체 그림

```txt
Satellite
  → Telemetry
  → Ground Station
  → Security Monitoring
  → Anomaly Detection   (정상 vs 공격 패턴 구분)
  → Threat Score        (위협 점수)
```

**탐지 대상 공격 예시:**
| 공격 유형 | 설명 |
|---|---|
| Spoofing | 가짜 신호로 위성/지상국 속이기 |
| Command Injection | 비정상 명령 주입 |
| Telemetry Manipulation | 상태값 조작 |
| Abnormal Communication | 비정상 통신 패턴 |
| Sensor Anomaly | 센서값 이상 |

지금 목표는 **Step 1** : 정상 데이터 + 공격 데이터를 만들고 → **이상탐지 모델(Isolation Forest)** 로 공격을 잡아내기.

---

## 🧰 1. 준비물

TESS/이전 프로젝트에서 **Python 3.12 / VS Code / Git** 세팅했으면 그대로 사용.
```powershell
py -3.12 --version
```

---

## 📁 2. 프로젝트 폴더 & 가상환경

```powershell
cd "C:\Users\조희선\Downloads\AI_Ethic_Monitoring--main\satellite-cyber-anomaly-detection"
```
```powershell
py -3.12 -m venv .venv
```
```powershell
.\.venv\Scripts\Activate.ps1
```
```powershell
python -m pip install --upgrade pip
```

---

## 📚 3. 라이브러리 설치

```powershell
pip install -r requirements.txt
```

| 라이브러리 | 역할 |
|---|---|
| `numpy`, `pandas` | 데이터 생성/처리 |
| `scikit-learn` | 이상탐지 모델 (Isolation Forest) |
| `matplotlib` | 결과 시각화 |

---

## 🚀 4. 첫 실습 — 공격 패턴 섞고, 모델로 탐지하기

`src\01_detect_anomalies.py` 를 실행합니다.

```powershell
python src\01_detect_anomalies.py
```

실행하면:
1. 정상 위성 telemetry를 다수 생성하고, 거기에 **공격성 이상 샘플**(급격한 전압 변화, 비정상 명령률 등)을 섞고,
2. **Isolation Forest** 모델로 "정상 vs 이상"을 학습 없이(비지도) 탐지하고,
3. 얼마나 잘 잡았는지(정확도/놓친 공격) 결과를 출력하고,
4. 정상=파랑, 탐지된 이상=빨강으로 표시한 산점도를 `outputs\anomaly_detection.png` 로 저장합니다.

이게 보안 이상탐지 시스템의 핵심 원리입니다.

---

## 🐙 5. GitHub에 정리

```powershell
cd "C:\Users\조희선\Downloads\AI_Ethic_Monitoring--main\satellite-cyber-anomaly-detection"
```
```powershell
git init
```
```powershell
git add .
```
```powershell
git commit -m "init: 위성 telemetry 사이버 공격 이상탐지 (Isolation Forest)"
```
GitHub 빈 저장소(`satellite-cyber-anomaly-detection`, Public) 생성 후:
```powershell
git remote add origin https://github.com/본인아이디/satellite-cyber-anomaly-detection.git
```
```powershell
git branch -M main
```
```powershell
git push -u origin main
```

---

## 🗂️ 6. 폴더 구조

```txt
satellite-cyber-anomaly-detection/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   └── 01_detect_anomalies.py
├── outputs/
└── data/
```

---

## 🧭 7. 로드맵

| 단계 | 할 일 | 핵심 |
|---|---|---|
| ✅ **Step 1** | 정상+공격 데이터 생성 + Isolation Forest 탐지 | 비지도 이상탐지 |
| **Step 2** | 공격 유형별 라벨 만들고 분류 모델로 구분 | 지도학습 분류 |
| **Step 3** | Threat Score(위협 점수) 설계 | 리스크 스코어링 |
| **Step 4** | 실시간 스트림에서 탐지 + 경보 | 실시간 처리 |
| **Step 5** | Security Monitoring 대시보드 (FastAPI) | 백엔드/시각화 |

**지금 할 일: 1→4 진행하고, 결과가 나오면 알려주세요. Step 2(공격 유형 분류)로 넘어갑니다.**

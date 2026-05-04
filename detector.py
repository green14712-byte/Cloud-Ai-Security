# Isolation Forest 이상 탐지 모델

import os
import json
import joblib
from sklearn.ensemble import IsolationForest

# 모델 저장 파일
MODEL_PATH = "iforest_model.pkl"

# 누적 학습 데이터 저장 파일
DATA_PATH = "accumulated_data.json"

# 최소 학습 데이터 개수
MIN_TRAIN_SIZE = 10

# Isolation Forest 모델 생성
IForest = IsolationForest(
    contamination=0.05,
    random_state=1234
)

# 모델 학습 여부
is_trained = False

# 누적 데이터
accumulated_data = []


# ---------------------------------------
# 1. 기존 누적 데이터 불러오기
# ---------------------------------------
if os.path.exists(DATA_PATH):
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            accumulated_data = json.load(f)

        print(f"저장된 학습 데이터 {len(accumulated_data)}개 불러오기 완료")

    except json.JSONDecodeError:
        accumulated_data = []
        print("누적 데이터 파일 오류 → 새로 시작")


# ---------------------------------------
# 2. 기존 학습 모델 불러오기
# ---------------------------------------
if os.path.exists(MODEL_PATH):
    try:
        IForest = joblib.load(MODEL_PATH)
        is_trained = True
        print("저장된 Isolation Forest 모델 불러오기 완료")

    except Exception:
        is_trained = False
        print("모델 파일 오류 → 새 모델로 시작")


# ---------------------------------------
# 3. feature 개수 확인
# ---------------------------------------
def is_same_feature_size(old_data, new_features):
    """
    기존 누적 데이터와 새 feature의 컬럼 개수가 같은지 확인
    feature 개수가 다르면 기존 데이터/모델을 그대로 쓰면 안 됨
    """
    if not old_data:
        return True

    if new_features is None or len(new_features) == 0:
        return True

    old_size = len(old_data[0])
    new_size = len(new_features[0])

    return old_size == new_size


# ---------------------------------------
# 4. 누적 데이터 저장
# ---------------------------------------
def save_accumulated_data():
    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(accumulated_data, f, indent=4)


# ---------------------------------------
# 5. 이상 탐지 함수
# ---------------------------------------
def detect_anomaly(features):
    global is_trained, accumulated_data, IForest

    # 입력 데이터 없음
    if features is None or len(features) == 0:
        return []

    # feature 개수가 바뀐 경우
    # 예: IP feature 추가 전 데이터와 추가 후 데이터가 섞이는 문제 방지
    if not is_same_feature_size(accumulated_data, features):
        print("feature 개수가 변경되어 기존 학습 데이터와 모델을 초기화합니다.")

        accumulated_data = []
        is_trained = False

        if os.path.exists(MODEL_PATH):
            os.remove(MODEL_PATH)

        if os.path.exists(DATA_PATH):
            os.remove(DATA_PATH)

        IForest = IsolationForest(
            contamination=0.05,
            random_state=1234
        )

    # 새 데이터를 누적 데이터에 추가
    for row in features:
        row_list = row.tolist()

        # 완전히 같은 feature는 중복 저장하지 않음
        if row_list not in accumulated_data:
            accumulated_data.append(row_list)

    # 누적 데이터 저장
    save_accumulated_data()

    print(f"누적 데이터 수: {len(accumulated_data)}/{MIN_TRAIN_SIZE}")

    # 아직 학습 전이면 데이터가 충분할 때 학습
    if not is_trained:
        if len(accumulated_data) >= MIN_TRAIN_SIZE:
            IForest.fit(accumulated_data)
            is_trained = True

            # 학습 모델 저장
            joblib.dump(IForest, MODEL_PATH)

            print("모델 학습 완료 및 저장")
        else:
            print("데이터 부족으로 아직 학습하지 않음")
            return []

    # 학습된 모델로 예측
    preds = IForest.predict(features)

    # 이상 점수 계산
    scores = IForest.decision_function(features)

    results = []

    for pred, score in zip(preds, scores):
        results.append({
            "is_anomaly": pred == -1,  # -1이면 이상, 1이면 정상
            "score": round(float(score), 4)
        })

    return results
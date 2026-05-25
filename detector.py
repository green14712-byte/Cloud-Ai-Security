# Isolation Forest 이상 탐지 모델

import os
import json
import joblib
from sklearn.ensemble import IsolationForest


MODEL_PATH = "iforest_model.pkl"
DATA_PATH = "accumulated_data.json"
TRAINED_IDS_PATH = "trained_event_ids.json"

MIN_TRAIN_SIZE = 10

IForest = IsolationForest(
    contamination=0.05,
    random_state=1234
)

is_trained = False
accumulated_data = []
trained_event_ids = set()


# ---------------------------------------
# 기존 누적 학습 데이터 불러오기
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
# 기존 학습 EventId 불러오기
# ---------------------------------------
if os.path.exists(TRAINED_IDS_PATH):
    try:
        with open(TRAINED_IDS_PATH, "r", encoding="utf-8") as f:
            trained_event_ids = set(json.load(f))

        print(f"이미 학습한 EventId {len(trained_event_ids)}개 불러오기 완료")

    except json.JSONDecodeError:
        trained_event_ids = set()
        print("학습 EventId 파일 오류 → 새로 시작")


# ---------------------------------------
# 기존 학습 모델 불러오기
# ---------------------------------------
if os.path.exists(MODEL_PATH):
    try:
        IForest = joblib.load(MODEL_PATH)
        is_trained = True
        print("저장된 Isolation Forest 모델 불러오기 완료")

    except Exception:
        is_trained = False
        print("모델 파일 오류 → 새 모델로 시작")


def is_same_feature_size(old_data, new_features):
    if not old_data:
        return True

    if new_features is None or len(new_features) == 0:
        return True

    old_size = len(old_data[0])
    new_size = len(new_features[0])

    return old_size == new_size


def save_accumulated_data():
    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(accumulated_data, f, indent=4)


def save_trained_event_ids():
    with open(TRAINED_IDS_PATH, "w", encoding="utf-8") as f:
        json.dump(list(trained_event_ids), f, indent=4)


def reset_model():
    global IForest, is_trained, accumulated_data, trained_event_ids

    accumulated_data = []
    trained_event_ids = set()
    is_trained = False

    for path in [MODEL_PATH, DATA_PATH, TRAINED_IDS_PATH]:
        if os.path.exists(path):
            os.remove(path)

    IForest = IsolationForest(
        contamination=0.05,
        random_state=1234
    )

    print("기존 학습 데이터, 학습 ID, 모델을 초기화했습니다.")


def train_model(features, events=None):
    """
    MongoDB 누적 로그를 기반으로 모델을 학습한다.

    개선점:
    1. 반복되는 정상 패턴도 학습한다.
    2. 단, 같은 EventId는 중복 학습하지 않는다.
    3. 새 EventId가 추가되면 모델을 재학습한다.
    """
    global IForest, is_trained, accumulated_data, trained_event_ids

    if features is None or len(features) == 0:
        print("학습할 데이터가 없습니다.")
        return False

    if not is_same_feature_size(accumulated_data, features):
        print("feature 개수가 변경되어 기존 학습 데이터와 모델을 초기화합니다.")
        reset_model()

    added_count = 0

    for index, row in enumerate(features):
        event_id = None

        if events and index < len(events):
            event_id = events[index].get("EventId")

        # EventId가 있는 로그는 중복 학습 방지
        if event_id:
            if event_id in trained_event_ids:
                continue

            trained_event_ids.add(event_id)

        # EventId가 없는 경우는 중복 판단이 어려우므로 학습에 추가
        row_list = row.tolist()
        accumulated_data.append(row_list)
        added_count += 1

    save_accumulated_data()
    save_trained_event_ids()

    print(f"새로 추가된 학습 데이터: {added_count}개")
    print(f"누적 학습 데이터 수: {len(accumulated_data)}/{MIN_TRAIN_SIZE}")
    print(f"학습 완료 EventId 수: {len(trained_event_ids)}개")

    if added_count == 0:
        print("새로 학습할 로그가 없어 모델 재학습을 건너뜁니다.")
        return is_trained

    if len(accumulated_data) < MIN_TRAIN_SIZE:
        print("데이터 부족으로 아직 모델을 학습하지 않음")
        return False

    IForest.fit(accumulated_data)
    is_trained = True

    joblib.dump(IForest, MODEL_PATH)

    print("Isolation Forest 모델 재학습 완료 및 저장")
    return True


def detect_anomaly(features):
    """
    이미 학습된 모델로 새 이벤트를 탐지한다.
    이 함수에서는 학습 데이터를 추가하지 않는다.
    """
    global is_trained, IForest

    if features is None or len(features) == 0:
        return []

    if not is_trained:
        print("모델이 아직 학습되지 않아 이상 탐지를 수행할 수 없습니다.")
        return []

    preds = IForest.predict(features)
    scores = IForest.decision_function(features)

    results = []

    for pred, score in zip(preds, scores):
        results.append({
            "is_anomaly": bool(pred == -1),
            "score": round(float(score), 4)
        })

    return results
#Isolation Forest 이상 탐지 모델

import numpy as np
#Isolation Forest 모델 불러오기
from sklearn.ensemble import IsolationForest

#Isolation Forest 모델 생성
IForest = IsolationForest(
    #전체의 5%를 이상치로 간주
    contamination=0.05,
    #매번 같은 결과 나오도록 고정
    random_state=1234
)
#모델이 학습됐는지 여부를 저장하는 변수 / 처음엔 학습 안됐기 때문에 False
is_trained = False
#preprocessor.py에서 넘어온 정규화 데이터를 받아서 이상탐지하는 함수
def detect_anomaly(features):
    #함수 안에서 밖에 있는 is_trained변수를 수정하겠다는 선언
    global is_trained

    #데이터 10개 이상 모이면 학습
    #모델 학습이 안 됐으면 아래 코드 실행

    #데이터가 10개 이상 모였는지 확인 / 10개 미만이면 학습하기 너무 적음
    if not is_trained:
        #데이터 10개 이상 시 학습 시작
        #완료 후 is_trained = True로 변경 / 차후부턴 학습 건너뛰고 바로 예측
        if len(features) >= 10:
            IForest.fit(features)
            is_trained = True
            print("모델 학습 완료")
        else:
            #데이터가 10개 미만이라 학습 못함
            #수집된 개수 출력하고 빈 리스트 반환
            print(f"데이터 수집 중..({len(features)}/10)")
            return[]

    #학습된 모델로 예측 / 1=정상 -1=이상
    preds = IForest.predict(features)
    #각 데이터의 이상 점수 계산
    #양수에 가까울수록 정상 / 음수에 가까울수록 이상
    scores = IForest.decision_function(features)

#결과 담을 빈 리스트 생성
    results = []
    #예측 값(preds)과 점수(scores)를 하나씩 같이 꺼내 처리
    for pred, score in zip(preds, scores):
        #각 이벤트마다 결과를 딕셔너리로 저장
        #pred==-1 True면 이상, False면 정상
        #round(float(score),4) -> 점수를 소수점 4자리로 반올림
        results.append({
            "is_anomaly": pred == -1, #1이면 이상
            "score": round(float(score),4)
        })

#결과를 메인으로 넘겨줌
    return results
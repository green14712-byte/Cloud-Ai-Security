#데이터 전처리

#데이터를 표(DataFrame) 형태로 다루는 라이브러리
import pandas as pd
#숫자 계산을 위한 라이브러리
import numpy as np
#데이터를 0~1 사이로 정규화 해주는 도구
from sklearn.preprocessing import MinMaxScaler

#collect_logs에서 넘어온 이벤트 리스트를 받아서 처리하는 함수 선언
def preprocess(events):
    #각 이벤트에서 추출한 특정 값들을 담을 빈 리스트 생성
    features = []
#넘어온 이벤트 처리
    for event in events:
        #시간대 추출 (0시 ~ 23시) / 시간 정보 없으면 0으로 처리
        event_time = event.get("EventTime")
        hour = event_time.hour if event_time else 0

        #위험 이벤트 여부/ 위험한 이벤트 목록 정의 이 이벤트들이 발생 시 위험 신호로 판단
        dangerous_evnets = {
            "DeleteBucket", "DeleteUser", "StopInstances",
            "DetachRolePolicy", "TerminateInstances"
        }
        #이벤트 이름 꺼내서 위험 이벤트 목록에 있으면 1, 없으면 0
        event_name = event.get("EventName", "")
        is_dangerous = 1 if event_name in dangerous_evnets else 0

        #에러 여부 / 에러 코드가 있으면 1, 없으면 0 에러가 많이 발생 시 비정상 접근 가능성 있음
        is_error = 1 if event.get("ErrorCode") else 0

        #새벽 시간대 여부 / 0시 ~ 6시면 1, 아니면 0, 새벽에 발생한 이벤트는 의심 가능
        is_night = 1 if hour <= 6 else 0

#추출한 특징값 4개를 딕셔너리로 만들어서 features 리스트에 추가
        features.append({
            "hour": hour,
            "is_dangerous": is_dangerous,
            "is_error": is_error,
            "is_night": is_night,
        })

#features 리스트를 DataFrame(표) 형태로 변환
        df = pd.DataFrame(features)

#리스트에 아무것도 없을시 none으로 출력
        if df.empty:
            return None

        #MinMaxScaler로 정규화
        #모든 값을 0~1 사이로 정규화
        #fit_transform = 범위 학습 및 변환 동시 수행
        scaler = MinMaxScaler()
        df_scaled = scaler.fit_transform(df)

#정규화된 데이터를 다음 순서로 념겨줌, 여기서 IForest가 받아서 이상탐지 시작
        return df_scaled
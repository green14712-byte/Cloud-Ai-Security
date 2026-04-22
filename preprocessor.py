import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from datetime import datetime


def preprocess(events):
    """
    DB 또는 수집기에서 전달된 이벤트 리스트를 받아
    AI 입력용 숫자 feature로 변환 후 정규화한다.
    """
    features = []

    for event in events:
        event_time_str = event.get("EventTime")

        try:
            event_time = datetime.fromisoformat(event_time_str)
            hour = event_time.hour
        except:
            hour = 0

        dangerous_events = {
            "DeleteBucket",
            "DeleteUser",
            "StopInstances",
            "DetachUserPolicy",
            "TerminateInstances",
            "AttachUserPolicy",
            "AuthorizeSecurityGroupIngress"
        }

        event_name = event.get("EventName", "")
        is_dangerous = 1 if event_name in dangerous_events else 0

        is_error = 1 if event.get("ErrorCode") else 0
        is_night = 1 if hour <= 6 else 0

        # root 또는 숨김 처리 계정은 고위험으로 보기 위한 단순 feature
        actor = event.get("Actor")
        is_root = 1 if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"] else 0

        features.append({
            "hour": hour,
            "is_dangerous": is_dangerous,
            "is_error": is_error,
            "is_night": is_night,
            "is_root": is_root
        })

    df = pd.DataFrame(features)

    if df.empty:
        return None

    scaler = MinMaxScaler()
    df_scaled = scaler.fit_transform(df)

    return df_scaled

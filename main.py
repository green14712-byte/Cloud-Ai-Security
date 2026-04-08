# main.py
import time
from log_collector import collect_logs
from preprocessor import preprocess
from detector import detect_anomaly

print("AI 보안 모니터링 시작")

try:
    while True:
        # 1. 로그 수집
        events = collect_logs()

        if not events:
            print("이벤트 없음. 5초 후 재시도")
            time.sleep(5)
            continue

        print(f"수집된 이벤트 {len(events)}개")
        for event in events:
            print(f"  - {event.get('EventName')} | {event.get('Username')} | {event.get('EventTime')}")

        # 2. 전처리
        features = preprocess(events)
        print(f"전처리 결과: {len(features)}개")

        if features is None:
            print("전처리 데이터 없음")
            time.sleep(5)
            continue

        # 3. 이상 탐지
        results = detect_anomaly(features)

        # 4. 결과 출력
        for event, result in zip(events, results):
            if result.get("is_anomaly"):
                print("이상 탐지")
                print("Event :", event.get("EventName"))
                print("User  :", event.get("Username"))
                print("Score :", result["score"])
                print("-" * 60)

        time.sleep(5)  # 5초마다 반복

except KeyboardInterrupt:
    print("모니터링 종료")
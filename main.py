<<<<<<< HEAD
import time

from log_collector import collect_logs
from db import init_db, save_logs_to_db, count_logs
from preprocessor import preprocess
from detector import detect_anomaly

# 프로그램 시작 시 DB 초기화
init_db()

while True:
    print("\n===== 로그 수집 시작 =====")

    # 1. CloudTrail에서 중요 이벤트 수집
    events = collect_logs()
    print(f"이번 수집 이벤트: {len(events)}개")

    # 2. DB 저장
    save_logs_to_db(events)

    # 3. 이번 수집 기준 최근 3개만 화면 출력 대상으로 사용
    recent_events = sorted(events, key=lambda x: x["EventTime"], reverse=True)[:3]
    print(f"DB 누적 로그 수: {count_logs()}개")
    print(f"화면 출력 대상 최근 로그 수: {len(recent_events)}개 (이번 수집 기준 최근 3개)")

    # 4. 전처리
    features = preprocess(recent_events)
    print("전처리 완료")

    # 5. 이벤트가 없을 경우
    if features is None:
        print("이벤트 없음")

    else:
        # 6. 이상 탐지
        results = detect_anomaly(features)

        print("\n🔎 탐지 결과 (이번 수집 기준 최근 3개):")

        # 아직 학습 전이면 결과가 빈 리스트일 수 있음
        if not results:
            for i, event in enumerate(recent_events, start=1):
                print("━━━━━━━━━━━━━━━━━━━━")
                print(f"[{i}]")
                print(f"🕒 시간   : {event['EventTime']}")
                print(f"👤 사용자 : {event['Actor']}")
                print(f"⚙ 이벤트 : {event['EventName']}")
                print(f"🎯 대상   : {event['TargetUser'] or '-'}")
                print(f"📍 리전   : {event['Region']}")
                print(f"🚨 상태   : 학습 전")
                print(f"📊 점수   : -")
            print("━━━━━━━━━━━━━━━━━━━━")

        else:
            for i, (event, result) in enumerate(zip(recent_events, results), start=1):
                status = "🚨 이상" if result["is_anomaly"] else "정상"
                score = result["score"]

                print("━━━━━━━━━━━━━━━━━━━━")
                print(f"[{i}]")
                print(f"🕒 시간   : {event['EventTime']}")
                print(f"👤 사용자 : {event['Actor']}")
                print(f"⚙ 이벤트 : {event['EventName']}")
                print(f"🎯 대상   : {event['TargetUser'] or '-'}")
                print(f"📍 리전   : {event['Region']}")
                print(f"🚨 상태   : {status}")
                print(f"📊 점수   : {score}")
            print("━━━━━━━━━━━━━━━━━━━━")

    # 7. 10초 대기 후 반복
    print("10초 후 다시 실행...\n")
    time.sleep(10)
=======
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
>>>>>>> c37d0be3ee38e4071f16ace9d5c08b468e308152

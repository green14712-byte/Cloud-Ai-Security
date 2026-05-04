import time

from log_collector import collect_logs
from db import init_db, save_logs_to_db, count_logs, load_recent_logs
from preprocessor import preprocess
from detector import detect_anomaly
from ip_tracker import analyze_ip_activity
from risk_engine import calculate_risk


# 프로그램 시작 시 DB 초기화
init_db()


while True:
    print("\n===== 로그 수집 시작 =====")

    # 1. CloudTrail에서 로그 수집
    events = collect_logs()
    print(f"이번 수집 이벤트: {len(events)}개")

    # 2. DB 저장
    save_logs_to_db(events)
    print(f"DB 누적 로그 수: {count_logs()}개")

    # 3. 이번 수집 기준 최근 3개만 화면 출력
    recent_events = sorted(
        events,
        key=lambda x: x.get("EventTime", ""),
        reverse=True
    )[:3]

    print(f"화면 출력 대상 최근 로그 수: {len(recent_events)}개")

    # 4. 전처리
    features = preprocess(recent_events)
    print("전처리 완료")

    # 5. 이벤트가 없을 경우
    if features is None:
        print("이벤트 없음")

    else:
        # 6. AI 이상 탐지
        ai_results = detect_anomaly(features)

        print("\n🔎 최근 이벤트 분석 결과:")

        for i, event in enumerate(recent_events, start=1):
            ai_result = None
            ai_status = "학습 전"
            ai_score = "-"

            if ai_results and i - 1 < len(ai_results):
                ai_result = ai_results[i - 1]
                ai_status = "이상" if ai_result["is_anomaly"] else "정상"
                ai_score = ai_result["score"]

            # 7. 위험도 계산
            risk = calculate_risk(event, ai_result)

            print("━━━━━━━━━━━━━━━━━━━━")
            print(f"[{i}]")
            print(f"🕒 시간       : {event.get('EventTime')}")
            print(f"👤 행위자     : {event.get('Actor')}")
            print(f"🌐 IP         : {event.get('SourceIP') or '-'}")
            print(f"⚙ 이벤트      : {event.get('EventName')}")
            print(f"🎯 대상       : {event.get('TargetUser') or '-'}")
            print(f"📍 리전       : {event.get('Region')}")
            print(f"🤖 AI 상태    : {ai_status}")
            print(f"📊 AI 점수    : {ai_score}")
            print(f"🔥 위험도     : {risk['risk_level']} ({risk['risk_score']}점)")
            print(f"📝 판단 근거  : {', '.join(risk['reasons'])}")

        print("━━━━━━━━━━━━━━━━━━━━")

    # 8. IP 반복 활동 분석
    print("\n🌐 IP 반복 활동 분석:")

    recent_db_logs = load_recent_logs(limit=50)
    ip_results = analyze_ip_activity(recent_db_logs)

    if not ip_results:
        print("IP 분석 대상 없음")
    else:
        printed = False

        for item in ip_results:
            if item["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                printed = True
                print("━━━━━━━━━━━━━━━━━━━━")
                print(f"IP          : {item['SourceIP']}")
                print(f"전체 이벤트 : {item['total_count']}회")
                print(f"위험 이벤트 : {item['dangerous_count']}회")
                print(f"위험도      : {item['risk_level']}")
                print(f"이유        : {', '.join(item['reason'])}")
                print(f"이벤트 목록 : {', '.join(item['events'])}")

        if not printed:
            print("반복 위험 IP 없음")

    # 9. 반복 대기
    print("\n10초 후 다시 실행...\n")
    time.sleep(10)
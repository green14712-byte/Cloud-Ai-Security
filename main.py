import time

from log_collector import collect_logs

# MongoDB 저장/조회
from mongo_db import (
    init_mongo,
    save_logs_to_mongo,
    save_or_update_analysis,
    save_response_actions,
    count_logs as count_mongo_logs,
    load_recent_logs as load_recent_mongo_logs
)

# SQLite 저장/조회
from db import (
    init_db,
    save_logs_to_db,
    count_logs as count_sqlite_logs
)

from preprocessor import preprocess
from detector import detect_anomaly
from ip_tracker import analyze_ip_activity
from risk_engine import calculate_risk
from auto_responder import apply_response, AUTO_RESPONSE_DRY_RUN


# 프로그램 시작 시 DB 준비
init_mongo()
init_db()


while True:
    print("\n===== 로그 수집 시작 =====")

    # 1. CloudTrail에서 로그 수집
    events = collect_logs()
    print(f"이번 수집 이벤트: {len(events)}개")

    # 2. MongoDB 저장
    save_logs_to_mongo(events)
    print(f"MongoDB 누적 로그 수: {count_mongo_logs()}개")

    # 3. SQLite에도 저장
    save_logs_to_db(events)
    print(f"SQLite 누적 로그 수: {count_sqlite_logs()}개")

    # 4. 이번 수집 기준 최근 3개만 화면 출력
    recent_events = sorted(
        events,
        key=lambda x: x.get("EventTime", ""),
        reverse=True
    )[:3]

    print(f"화면 출력 대상 최근 로그 수: {len(recent_events)}개")

    # 5. AI 학습용 데이터는 MongoDB 누적 로그 사용
    training_events = load_recent_mongo_logs(limit=100)
    training_features = preprocess(training_events)

    if training_features is None:
        print("AI 학습용 데이터 없음")
    else:
        detect_anomaly(training_features)

    # 6. 이번에 수집된 이벤트만 따로 탐지
    detect_features = preprocess(recent_events)
    print("전처리 완료")

    if detect_features is None:
        print("이벤트 없음")

    else:
        ai_results = detect_anomaly(detect_features)

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

            # 8. MongoDB에 AI 결과와 위험도 결과 업데이트
            save_or_update_analysis(
                event_id=event.get("EventId"),
                ai_result=ai_result,
                risk=risk
            )

            # 9. 위험도 결과를 기반으로 자동 대응 정책 적용
            response_actions = apply_response(event, risk, ai_result)
            save_response_actions(event.get("EventId"), response_actions)

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
            print(f"🛡 자동 대응  : {'DRY_RUN' if AUTO_RESPONSE_DRY_RUN else 'LIVE'} / {len(response_actions)}건")
            for action in response_actions:
                result = action.get("result", {})
                print(f"   - {action.get('action_type')}: {result.get('status')} ({result.get('message')})")

        print("━━━━━━━━━━━━━━━━━━━━")

    # 9. IP 반복 활동 분석
    print("\n🌐 IP 반복 활동 분석:")

    recent_db_logs = load_recent_mongo_logs(limit=50)
    ip_results = analyze_ip_activity(recent_db_logs)

    if not ip_results:
        print("IP 분석 대상 없음")
    else:
        printed = False

        for item in ip_results:
            if item["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                printed = True

                print("━━━━━━━━━━━━━━━━━━━━")
                print(f"IP              : {item['SourceIP']}")
                print(f"전체 이벤트      : {item['total_count']}회")
                print(f"평균 위험도      : {item['avg_risk_score']}점")
                print(f"최대 위험도      : {item['max_risk_score']}점")
                print(f"최종 위험도      : {item['risk_level']} ({item['final_risk_score']}점)")
                print(f"HIGH 이벤트      : {item['high_count']}회")
                print(f"CRITICAL 이벤트  : {item['critical_count']}회")
                print(f"정상 IP 활동     : {item['trusted_count']}회")

                if item.get("reason"):
                    print(f"판단 근거        : {', '.join(item['reason'])}")
                else:
                    print("판단 근거        : -")

                print(f"이벤트 목록      : {', '.join(item['events'])}")

                if item.get("event_reasons"):
                    print("대표 이벤트 근거 :")
                    for reason in item["event_reasons"]:
                        print(f" - {reason}")

        if not printed:
            print("반복 위험 IP 없음")

    print("\n10초 후 다시 실행...\n")
    time.sleep(10)
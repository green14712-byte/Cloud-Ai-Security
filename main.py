import time

from log_collector import collect_logs

# MongoDB 저장/조회
from mongo_db import (
    init_mongo,
    save_logs_to_mongo,
    save_or_update_analysis,
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
from detector import train_model, detect_anomaly
from ip_tracker import analyze_ip_activity
from risk_engine import calculate_risk

# 새 모듈
from attack_classifier import classify_attack
from auto_responder import handle_auto_response


# 프로그램 시작 시 DB 준비
init_mongo()
init_db()


while True:
    print("\n===== 로그 수집 시작 =====")

    # 1. CloudTrail 로그 수집
    events = collect_logs()
    print(f"이번 수집 이벤트: {len(events)}개")

    # 2. MongoDB 저장
    save_logs_to_mongo(events)
    print(f"MongoDB 누적 로그 수: {count_mongo_logs()}개")

    # 3. SQLite 저장
    save_logs_to_db(events)
    print(f"SQLite 누적 로그 수: {count_sqlite_logs()}개")

    # 4. 최근 이벤트 출력용
    recent_events = sorted(
        events,
        key=lambda x: x.get("EventTime", ""),
        reverse=True
    )[:3]

    print(f"화면 출력 대상 최근 로그 수: {len(recent_events)}개")

    # =========================================
    # 5. AI 학습
    # =========================================
    training_events = load_recent_mongo_logs(limit=100)
    training_features = preprocess(training_events)

    if training_features is None:
        print("AI 학습용 데이터 없음")
    else:
        train_model(training_features, training_events)

    # =========================================
    # 6. 이번 이벤트 탐지
    # =========================================
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
                ai_status = (
                    "이상"
                    if ai_result["is_anomaly"]
                    else "정상"
                )
                ai_score = ai_result["score"]

            # =========================================
            # 7. 위험도 계산
            # =========================================
            risk = calculate_risk(event, ai_result)

            # =========================================
            # 8. 공격 유형 분류
            # =========================================
            attack_type = classify_attack(event)

            # =========================================
            # 9. 자동 대응 판단
            # =========================================
            response_actions = handle_auto_response(
                event,
                risk,
                ai_result,
                attack_type
            )

            # =========================================
            # 10. MongoDB 저장
            # =========================================
            save_or_update_analysis(
                event_id=event.get("EventId"),
                ai_result=ai_result,
                risk=risk,
                attack_type=attack_type,
                response_actions=response_actions
            )

            # =========================================
            # 화면 출력
            # =========================================
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

            print(
                f"🔥 위험도     : "
                f"{risk['risk_level']} "
                f"({risk['risk_score']}점)"
            )

            print(
                f"🧠 공격 유형  : "
                f"{attack_type}"
            )

            print(
                f"📝 판단 근거  : "
                f"{', '.join(risk['reasons'])}"
            )

            # 자동 대응 출력
            if response_actions:

                print("🛡 자동 대응   :")

                for action in response_actions:
                    print(
                        f" - {action.get('Action')} "
                        f"({action.get('Status')})"
                    )

            else:
                print("🛡 자동 대응   : 없음")

        print("━━━━━━━━━━━━━━━━━━━━")

    # =========================================
    # 11. IP 반복 활동 분석
    # =========================================
    print("\n🌐 IP 반복 활동 분석:")

    recent_db_logs = load_recent_mongo_logs(limit=50)
    ip_results = analyze_ip_activity(recent_db_logs)

    if not ip_results:
        print("IP 분석 대상 없음")

    else:
        printed = False

        for item in ip_results:

            if item["risk_level"] in [
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]:

                printed = True

                print("━━━━━━━━━━━━━━━━━━━━")
                print(f"IP              : {item['SourceIP']}")
                print(f"전체 이벤트      : {item['total_count']}회")
                print(f"평균 위험도      : {item['avg_risk_score']}점")
                print(f"최대 위험도      : {item['max_risk_score']}점")

                print(
                    f"최종 위험도      : "
                    f"{item['risk_level']} "
                    f"({item['final_risk_score']}점)"
                )

                print(f"HIGH 이벤트      : {item['high_count']}회")
                print(f"CRITICAL 이벤트  : {item['critical_count']}회")
                print(f"정상 IP 활동     : {item['trusted_count']}회")

                if item.get("reason"):
                    print(
                        f"판단 근거        : "
                        f"{', '.join(item['reason'])}"
                    )
                else:
                    print("판단 근거        : -")

                print(
                    f"이벤트 목록      : "
                    f"{', '.join(item['events'])}"
                )

                if item.get("event_reasons"):
                    print("대표 이벤트 근거 :")

                    for reason in item["event_reasons"]:
                        print(f" - {reason}")

        if not printed:
            print("반복 위험 IP 없음")

    print("\n10초 후 다시 실행...\n")
    time.sleep(10)
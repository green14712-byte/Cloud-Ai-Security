from mongo_db import init_mongo, load_all_logs, count_logs


def format_value(value):
    return value if value else "-"


def format_policy(policy_arn):
    if not policy_arn:
        return "-"
    return policy_arn.split("/")[-1]


def format_ai(log):
    ai_status = log.get("AIStatus")
    ai_score = log.get("AIScore")

    if not ai_status:
        return "분석 전"

    return f"{ai_status} / score={ai_score}"


def format_risk(log):
    level = log.get("RiskLevel")
    score = log.get("RiskScore")

    if not level:
        return "평가 전"

    return f"{level} ({score}점)"


def print_log(log, index):
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"[{index}]")
    print(f"🕒 시간       : {format_value(log.get('EventTime'))}")
    print(f"📍 리전       : {format_value(log.get('Region'))}")
    print(f"👤 행위자     : {format_value(log.get('Actor'))}")
    print(f"🌐 Source IP  : {format_value(log.get('SourceIP'))}")
    print(f"⚙ 이벤트      : {format_value(log.get('EventName'))}")
    print(f"🎯 대상       : {format_value(log.get('TargetUser'))}")
    print(f"🔐 정책       : {format_policy(log.get('PolicyArn'))}")
    print(f"🤖 AI 결과    : {format_ai(log)}")
    print(f"🔥 위험도     : {format_risk(log)}")

    reasons = log.get("RiskReasons")
    if reasons:
        print(f"📝 판단 근거  : {', '.join(reasons)}")

    error = log.get("ErrorCode")
    print(f"🚨 상태       : {'에러 발생' if error else '정상'}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


def main():
    init_mongo()

    logs = load_all_logs()

    if not logs:
        print("MongoDB에 저장된 로그가 없습니다.")
        return

    print(f"MongoDB 전체 로그 수: {count_logs()}개\n")

    for i, log in enumerate(logs, start=1):
        print_log(log, i)


if __name__ == "__main__":
    main()
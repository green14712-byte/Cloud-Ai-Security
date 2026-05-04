import sqlite3


def format_policy(policy_arn):
    if not policy_arn:
        return "-"
    return policy_arn.split("/")[-1]


def format_error(error):
    return "에러 발생" if error else "정상"


def format_value(value):
    return value if value else "-"


def print_log(log, index):
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"[{index}]")
    print(f"🕒 시간   : {format_value(log['EventTime'])}")
    print(f"📍 리전   : {format_value(log['Region'])}")
    print(f"👤 행위자 : {format_value(log['Actor'])}")
    print(f"🌐 IP     : {format_value(log['SourceIP'])}")
    print(f"🎯 대상   : {format_value(log['TargetUser'])}")
    print(f"⚙ 이벤트 : {format_value(log['EventName'])}")
    print(f"🔐 정책   : {format_policy(log['PolicyArn'])}")
    print(f"🚨 상태   : {format_error(log['ErrorCode'])}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


def main():
    conn = sqlite3.connect("logs.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM logs
    ORDER BY EventTime ASC
    """)

    rows = cursor.fetchall()

    if not rows:
        print("⚠️ DB에 저장된 로그가 없습니다.")
    else:
        print(f"📂 DB 전체 로그 수: {len(rows)}개\n")
        for i, row in enumerate(rows, start=1):
            print_log(dict(row), i)

    conn.close()


if __name__ == "__main__":
    main()
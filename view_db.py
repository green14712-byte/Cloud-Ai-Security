import sqlite3


def format_policy(policy_arn):
    """
    정책 ARN에서 마지막 정책 이름만 추출
    예: arn:aws:iam::aws:policy/AdministratorAccess -> AdministratorAccess
    """
    if not policy_arn:
        return "-"
    return policy_arn.split("/")[-1]


def format_error(error):
    """
    ErrorCode가 있으면 에러 발생, 없으면 정상
    """
    return "에러 발생" if error else "정상"


def print_log(log, index):
    """
    로그 한 개를 보기 좋게 출력
    """
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"[{index}]")
    print(f"🕒 시간   : {log['EventTime']}")
    print(f"📍 리전   : {log['Region']}")
    print(f"👤 행위자 : {log['Actor']}")
    print(f"🎯 대상   : {log['TargetUser'] or '-'}")
    print(f"⚙ 이벤트 : {log['EventName']}")
    print(f"🔐 정책   : {format_policy(log['PolicyArn'])}")
    print(f"🚨 상태   : {format_error(log['ErrorCode'])}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


def main():
    conn = sqlite3.connect("logs.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 오래된 로그가 위, 최신 로그가 아래로 오도록 ASC 정렬
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
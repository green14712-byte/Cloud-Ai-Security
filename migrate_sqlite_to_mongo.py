import sqlite3
from mongo_db import init_mongo, save_logs_to_mongo


SQLITE_DB_NAME = "logs.db"


def load_sqlite_logs():
    """
    SQLite logs.db에 저장된 전체 로그를 불러온다.
    """
    conn = sqlite3.connect(SQLITE_DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM logs
    ORDER BY EventTime ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def main():
    print("===== SQLite → MongoDB 마이그레이션 시작 =====")

    # 1. MongoDB 연결 확인
    init_mongo()

    # 2. SQLite 로그 불러오기
    logs = load_sqlite_logs()
    print(f"SQLite에서 불러온 로그 수: {len(logs)}개")

    if not logs:
        print("옮길 로그가 없습니다.")
        return

    # 3. MongoDB에 저장
    save_logs_to_mongo(logs)

    print("===== 마이그레이션 완료 =====")


if __name__ == "__main__":
    main()
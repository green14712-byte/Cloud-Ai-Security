import sqlite3
from typing import List, Dict, Any

DB_FILE = "logs.db"


def get_connection():
    """
    SQLite DB 연결 생성
    """
    return sqlite3.connect(DB_FILE)


def init_db():
    """
    logs 테이블 생성
    EventId를 PRIMARY KEY로 설정하여 중복 저장 방지
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        EventId TEXT PRIMARY KEY,
        EventName TEXT,
        EventTime TEXT,
        Actor TEXT,
        TargetUser TEXT,
        PolicyArn TEXT,
        Region TEXT,
        EventSource TEXT,
        ErrorCode TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_logs_to_db(events: List[Dict[str, Any]]):
    """
    수집한 로그를 DB에 저장
    EventId 중복은 자동 무시
    """
    if not events:
        print("💾 DB에 저장할 새 이벤트 없음")
        return

    conn = get_connection()
    cursor = conn.cursor()

    added_count = 0

    for event in events:
        try:
            cursor.execute("""
            INSERT INTO logs (
                EventId, EventName, EventTime, Actor, TargetUser,
                PolicyArn, Region, EventSource, ErrorCode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("EventId"),
                event.get("EventName"),
                event.get("EventTime"),
                event.get("Actor"),
                event.get("TargetUser"),
                event.get("PolicyArn"),
                event.get("Region"),
                event.get("EventSource"),
                event.get("ErrorCode")
            ))
            added_count += 1

        except sqlite3.IntegrityError:
            # EventId 중복이면 무시
            pass

    conn.commit()
    conn.close()

    print(f"🗄️ DB 저장 완료 (+{added_count}개 추가)")


def load_recent_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """
    DB에서 최근 로그를 불러온다.
    EventTime 기준 내림차순 정렬
    """
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM logs
    ORDER BY EventTime DESC
    LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def count_logs() -> int:
    """
    DB에 저장된 전체 로그 개수 반환
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]

    conn.close()
    return count
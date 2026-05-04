import sqlite3

DB_NAME = "logs.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def add_column_if_not_exists(cursor, table_name, column_name, column_type):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]

    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def init_db():
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

    extra_columns = {
        "AccessKeyId": "TEXT",
        "GroupId": "TEXT",
        "CidrIp": "TEXT",
        "FromPort": "TEXT",
        "ToPort": "TEXT",
        "IpProtocol": "TEXT",
        "InstanceIds": "TEXT",
        "SourceIP": "TEXT"
    }

    for column_name, column_type in extra_columns.items():
        add_column_if_not_exists(cursor, "logs", column_name, column_type)

    conn.commit()
    conn.close()


def save_logs_to_db(events):
    if not events:
        print("💾 DB에 저장할 새 이벤트 없음")
        return

    conn = get_connection()
    cursor = conn.cursor()

    added_count = 0

    for event in events:
        cursor.execute("""
        INSERT OR IGNORE INTO logs (
            EventId, EventName, EventTime, Actor, TargetUser,
            PolicyArn, Region, EventSource, ErrorCode,
            AccessKeyId, GroupId, CidrIp, FromPort, ToPort,
            IpProtocol, InstanceIds, SourceIP
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("EventId"),
            event.get("EventName"),
            event.get("EventTime"),
            event.get("Actor"),
            event.get("TargetUser"),
            event.get("PolicyArn"),
            event.get("Region"),
            event.get("EventSource"),
            event.get("ErrorCode"),
            event.get("AccessKeyId"),
            event.get("GroupId"),
            event.get("CidrIp"),
            event.get("FromPort"),
            event.get("ToPort"),
            event.get("IpProtocol"),
            event.get("InstanceIds"),
            event.get("SourceIP")
        ))

        if cursor.rowcount == 1:
            added_count += 1

    conn.commit()
    conn.close()

    print(f"💾 DB 저장 완료 (+{added_count}개 추가)")


def load_recent_logs(limit=100):
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


def load_all_logs():
    conn = get_connection()
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


def count_logs():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]

    conn.close()
    return count
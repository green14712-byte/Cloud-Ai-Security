import os
import json
import pandas as pd

# 저장 경로
LOG_DIR = "logs"
RAW_JSON_FILE = os.path.join(LOG_DIR, "logs_raw.json")
PROCESSED_CSV_FILE = os.path.join(LOG_DIR, "logs_processed.csv")


def ensure_log_dir():
    """
    logs 폴더가 없으면 생성한다.
    """
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def save_logs_json(new_logs):
    """
    원본 로그를 JSON 파일에 누적 저장한다.
    EventId 기준으로 중복 제거한다.
    """
    ensure_log_dir()

    # 기존 로그 불러오기
    if os.path.exists(RAW_JSON_FILE):
        with open(RAW_JSON_FILE, "r", encoding="utf-8") as f:
            try:
                existing_logs = json.load(f)
            except json.JSONDecodeError:
                existing_logs = []
    else:
        existing_logs = []

    existing_ids = {log["EventId"] for log in existing_logs if "EventId" in log}

    added_count = 0
    for log in new_logs:
        if log["EventId"] not in existing_ids:
            existing_logs.append(log)
            added_count += 1

    with open(RAW_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(existing_logs, f, indent=4, ensure_ascii=False)

    print(f"💾 JSON 저장 완료 (+{added_count}개 추가)")


def save_logs_csv(new_logs):
    """
    로그를 CSV 파일에 누적 저장한다.
    EventId 기준으로 중복 제거한다.
    """
    ensure_log_dir()

    new_df = pd.DataFrame(new_logs)

    if new_df.empty:
        print("📊 CSV 저장할 로그 없음")
        return

    if os.path.exists(PROCESSED_CSV_FILE):
        old_df = pd.read_csv(PROCESSED_CSV_FILE)
        merged_df = pd.concat([old_df, new_df], ignore_index=True)
        merged_df.drop_duplicates(subset=["EventId"], inplace=True)
    else:
        merged_df = new_df

    merged_df.to_csv(PROCESSED_CSV_FILE, index=False, encoding="utf-8-sig")
    print("📊 CSV 저장 완료")
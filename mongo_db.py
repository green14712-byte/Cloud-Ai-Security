from datetime import datetime
import os

from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cloud_ai_security")
MONGO_COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME", "logs")

if not MONGO_URI:
    raise ValueError(".env 파일에 MONGO_URI가 없습니다.")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]
logs_collection = db[MONGO_COLLECTION_NAME]


def init_mongo():
    """
    MongoDB 연결 확인 및 인덱스 생성
    """
    client.admin.command("ping")

    logs_collection.create_index([("EventId", ASCENDING)], unique=True)
    logs_collection.create_index([("EventTime", DESCENDING)])
    logs_collection.create_index([("SourceIP", ASCENDING)])
    logs_collection.create_index([("RiskLevel", ASCENDING)])

    print("MongoDB 연결 및 인덱스 준비 완료")


def save_logs_to_mongo(events):
    """
    CloudTrail에서 수집한 로그를 MongoDB에 저장한다.
    EventId 기준으로 중복 저장을 방지한다.
    """
    if not events:
        print("MongoDB에 저장할 새 이벤트 없음")
        return 0

    added_count = 0

    for event in events:
        doc = dict(event)
        doc["CollectedAt"] = datetime.now().isoformat()

        try:
            result = logs_collection.update_one(
                {"EventId": doc.get("EventId")},
                {"$setOnInsert": doc},
                upsert=True
            )

            if result.upserted_id is not None:
                added_count += 1

        except DuplicateKeyError:
            pass
        except Exception as e:
            print(f"MongoDB 저장 오류: {e}")

    print(f"MongoDB 저장 완료 (+{added_count}개 추가)")
    return added_count


def save_or_update_analysis(event_id, ai_result=None, risk=None):
    """
    이미 저장된 로그에 AI 분석 결과와 위험도 평가 결과를 업데이트한다.
    """
    if not event_id:
        return

    update_data = {
        "AnalyzedAt": datetime.now().isoformat()
    }

    if ai_result is not None:
        update_data["AIResult"] = ai_result
        update_data["AIStatus"] = "ANOMALY" if ai_result.get("is_anomaly") else "NORMAL"
        update_data["AIScore"] = ai_result.get("score")

    if risk is not None:
        update_data["RiskScore"] = risk.get("risk_score")
        update_data["RiskLevel"] = risk.get("risk_level")
        update_data["RiskReasons"] = risk.get("reasons")

    logs_collection.update_one(
        {"EventId": event_id},
        {"$set": update_data}
    )


def load_recent_logs(limit=100):
    """
    MongoDB에서 최근 로그를 가져온다.
    AI 학습 및 IP 분석에 사용한다.
    """
    cursor = logs_collection.find(
        {},
        {"_id": 0}
    ).sort("EventTime", DESCENDING).limit(limit)

    return list(cursor)


def load_all_logs():
    """
    MongoDB 전체 로그를 오래된 순서대로 가져온다.
    """
    cursor = logs_collection.find(
        {},
        {"_id": 0}
    ).sort("EventTime", ASCENDING)

    return list(cursor)


def count_logs():
    """
    MongoDB에 저장된 전체 로그 개수 반환
    """
    return logs_collection.count_documents({})
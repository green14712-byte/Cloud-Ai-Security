import boto3
import time
from botocore.exceptions import ClientError

# 조회할 리전 목록
regions = [
    "ap-southeast-2",  # 시드니
    "ap-northeast-2",  # 서울
    "us-east-1"        # 버지니아 북부
]

# 중요 이벤트 목록
important_events = {
    "ConsoleLogin",
    "StartInstances",
    "StopInstances",
    "RunInstances",
    "TerminateInstances",
    "CreateUser",
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress"
}

# 이미 처리한 이벤트 저장
seen_event_ids = set()

print("🔍 멀티 리전 CloudTrail 모니터링 시작 (10초 간격)...\n")

try:
    while True:
        for region in regions:
            try:
                client = boto3.client("cloudtrail", region_name=region)
                response = client.lookup_events(MaxResults=20)
                events = response.get("Events", [])

                for event in events:
                    event_id = event.get("EventId")
                    event_name = event.get("EventName")

                    # 이미 본 이벤트면 스킵
                    if event_id in seen_event_ids:
                        continue

                    # 중요 이벤트 아니면 스킵
                    if event_name not in important_events:
                        continue

                    # 새로운 중요 이벤트
                    seen_event_ids.add(event_id)

                    print("🚨 중요 이벤트 발견!")
                    print("Region :", region)
                    print("Event  :", event_name)
                    print("Time   :", event.get("EventTime"))
                    print("User   :", event.get("Username"))
                    print("EventId:", event_id)
                    print("-" * 60)

            except ClientError as e:
                print(f"[{region}] AWS 오류:", e)

        # 5초 대기
        time.sleep(5)

except KeyboardInterrupt:
    print("\n⛔ 모니터링 종료")
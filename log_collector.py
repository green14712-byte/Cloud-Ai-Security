# CloudTrail 내의 로그 수집

import boto3
import json
from botocore.exceptions import ClientError

# 로그 수집할 리전 목록
regions = [
    "ap-southeast-2",  # 시드니
    "ap-northeast-2",  # 서울
    "us-east-1"        # 버지니아 북부 (IAM / ConsoleLogin 등 글로벌 이벤트)
]

# 중요 이벤트 목록
important_events = {
    "ConsoleLogin",
    "StartInstances",
    "StopInstances",
    "RunInstances",
    "TerminateInstances",
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress",
    "CreateAccessKey",
    "DeleteAccessKey"
}

# 이미 처리한 이벤트 저장
seen_event_ids = set()


def collect_logs():
    """
    여러 리전의 CloudTrail 로그를 조회하여
    중요 이벤트만 수집하고, EventId 기준으로 중복 제거 후 반환한다.
    """
    collected = []

    for region in regions:
        try:
            client = boto3.client("cloudtrail", region_name=region)
            response = client.lookup_events(MaxResults=50)
            events = response.get("Events", [])

            for event in events:
                event_id = event.get("EventId")
                event_name = event.get("EventName")

                # 이미 처리한 이벤트면 건너뜀
                if event_id in seen_event_ids:
                    continue

                # 중요 이벤트가 아니면 건너뜀
                if event_name not in important_events:
                    continue

                seen_event_ids.add(event_id)

                actor = event.get("Username")
                target_user = None
                policy_arn = None

                # CloudTrailEvent 원본 JSON 파싱
                cloudtrail_event_str = event.get("CloudTrailEvent")

                if cloudtrail_event_str:
                    try:
                        parsed_event = json.loads(cloudtrail_event_str)

                        request_params = parsed_event.get("requestParameters")

                        # requestParameters가 dict일 때만 접근
                        if isinstance(request_params, dict):
                            target_user = request_params.get("userName")
                            policy_arn = request_params.get("policyArn")

                    except json.JSONDecodeError:
                        pass

                collected.append({
                    "EventId": event_id,
                    "EventName": event_name,
                    "EventTime": str(event.get("EventTime")),
                    "Actor": actor,                 # 실제 행위자
                    "TargetUser": target_user,      # 권한 변경 대상 사용자
                    "PolicyArn": policy_arn,        # 붙이거나 뗀 정책 ARN
                    "Region": region,
                    "EventSource": event.get("EventSource"),
                    "ErrorCode": event.get("ErrorCode")
                })

        except ClientError as e:
            print(f"[{region}] AWS 오류:", e)

    return collected
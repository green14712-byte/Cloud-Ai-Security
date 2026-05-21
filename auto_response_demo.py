"""
자동 대응 기능 시연용 스크립트
실제 AWS 자원을 변경하지 않는 DRY_RUN 상태에서 정책 결정과 대응 결과를 확인한다.

실행:
    python auto_response_demo.py
"""

from auto_responder import apply_response, AUTO_RESPONSE_DRY_RUN


def print_actions(title, event, risk, ai_result=None):
    print("\n" + "=" * 70)
    print(title)
    print("이벤트:", event["EventName"])
    print("위험도:", f"{risk['risk_level']} ({risk['risk_score']}점)")
    print("DRY_RUN:", AUTO_RESPONSE_DRY_RUN)

    actions = apply_response(event, risk, ai_result)

    for action in actions:
        result = action.get("result", {})
        print("- 조치:", action.get("action_type"))
        print("  사유:", action.get("reason"))
        print("  결과:", result.get("status"), "/", result.get("message"))


if __name__ == "__main__":
    ai_anomaly = {"is_anomaly": True, "score": -0.12}

    print_actions(
        "시나리오 1: 보안그룹 SSH 전체 개방 → 인바운드 규칙 제거 대상",
        {
            "EventId": "demo-001",
            "EventName": "AuthorizeSecurityGroupIngress",
            "EventTime": "2026-05-19T01:10:00",
            "Actor": "root",
            "SourceIP": "8.8.8.8",
            "Region": "ap-northeast-2",
            "GroupId": "sg-demo1234",
            "CidrIp": "0.0.0.0/0",
            "FromPort": "22",
            "ToPort": "22",
            "IpProtocol": "tcp",
        },
        {"risk_level": "CRITICAL", "risk_score": 100, "reasons": ["0.0.0.0/0 민감 포트 개방"]},
        ai_anomaly,
    )

    print_actions(
        "시나리오 2: 외부 IP에서 Access Key 생성 → 키 비활성화 대상",
        {
            "EventId": "demo-002",
            "EventName": "CreateAccessKey",
            "EventTime": "2026-05-19T02:20:00",
            "Actor": "test-admin",
            "TargetUser": "test-user",
            "SourceIP": "8.8.4.4",
            "Region": "ap-northeast-2",
            "AccessKeyId": "AKIADEMOEXAMPLE",
        },
        {"risk_level": "HIGH", "risk_score": 85, "reasons": ["신규 Access Key 생성"]},
        ai_anomaly,
    )

    print_actions(
        "시나리오 3: CloudTrail 로깅 중지 → 로깅 재시작 대상",
        {
            "EventId": "demo-003",
            "EventName": "StopLogging",
            "EventTime": "2026-05-19T03:30:00",
            "Actor": "root",
            "SourceIP": "8.8.8.8",
            "Region": "ap-northeast-2",
            "TrailName": "capstone-trail",
        },
        {"risk_level": "CRITICAL", "risk_score": 95, "reasons": ["CloudTrail 방어 회피 의심"]},
        ai_anomaly,
    )

    print_actions(
        "시나리오 4: S3 정책 변경 → Public Access Block 적용 대상",
        {
            "EventId": "demo-004",
            "EventName": "PutBucketPolicy",
            "EventTime": "2026-05-19T04:40:00",
            "Actor": "test-admin",
            "SourceIP": "8.8.8.8",
            "Region": "ap-northeast-2",
            "BucketName": "capstone-test-bucket",
        },
        {"risk_level": "HIGH", "risk_score": 88, "reasons": ["S3 버킷 정책 변경"]},
        ai_anomaly,
    )

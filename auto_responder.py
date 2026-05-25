import os
from datetime import datetime

import boto3
from dotenv import load_dotenv

from risk_engine import is_trusted_ip, is_external_ip

load_dotenv()


AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "false").lower() == "true"
AUTO_RESPONSE_DRY_RUN = os.getenv("AUTO_RESPONSE_DRY_RUN", "true").lower() == "true"
AUTO_RESPONSE_MIN_LEVEL = os.getenv("AUTO_RESPONSE_MIN_LEVEL", "HIGH")
AUTO_RESPONSE_NOTIFY_LEVEL = os.getenv("AUTO_RESPONSE_NOTIFY_LEVEL", "MEDIUM")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")

EXCLUDED_ACTORS = [
    actor.strip()
    for actor in os.getenv("AUTO_RESPONSE_EXCLUDED_ACTORS", "").split(",")
    if actor.strip()
]

RISK_ORDER = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def is_level_at_least(level, minimum):
    return RISK_ORDER.get(level, 0) >= RISK_ORDER.get(minimum, 0)


def make_action(action, status, reason, detail=None):
    return {
        "Action": action,
        "Status": status,
        "Reason": reason,
        "Detail": detail or {},
        "ExecutedAt": datetime.now().isoformat()
    }


def is_root_actor(actor):
    return actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"]


def should_skip_root_by_trusted_ip(event):
    actor = event.get("Actor")
    source_ip = event.get("SourceIP")

    if not is_root_actor(actor):
        return False

    if is_trusted_ip(actor, source_ip):
        return True

    return False


def notify_admin(event, risk, attack_type):
    if not SNS_TOPIC_ARN:
        return make_action(
            "SEND_ALERT",
            "SKIPPED",
            "SNS_TOPIC_ARN이 설정되지 않아 알림 전송 생략"
        )

    if AUTO_RESPONSE_DRY_RUN:
        return make_action(
            "SEND_ALERT",
            "DRY_RUN",
            "관리자 알림 전송 예정",
            {
                "TopicArn": SNS_TOPIC_ARN,
                "EventName": event.get("EventName"),
                "RiskLevel": risk.get("risk_level"),
                "RiskScore": risk.get("risk_score"),
                "AttackType": attack_type
            }
        )

    try:
        sns = boto3.client("sns")
        message = (
            f"[Cloud AI Security Alert]\n"
            f"Event: {event.get('EventName')}\n"
            f"Actor: {event.get('Actor')}\n"
            f"SourceIP: {event.get('SourceIP')}\n"
            f"Risk: {risk.get('risk_level')} ({risk.get('risk_score')})\n"
            f"AttackType: {attack_type}\n"
            f"Reasons: {', '.join(risk.get('reasons', []))}"
        )

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Cloud AI Security Alert",
            Message=message
        )

        return make_action("SEND_ALERT", "SUCCESS", "SNS 알림 전송 완료")

    except Exception as e:
        return make_action("SEND_ALERT", "FAILED", str(e))


def revoke_security_group_ingress(event):
    region = event.get("Region")
    group_id = event.get("GroupId")
    cidr_ip = event.get("CidrIp")
    from_port = event.get("FromPort")
    to_port = event.get("ToPort")
    ip_protocol = event.get("IpProtocol") or "tcp"

    if not all([region, group_id, cidr_ip, from_port, to_port]):
        return make_action(
            "REVOKE_SECURITY_GROUP_INGRESS",
            "SKIPPED",
            "보안그룹 차단에 필요한 필드 부족",
            {
                "Region": region,
                "GroupId": group_id,
                "CidrIp": cidr_ip,
                "FromPort": from_port,
                "ToPort": to_port,
                "IpProtocol": ip_protocol
            }
        )

    if AUTO_RESPONSE_DRY_RUN:
        return make_action(
            "REVOKE_SECURITY_GROUP_INGRESS",
            "DRY_RUN",
            "보안그룹 인바운드 규칙 제거 예정",
            {
                "Region": region,
                "GroupId": group_id,
                "CidrIp": cidr_ip,
                "FromPort": from_port,
                "ToPort": to_port,
                "IpProtocol": ip_protocol
            }
        )

    try:
        ec2 = boto3.client("ec2", region_name=region)
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": ip_protocol,
                    "FromPort": int(from_port),
                    "ToPort": int(to_port),
                    "IpRanges": [{"CidrIp": cidr_ip}]
                }
            ]
        )

        return make_action(
            "REVOKE_SECURITY_GROUP_INGRESS",
            "SUCCESS",
            "보안그룹 인바운드 규칙 제거 완료"
        )

    except Exception as e:
        return make_action("REVOKE_SECURITY_GROUP_INGRESS", "FAILED", str(e))


def deactivate_access_key(event):
    target_user = event.get("TargetUser")
    access_key_id = event.get("AccessKeyId")

    if not target_user or not access_key_id:
        return make_action(
            "DEACTIVATE_ACCESS_KEY",
            "SKIPPED",
            "Access Key 비활성화에 필요한 필드 부족",
            {
                "TargetUser": target_user,
                "AccessKeyId": access_key_id
            }
        )

    if AUTO_RESPONSE_DRY_RUN:
        return make_action(
            "DEACTIVATE_ACCESS_KEY",
            "DRY_RUN",
            "Access Key 비활성화 예정",
            {
                "TargetUser": target_user,
                "AccessKeyId": access_key_id
            }
        )

    try:
        iam = boto3.client("iam")
        iam.update_access_key(
            UserName=target_user,
            AccessKeyId=access_key_id,
            Status="Inactive"
        )

        return make_action(
            "DEACTIVATE_ACCESS_KEY",
            "SUCCESS",
            "Access Key 비활성화 완료"
        )

    except Exception as e:
        return make_action("DEACTIVATE_ACCESS_KEY", "FAILED", str(e))


def start_cloudtrail_logging(event):
    region = event.get("Region")
    trail_name = event.get("TrailName")

    if not region or not trail_name:
        return make_action(
            "START_CLOUDTRAIL_LOGGING",
            "SKIPPED",
            "CloudTrail 재시작에 필요한 TrailName 또는 Region 부족",
            {
                "Region": region,
                "TrailName": trail_name
            }
        )

    if AUTO_RESPONSE_DRY_RUN:
        return make_action(
            "START_CLOUDTRAIL_LOGGING",
            "DRY_RUN",
            "CloudTrail 로깅 재시작 예정",
            {
                "Region": region,
                "TrailName": trail_name
            }
        )

    try:
        cloudtrail = boto3.client("cloudtrail", region_name=region)
        cloudtrail.start_logging(Name=trail_name)

        return make_action(
            "START_CLOUDTRAIL_LOGGING",
            "SUCCESS",
            "CloudTrail 로깅 재시작 완료"
        )

    except Exception as e:
        return make_action("START_CLOUDTRAIL_LOGGING", "FAILED", str(e))


def enable_s3_public_access_block(event):
    bucket_name = event.get("BucketName")

    if not bucket_name:
        return make_action(
            "ENABLE_S3_PUBLIC_ACCESS_BLOCK",
            "SKIPPED",
            "S3 Public Access Block 설정에 필요한 BucketName 부족"
        )

    if AUTO_RESPONSE_DRY_RUN:
        return make_action(
            "ENABLE_S3_PUBLIC_ACCESS_BLOCK",
            "DRY_RUN",
            "S3 Public Access Block 적용 예정",
            {
                "BucketName": bucket_name
            }
        )

    try:
        s3 = boto3.client("s3")
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )

        return make_action(
            "ENABLE_S3_PUBLIC_ACCESS_BLOCK",
            "SUCCESS",
            "S3 Public Access Block 적용 완료"
        )

    except Exception as e:
        return make_action("ENABLE_S3_PUBLIC_ACCESS_BLOCK", "FAILED", str(e))


def handle_auto_response(event, risk, ai_result=None, attack_type=None):
    actions = []

    if not AUTO_RESPONSE_ENABLED:
        actions.append(
            make_action("AUTO_RESPONSE", "DISABLED", "자동 대응 기능 비활성화")
        )
        return actions

    actor = event.get("Actor")
    source_ip = event.get("SourceIP")
    risk_level = risk.get("risk_level", "LOW")
    event_name = event.get("EventName")

    # 1. .env에서 제외한 계정은 자동대응 제외
    if actor in EXCLUDED_ACTORS:
        actions.append(
            make_action(
                "AUTO_RESPONSE",
                "SKIPPED",
                "자동 대응 제외 계정",
                {"Actor": actor}
            )
        )
        return actions

    # 2. root 계정이라도 trusted IP면 자동대응 제외
    if should_skip_root_by_trusted_ip(event):
        actions.append(
            make_action(
                "AUTO_RESPONSE",
                "SKIPPED",
                "root 계정이 등록된 정상 IP에서 활동하여 자동대응 제외",
                {
                    "Actor": actor,
                    "SourceIP": source_ip
                }
            )
        )
        return actions

    # 3. root 계정인데 trusted IP가 아니면 자동대응 계속 진행
    if is_root_actor(actor) and not is_trusted_ip(actor, source_ip):
        if is_external_ip(source_ip):
            actions.append(
                make_action(
                    "ROOT_EXTERNAL_IP_DETECTED",
                    "CHECKED",
                    "root 계정이 등록되지 않은 외부 IP에서 활동하여 자동대응 판단 계속 진행",
                    {
                        "Actor": actor,
                        "SourceIP": source_ip
                    }
                )
            )

    # 4. 알림 기준 이상이면 알림
    if is_level_at_least(risk_level, AUTO_RESPONSE_NOTIFY_LEVEL):
        actions.append(notify_admin(event, risk, attack_type))

    # 5. 자동대응 최소 위험도 미충족이면 종료
    if not is_level_at_least(risk_level, AUTO_RESPONSE_MIN_LEVEL):
        actions.append(
            make_action(
                "AUTO_RESPONSE",
                "SKIPPED",
                "자동 대응 최소 위험도 미충족",
                {
                    "RiskLevel": risk_level,
                    "MinLevel": AUTO_RESPONSE_MIN_LEVEL
                }
            )
        )
        return actions

    # 6. 이벤트별 자동대응 실행
    if event_name == "AuthorizeSecurityGroupIngress":
        actions.append(revoke_security_group_ingress(event))

    elif event_name == "CreateAccessKey":
        actions.append(deactivate_access_key(event))

    elif event_name == "StopLogging":
        actions.append(start_cloudtrail_logging(event))

    elif event_name in ["PutBucketPolicy", "PutBucketAcl"]:
        actions.append(enable_s3_public_access_block(event))

    else:
        actions.append(
            make_action(
                "MANUAL_REVIEW",
                "REQUIRED",
                "자동 조치 대상이 아니므로 수동 검토 필요",
                {
                    "EventName": event_name,
                    "RiskLevel": risk_level,
                    "AttackType": attack_type
                }
            )
        )

    return actions
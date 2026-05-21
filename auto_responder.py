"""
Cloud AI Security - 자동 대응 정책 엔진

설계 원칙
1) 위험도 평가 결과를 그대로 신뢰하지 않고, 이벤트 종류와 필수 필드가 맞는 경우에만 조치한다.
2) 실습/시연 안전을 위해 기본값은 DRY_RUN=True이다. 실제 AWS 변경은 .env에서 AUTO_RESPONSE_DRY_RUN=false로 바꿔야 한다.
3) 모든 대응 결과는 MongoDB 로그 문서의 ResponseActions 배열에 저장할 수 있도록 action 결과를 반환한다.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from risk_engine import is_open_to_world, is_sensitive_port, is_trusted_ip

load_dotenv()

LEVEL_RANK = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_list(name: str) -> List[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _rank(level: str) -> int:
    return LEVEL_RANK.get((level or "LOW").upper(), 1)


AUTO_RESPONSE_ENABLED = _env_bool("AUTO_RESPONSE_ENABLED", True)
AUTO_RESPONSE_DRY_RUN = _env_bool("AUTO_RESPONSE_DRY_RUN", True)
AUTO_RESPONSE_MIN_LEVEL = os.getenv("AUTO_RESPONSE_MIN_LEVEL", "HIGH").upper()
AUTO_RESPONSE_NOTIFY_LEVEL = os.getenv("AUTO_RESPONSE_NOTIFY_LEVEL", "MEDIUM").upper()
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
EXCLUDED_ACTORS = set(_env_list("AUTO_RESPONSE_EXCLUDED_ACTORS"))


def build_action(
    action_type: str,
    reason: str,
    status: str = "PENDING",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "action_type": action_type,
        "reason": reason,
        "status": status,
        "details": details or {},
    }


def decide_actions(event: Dict[str, Any], risk: Dict[str, Any], ai_result: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    위험도 결과와 이벤트 필드를 보고 수행할 대응 후보를 결정한다.
    여기서는 아직 AWS API를 호출하지 않고, 어떤 조치가 필요한지만 판단한다.
    """
    if not AUTO_RESPONSE_ENABLED:
        return [build_action("AUTO_RESPONSE_DISABLED", "자동 대응 기능이 비활성화되어 있음", "SKIPPED")]

    event_name = event.get("EventName", "")
    actor = event.get("Actor")
    source_ip = event.get("SourceIP")
    risk_level = risk.get("risk_level", "LOW")
    risk_score = int(risk.get("risk_score", 0) or 0)
    actions: List[Dict[str, Any]] = []

    if actor in EXCLUDED_ACTORS:
        return [build_action("EXCLUDED_ACTOR", f"제외 대상 행위자({actor})의 이벤트", "SKIPPED")]

    # MEDIUM 이상은 공통적으로 알림 대상이다.
    if _rank(risk_level) >= _rank(AUTO_RESPONSE_NOTIFY_LEVEL):
        actions.append(build_action(
            "SEND_ALERT",
            f"{risk_level} 위험 이벤트 알림 대상",
            details={
                "risk_level": risk_level,
                "risk_score": risk_score,
                "event_name": event_name,
                "actor": actor,
                "source_ip": source_ip,
            },
        ))

    # 실제 차단/복구 조치는 HIGH 이상부터 수행한다.
    if _rank(risk_level) < _rank(AUTO_RESPONSE_MIN_LEVEL):
        return actions

    # 1) Security Group이 0.0.0.0/0으로 민감 포트를 열면 해당 인바운드 규칙 제거
    if event_name == "AuthorizeSecurityGroupIngress":
        cidr_ip = event.get("CidrIp")
        from_port = event.get("FromPort")
        to_port = event.get("ToPort")
        group_id = event.get("GroupId")
        sg_rule_id = event.get("SecurityGroupRuleId")

        if group_id and is_open_to_world(cidr_ip) and is_sensitive_port(from_port, to_port):
            actions.append(build_action(
                "REVOKE_SECURITY_GROUP_INGRESS",
                "보안그룹이 전체 인터넷(0.0.0.0/0)에 민감 포트를 개방하여 인바운드 규칙 제거 필요",
                details={
                    "region": event.get("Region"),
                    "group_id": group_id,
                    "security_group_rule_id": sg_rule_id,
                    "cidr_ip": cidr_ip,
                    "from_port": from_port,
                    "to_port": to_port,
                    "ip_protocol": event.get("IpProtocol") or "tcp",
                },
            ))

    # 2) 새 Access Key 생성이 고위험이면 삭제보다 안전한 비활성화 우선
    if event_name == "CreateAccessKey":
        access_key_id = event.get("AccessKeyId")
        target_user = event.get("TargetUser") or actor
        ai_anomaly = bool(ai_result and ai_result.get("is_anomaly"))
        trusted = is_trusted_ip(actor, source_ip)

        if access_key_id and (risk_score >= 90 or ai_anomaly or not trusted):
            actions.append(build_action(
                "DEACTIVATE_ACCESS_KEY",
                "고위험 조건에서 신규 Access Key가 생성되어 키 비활성화 필요",
                details={
                    "access_key_id": access_key_id,
                    "user_name": target_user,
                    "ai_anomaly": ai_anomaly,
                    "trusted_ip": trusted,
                },
            ))

    # 3) CloudTrail StopLogging은 탐지 우회 가능성이 높으므로 로깅 재시작 시도
    if event_name == "StopLogging":
        trail_name = event.get("TrailName")
        if trail_name:
            actions.append(build_action(
                "START_CLOUDTRAIL_LOGGING",
                "CloudTrail 로깅 중지 이벤트가 발생하여 로깅 재시작 필요",
                details={
                    "region": event.get("Region"),
                    "trail_name": trail_name,
                },
            ))
        else:
            actions.append(build_action(
                "MANUAL_REVIEW_REQUIRED",
                "CloudTrail StopLogging 탐지: TrailName이 없어 자동 재시작 대신 수동 확인 필요",
                "SKIPPED",
            ))

    # 4) S3 정책/ACL 변경은 공개 차단 설정으로 완화 가능
    if event_name in {"PutBucketPolicy", "PutBucketAcl"}:
        bucket_name = event.get("BucketName")
        if bucket_name:
            actions.append(build_action(
                "ENABLE_S3_PUBLIC_ACCESS_BLOCK",
                "S3 공개 가능성 있는 설정 변경이 발생하여 버킷 Public Access Block 적용 필요",
                details={"bucket_name": bucket_name},
            ))
        else:
            actions.append(build_action(
                "MANUAL_REVIEW_REQUIRED",
                "S3 정책/ACL 변경 탐지: BucketName이 없어 수동 확인 필요",
                "SKIPPED",
            ))

    # 5) 자동 원복이 위험한 이벤트는 알림과 검토 요청으로 제한
    if event_name in {"AttachUserPolicy", "PutUserPolicy", "DeleteTrail", "TerminateInstances", "DeleteUser", "DeleteBucket"}:
        actions.append(build_action(
            "MANUAL_REVIEW_REQUIRED",
            f"{event_name} 이벤트는 자동 원복 시 업무 영향이 커서 관리자 검토 필요",
            "SKIPPED",
        ))

    return actions


def _format_alert_message(event: Dict[str, Any], risk: Dict[str, Any], action: Dict[str, Any]) -> str:
    return json.dumps({
        "title": "Cloud AI Security 자동 대응 알림",
        "time": datetime.now().isoformat(),
        "event_id": event.get("EventId"),
        "event_time": event.get("EventTime"),
        "event_name": event.get("EventName"),
        "actor": event.get("Actor"),
        "source_ip": event.get("SourceIP"),
        "region": event.get("Region"),
        "risk_level": risk.get("risk_level"),
        "risk_score": risk.get("risk_score"),
        "risk_reasons": risk.get("reasons", []),
        "action": action,
    }, ensure_ascii=False, indent=2)


def _execute_send_alert(event: Dict[str, Any], risk: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
    message = _format_alert_message(event, risk, action)

    if not SNS_TOPIC_ARN:
        return {"status": "SIMULATED", "message": "SNS_TOPIC_ARN 미설정: 콘솔/DB 이력으로만 알림 기록", "payload": message}

    if AUTO_RESPONSE_DRY_RUN:
        return {"status": "DRY_RUN", "message": "SNS publish 시뮬레이션", "payload": message}

    sns = boto3.client("sns")
    response = sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[Cloud AI Security] 위험 이벤트 탐지",
        Message=message,
    )
    return {"status": "SUCCESS", "message": "SNS 알림 발송 완료", "aws_response": response}


def _execute_revoke_sg(action: Dict[str, Any]) -> Dict[str, Any]:
    details = action.get("details", {})
    region = details.get("region")
    group_id = details.get("group_id")
    sg_rule_id = details.get("security_group_rule_id")

    if not group_id:
        return {"status": "FAILED", "message": "GroupId가 없어 보안그룹 규칙 제거 불가"}

    if AUTO_RESPONSE_DRY_RUN:
        return {"status": "DRY_RUN", "message": "보안그룹 인바운드 규칙 제거 시뮬레이션", "request": details}

    ec2 = boto3.client("ec2", region_name=region)

    if sg_rule_id:
        response = ec2.revoke_security_group_ingress(
            GroupId=group_id,
            SecurityGroupRuleIds=[sg_rule_id],
        )
    else:
        response = ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{
                "IpProtocol": str(details.get("ip_protocol") or "tcp"),
                "FromPort": int(details.get("from_port")),
                "ToPort": int(details.get("to_port")),
                "IpRanges": [{"CidrIp": details.get("cidr_ip")}],
            }],
        )

    return {"status": "SUCCESS", "message": "보안그룹 인바운드 규칙 제거 완료", "aws_response": response}


def _execute_deactivate_access_key(action: Dict[str, Any]) -> Dict[str, Any]:
    details = action.get("details", {})
    access_key_id = details.get("access_key_id")
    user_name = details.get("user_name")

    if not access_key_id:
        return {"status": "FAILED", "message": "AccessKeyId가 없어 키 비활성화 불가"}

    request = {"AccessKeyId": access_key_id, "Status": "Inactive"}
    if user_name and user_name not in {"root", "HIDDEN_DUE_TO_SECURITY_REASONS"}:
        request["UserName"] = user_name

    if AUTO_RESPONSE_DRY_RUN:
        return {"status": "DRY_RUN", "message": "Access Key 비활성화 시뮬레이션", "request": request}

    iam = boto3.client("iam")
    response = iam.update_access_key(**request)
    return {"status": "SUCCESS", "message": "Access Key 비활성화 완료", "aws_response": response}


def _execute_start_cloudtrail_logging(action: Dict[str, Any]) -> Dict[str, Any]:
    details = action.get("details", {})
    region = details.get("region")
    trail_name = details.get("trail_name")

    if not trail_name:
        return {"status": "FAILED", "message": "TrailName이 없어 CloudTrail 재시작 불가"}

    if AUTO_RESPONSE_DRY_RUN:
        return {"status": "DRY_RUN", "message": "CloudTrail StartLogging 시뮬레이션", "request": details}

    cloudtrail = boto3.client("cloudtrail", region_name=region)
    response = cloudtrail.start_logging(Name=trail_name)
    return {"status": "SUCCESS", "message": "CloudTrail 로깅 재시작 완료", "aws_response": response}


def _execute_s3_public_access_block(action: Dict[str, Any]) -> Dict[str, Any]:
    details = action.get("details", {})
    bucket_name = details.get("bucket_name")

    if not bucket_name:
        return {"status": "FAILED", "message": "BucketName이 없어 S3 Public Access Block 적용 불가"}

    request = {
        "Bucket": bucket_name,
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }

    if AUTO_RESPONSE_DRY_RUN:
        return {"status": "DRY_RUN", "message": "S3 Public Access Block 적용 시뮬레이션", "request": request}

    s3 = boto3.client("s3")
    response = s3.put_public_access_block(**request)
    return {"status": "SUCCESS", "message": "S3 Public Access Block 적용 완료", "aws_response": response}


def execute_action(event: Dict[str, Any], risk: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
    action_type = action.get("action_type")

    if action.get("status") == "SKIPPED":
        result = {"status": "SKIPPED", "message": action.get("reason")}
    else:
        try:
            if action_type == "SEND_ALERT":
                result = _execute_send_alert(event, risk, action)
            elif action_type == "REVOKE_SECURITY_GROUP_INGRESS":
                result = _execute_revoke_sg(action)
            elif action_type == "DEACTIVATE_ACCESS_KEY":
                result = _execute_deactivate_access_key(action)
            elif action_type == "START_CLOUDTRAIL_LOGGING":
                result = _execute_start_cloudtrail_logging(action)
            elif action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
                result = _execute_s3_public_access_block(action)
            else:
                result = {"status": "SKIPPED", "message": f"실행 대상이 아닌 조치 유형: {action_type}"}

        except (ClientError, BotoCoreError) as e:
            result = {"status": "FAILED", "message": str(e)}
        except Exception as e:
            result = {"status": "FAILED", "message": f"예상치 못한 오류: {e}"}

    return {
        **action,
        "executed_at": datetime.now().isoformat(),
        "dry_run": AUTO_RESPONSE_DRY_RUN,
        "result": result,
    }


def apply_response(event: Dict[str, Any], risk: Dict[str, Any], ai_result: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    자동 대응 전체 흐름: 정책 결정 -> 실행/시뮬레이션 -> 결과 반환
    """
    actions = decide_actions(event, risk, ai_result)
    executed_actions = []

    for action in actions:
        executed_actions.append(execute_action(event, risk, action))

    return executed_actions

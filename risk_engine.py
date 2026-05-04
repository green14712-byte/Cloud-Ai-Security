from datetime import datetime
import ipaddress


# 이벤트별 기본 위험 점수
# CVSS의 Impact 개념을 참고해서 이벤트가 시스템에 미치는 영향도 기준으로 설정
EVENT_SCORES = {
    "ConsoleLogin": 2,

    "StartInstances": 3,
    "StopInstances": 5,
    "RunInstances": 6,
    "TerminateInstances": 8,

    "CreateUser": 7,
    "DeleteUser": 8,

    "AttachUserPolicy": 9,
    "DetachUserPolicy": 5,
    "PutUserPolicy": 9,
    "DeleteUserPolicy": 6,

    "CreateAccessKey": 8,
    "DeleteAccessKey": 5,

    "AuthorizeSecurityGroupIngress": 8,
    "RevokeSecurityGroupIngress": 4,
}


def get_hour(event_time):
    """
    EventTime 문자열에서 시간(hour)을 추출한다.
    실패하면 -1 반환
    """
    try:
        return datetime.fromisoformat(event_time).hour
    except Exception:
        return -1


def is_external_ip(ip):
    """
    외부 IP 여부 판단.
    사설 IP면 0, 외부 IP면 1.
    """
    if not ip:
        return 0

    try:
        ip_obj = ipaddress.ip_address(ip)
        return 0 if ip_obj.is_private else 1
    except ValueError:
        return 0


def classify_risk(score):
    """
    총 위험 점수를 위험 등급으로 변환
    """
    if score <= 4:
        return "LOW"
    elif score <= 9:
        return "MEDIUM"
    elif score <= 14:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_risk(event, ai_result=None):
    """
    하나의 CloudTrail 이벤트에 대해 위험도 점수 계산
    """
    score = 0
    reasons = []

    event_name = event.get("EventName", "")
    actor = event.get("Actor")
    source_ip = event.get("SourceIP")
    error_code = event.get("ErrorCode")
    event_time = event.get("EventTime")

    # 1. 이벤트 영향도 점수
    base_score = EVENT_SCORES.get(event_name, 1)
    score += base_score
    reasons.append(f"이벤트 영향도 +{base_score}")

    # 2. root 계정 또는 숨김 계정 사용
    if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"]:
        score += 4
        reasons.append("root/숨김 계정 사용 +4")

    # 3. 야간 시간대
    hour = get_hour(event_time)
    if 0 <= hour <= 6:
        score += 2
        reasons.append("야간 시간대 활동 +2")

    # 4. 에러 발생
    if error_code:
        score += 2
        reasons.append("에러 발생 +2")

    # 5. 외부 IP 접근
    if is_external_ip(source_ip):
        score += 2
        reasons.append("외부 IP 접근 +2")

    # 6. AI 이상 탐지 결과
    if ai_result and ai_result.get("is_anomaly"):
        score += 3
        reasons.append("AI 이상 탐지 +3")

    risk_level = classify_risk(score)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }
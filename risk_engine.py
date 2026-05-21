from datetime import datetime
import ipaddress
import json
import os


# ============================================
# 0. 정상 IP 설정 파일
# ============================================

TRUSTED_IPS_FILE = "trusted_ips.json"


def load_trusted_ips():
    """
    사용자별 정상 IP 목록을 trusted_ips.json에서 불러온다.
    파일이 없으면 빈 dict 반환.
    """
    if not os.path.exists(TRUSTED_IPS_FILE):
        return {}

    try:
        with open(TRUSTED_IPS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


TRUSTED_IPS = load_trusted_ips()


# ============================================
# 1. 이벤트 기본 점수표
# AWS Security Hub, GuardDuty, Elastic Rule, MITRE ATT&CK 개념 참고
# ============================================

BASE_EVENT_SCORES = {
    # 일반 로그인/조회성 이벤트
    "ConsoleLogin": 30,

    # EC2 관련
    "StartInstances": 30,
    "StopInstances": 50,
    "RunInstances": 60,
    "TerminateInstances": 80,

    # IAM 사용자 관련
    "CreateUser": 65,
    "DeleteUser": 75,

    # IAM 권한 변경
    "AttachUserPolicy": 75,
    "DetachUserPolicy": 55,
    "PutUserPolicy": 75,
    "DeleteUserPolicy": 60,

    # Access Key 관련
    "CreateAccessKey": 75,
    "DeleteAccessKey": 55,

    # Security Group 관련
    "AuthorizeSecurityGroupIngress": 75,
    "RevokeSecurityGroupIngress": 45,

    # CloudTrail 방어 회피
    "StopLogging": 85,
    "DeleteTrail": 90,
    "UpdateTrail": 65,

    # S3 관련
    "PutBucketPolicy": 80,
    "DeleteBucket": 80,
    "PutBucketAcl": 75,
}


# ============================================
# 2. 위험 이벤트 분류
# ============================================

HIGH_RISK_EVENTS = {
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateAccessKey",
    "AuthorizeSecurityGroupIngress",
    "TerminateInstances",
    "DeleteUser",
    "StopLogging",
    "DeleteTrail",
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeleteBucket",
}

MEDIUM_RISK_EVENTS = {
    "StopInstances",
    "DetachUserPolicy",
    "DeleteAccessKey",
    "DeleteUserPolicy",
    "RunInstances",
    "CreateUser",
}


# ============================================
# 3. 위험도 등급 분류
# AWS Security Hub 정규화 심각도 방식 참고
# ============================================

def classify_risk(score):
    if score == 0:
        return "INFORMATIONAL"
    elif score <= 39:
        return "LOW"
    elif score <= 69:
        return "MEDIUM"
    elif score <= 89:
        return "HIGH"
    else:
        return "CRITICAL"


# ============================================
# 4. 유틸 함수
# ============================================

def get_hour(event_time):
    """
    EventTime 문자열에서 hour 추출.
    실패하면 -1 반환.
    """
    try:
        return datetime.fromisoformat(event_time).hour
    except Exception:
        return -1


def is_external_ip(ip):
    """
    외부 IP 여부 판단.
    사설 IP면 False, 공인 IP면 True.
    """
    if not ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False


def is_trusted_ip(actor, ip):
    """
    trusted_ips.json에 등록된 정상 IP인지 확인.
    """
    if not actor or not ip:
        return False

    trusted_list = TRUSTED_IPS.get(actor, [])

    return ip in trusted_list


def is_open_to_world(cidr_ip):
    """
    보안 그룹이 전체 인터넷에 열렸는지 확인.
    """
    return cidr_ip == "0.0.0.0/0"


def is_admin_policy(policy_arn):
    """
    관리자급 정책인지 확인.
    """
    if not policy_arn:
        return False

    admin_keywords = [
        "AdministratorAccess",
        "PowerUserAccess",
        "IAMFullAccess"
    ]

    return any(keyword in policy_arn for keyword in admin_keywords)


def is_sensitive_port(from_port, to_port):
    """
    SSH, RDP, DB 등 민감 포트 개방 여부 확인.
    """
    sensitive_ports = {22, 3389, 3306, 5432, 6379, 9200}

    try:
        fp = int(from_port) if from_port is not None else None
        tp = int(to_port) if to_port is not None else None
    except ValueError:
        return False

    if fp is None or tp is None:
        return False

    for port in sensitive_ports:
        if fp <= port <= tp:
            return True

    return False


# ============================================
# 5. 위험도 계산 핵심 함수
# ============================================

def calculate_risk(event, ai_result=None):
    """
    최종 점수 공식:

    RiskScore = min(
        100,
        round(
            (BaseScore + ContextBonus + AnomalyBonus + CorrelationBonus)
            × CriticalityMultiplier
        )
    )

    추가 개선:
    - trusted_ips.json에 등록된 정상 IP에서 root 활동이 발생하면 감점 적용
    """

    event_name = event.get("EventName", "")
    actor = event.get("Actor")
    source_ip = event.get("SourceIP")
    event_time = event.get("EventTime")
    error_code = event.get("ErrorCode")
    policy_arn = event.get("PolicyArn")
    cidr_ip = event.get("CidrIp")
    from_port = event.get("FromPort")
    to_port = event.get("ToPort")

    reasons = []

    # ----------------------------------------
    # 1. BaseScore: 이벤트 자체 위험도
    # ----------------------------------------
    base_score = BASE_EVENT_SCORES.get(event_name, 20)

    score = base_score
    reasons.append(f"이벤트 기본 위험도 +{base_score}")

    # ----------------------------------------
    # 2. ContextBonus: 상황 기반 보정
    # ----------------------------------------
    context_bonus = 0

    hour = get_hour(event_time)

    # 야간 자체를 크게 보지 않고, 위험 이벤트와 결합될 때 더 강하게 반영
    if 0 <= hour <= 6:
        if event_name in HIGH_RISK_EVENTS:
            context_bonus += 10
            reasons.append("야간 시간대 고위험 이벤트 +10")
        elif event_name in MEDIUM_RISK_EVENTS:
            context_bonus += 5
            reasons.append("야간 시간대 중간 위험 이벤트 +5")
        else:
            context_bonus += 2
            reasons.append("야간 시간대 활동 +2")

    # 외부 IP 접근
    if is_external_ip(source_ip):
        if event_name in HIGH_RISK_EVENTS:
            context_bonus += 10
            reasons.append("외부 IP에서 고위험 이벤트 발생 +10")
        else:
            context_bonus += 5
            reasons.append("외부 IP 접근 +5")

    # 정상 등록 IP 사용 시 위험도 감소
    if is_trusted_ip(actor, source_ip):
        if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"]:
            context_bonus -= 15
            reasons.append("등록된 root 정상 IP 사용 -15")
        else:
            context_bonus -= 10
            reasons.append("등록된 정상 IP 사용 -10")

    # API 오류 또는 실패 이벤트
    if error_code:
        context_bonus += 5
        reasons.append("API 오류 또는 실패 이벤트 +5")

    # 관리자 정책 부여
    if event_name in {"AttachUserPolicy", "PutUserPolicy"} and is_admin_policy(policy_arn):
        context_bonus += 15
        reasons.append("관리자급 정책 부여 +15")

    # 보안그룹 전체 개방 및 민감 포트 개방
    if event_name == "AuthorizeSecurityGroupIngress":
        if is_open_to_world(cidr_ip):
            context_bonus += 15
            reasons.append("0.0.0.0/0 전체 개방 +15")

        if is_sensitive_port(from_port, to_port):
            context_bonus += 10
            reasons.append("민감 포트 개방 +10")

    score += context_bonus

    # ----------------------------------------
    # 3. AnomalyBonus: AI 이상 탐지 결과
    # ----------------------------------------
    anomaly_bonus = 0

    if ai_result and ai_result.get("is_anomaly"):
        anomaly_bonus += 10
        reasons.append("AI 이상 탐지 결과 +10")

    score += anomaly_bonus

    # ----------------------------------------
    # 4. CorrelationBonus
    # 현재 단일 이벤트 기반에서는 0점
    # 추후 로그인 → 권한 변경 → AccessKey 생성 같은 연쇄 탐지 시 추가
    # ----------------------------------------
    correlation_bonus = 0
    score += correlation_bonus

    # ----------------------------------------
    # 5. CriticalityMultiplier: 계정 중요도 배수
    # root 자체를 무조건 높게 보지 않고,
    # 고위험 이벤트와 결합될 때 더 강하게 반영
    # ----------------------------------------
    multiplier = 1.0

    if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"]:
        if event_name in HIGH_RISK_EVENTS:
            multiplier = 1.25
            reasons.append("root/고권한 계정의 고위험 이벤트 ×1.25")
        else:
            multiplier = 1.10
            reasons.append("root/고권한 계정 활동 ×1.10")

    # ----------------------------------------
    # 6. 최종 점수 보정
    # 음수 방지, 100점 초과 방지
    # ----------------------------------------
    final_score = round(score * multiplier)

    if final_score < 0:
        final_score = 0

    final_score = min(100, final_score)

    risk_level = classify_risk(final_score)

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "base_score": base_score,
        "context_bonus": context_bonus,
        "anomaly_bonus": anomaly_bonus,
        "correlation_bonus": correlation_bonus,
        "criticality_multiplier": multiplier,
    }
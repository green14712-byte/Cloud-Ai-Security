def classify_attack(event):
    event_name = event.get("EventName", "")
    user_type = event.get("UserType")
    source_ip = event.get("SourceIP") or ""
    event_source = event.get("EventSource") or ""

    # AWS 내부 서비스가 AssumeRole 한 경우
    if event_name == "AssumeRole":
        if (
            user_type == "AWSService"
            or source_ip.endswith(".amazonaws.com")
            or "amazonaws.com" in source_ip
        ):
            return "AWS 서비스 Role 사용"

        return "역할 가장 / 권한 탈취 의심"

    if event_name in ["StopLogging", "DeleteTrail"]:
        return "CloudTrail 방어 회피 공격"

    if event_name in ["AttachUserPolicy", "PutUserPolicy"]:
        return "IAM 사용자 권한 상승 공격"

    if event_name in ["AttachRolePolicy", "PutRolePolicy"]:
        return "IAM Role 권한 상승 공격"

    if event_name in ["CreateRole", "UpdateAssumeRolePolicy"]:
        return "IAM Role 백도어 의심"

    if event_name == "CreateAccessKey":
        return "인증 정보 생성 / 계정 탈취 의심"

    if event_name == "AuthorizeSecurityGroupIngress":
        return "외부 접근 허용 / 침입 가능성"

    if event_name in ["PutBucketPolicy", "PutBucketAcl"]:
        return "S3 공개화 또는 권한 변경 의심"

    if event_name == "TerminateInstances":
        return "서비스 종료 공격"

    if event_name == "DeleteUser":
        return "계정 삭제 공격"

    if event_name == "ConsoleLogin":
        return "로그인 이벤트"

    return "일반 활동"
from collections import defaultdict

DANGEROUS_EVENTS = {
    "DeleteUser",
    "AttachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "CreateAccessKey",
    "AuthorizeSecurityGroupIngress",
    "TerminateInstances"
}


def analyze_ip_activity(events):
    ip_stats = defaultdict(lambda: {
        "total_count": 0,
        "dangerous_count": 0,
        "events": []
    })

    for event in events:
        source_ip = event.get("SourceIP")

        if not source_ip:
            continue

        event_name = event.get("EventName", "")

        ip_stats[source_ip]["total_count"] += 1
        ip_stats[source_ip]["events"].append(event_name)

        if event_name in DANGEROUS_EVENTS:
            ip_stats[source_ip]["dangerous_count"] += 1

    results = []

    for ip, stat in ip_stats.items():
        risk_level = "LOW"
        reason = []

        if stat["total_count"] >= 5:
            risk_level = "MEDIUM"
            reason.append("동일 IP에서 반복 이벤트 발생")

        if stat["dangerous_count"] >= 2:
            risk_level = "HIGH"
            reason.append("동일 IP에서 위험 이벤트 반복 발생")

        if stat["total_count"] >= 10 or stat["dangerous_count"] >= 4:
            risk_level = "CRITICAL"
            reason.append("동일 IP에서 과도한 위험 활동 발생")

        results.append({
            "SourceIP": ip,
            "total_count": stat["total_count"],
            "dangerous_count": stat["dangerous_count"],
            "risk_level": risk_level,
            "events": stat["events"],
            "reason": reason
        })

    return results
from collections import defaultdict

from risk_engine import calculate_risk, classify_risk, is_trusted_ip


def summarize_ip_risk(avg_score, max_score, total_count, high_count, critical_count, trusted_count):
    """
    IP 단위 반복 활동 위험도 계산.

    핵심 기준:
    - 단순 반복 횟수만으로 CRITICAL을 만들지 않음
    - 개별 이벤트의 RiskScore를 기반으로 평균/최대 점수를 계산
    - trusted IP에서 발생한 정상 가능성 높은 활동은 완화
    """

    score = avg_score
    reasons = []

    # 반복 이벤트 보정
    if total_count >= 10:
        score += 10
        reasons.append("동일 IP에서 10회 이상 반복 활동 +10")
    elif total_count >= 5:
        score += 5
        reasons.append("동일 IP에서 5회 이상 반복 활동 +5")

    # HIGH/CRITICAL 이벤트 비율 보정
    if critical_count >= 2:
        score += 15
        reasons.append("CRITICAL 이벤트 반복 발생 +15")
    elif critical_count >= 1:
        score += 10
        reasons.append("CRITICAL 이벤트 발생 +10")

    if high_count >= 3:
        score += 10
        reasons.append("HIGH 이벤트 3회 이상 발생 +10")
    elif high_count >= 1:
        score += 5
        reasons.append("HIGH 이벤트 발생 +5")

    # 최대 위험 이벤트가 높으면 보정
    if max_score >= 90:
        score += 10
        reasons.append("최대 위험 이벤트가 CRITICAL 수준 +10")
    elif max_score >= 70:
        score += 5
        reasons.append("최대 위험 이벤트가 HIGH 수준 +5")

    # trusted IP 완화
    if trusted_count > 0:
        score -= 15
        reasons.append("등록된 정상 IP 활동 포함 -15")

    # 점수 범위 보정
    score = max(0, min(100, round(score)))

    return score, classify_risk(score), reasons


def analyze_ip_activity(events):
    """
    최근 로그를 SourceIP 기준으로 묶어서 반복 활동 위험도를 분석한다.

    기존 방식:
    - 이벤트 개수와 위험 이벤트 개수만 보고 판단

    개선 방식:
    - 각 이벤트를 risk_engine.calculate_risk()로 다시 평가
    - IP별 평균 RiskScore, 최대 RiskScore, HIGH/CRITICAL 개수 사용
    - trusted IP 여부를 반영해 정상 관리자 활동 오탐 감소
    """

    ip_stats = defaultdict(lambda: {
        "total_count": 0,
        "events": [],
        "risk_scores": [],
        "risk_levels": [],
        "risk_reasons": [],
        "trusted_count": 0,
        "high_count": 0,
        "critical_count": 0,
    })

    for event in events:
        source_ip = event.get("SourceIP")

        if not source_ip:
            continue

        actor = event.get("Actor")
        event_name = event.get("EventName", "")

        # 개별 이벤트 위험도 재계산
        # IP 분석 단계에서는 AI 결과가 없을 수 있으므로 ai_result=None
        risk = calculate_risk(event, ai_result=None)

        risk_score = risk.get("risk_score", 0)
        risk_level = risk.get("risk_level", "LOW")

        ip_stats[source_ip]["total_count"] += 1
        ip_stats[source_ip]["events"].append(event_name)
        ip_stats[source_ip]["risk_scores"].append(risk_score)
        ip_stats[source_ip]["risk_levels"].append(risk_level)
        ip_stats[source_ip]["risk_reasons"].extend(risk.get("reasons", []))

        if is_trusted_ip(actor, source_ip):
            ip_stats[source_ip]["trusted_count"] += 1

        if risk_level == "HIGH":
            ip_stats[source_ip]["high_count"] += 1

        if risk_level == "CRITICAL":
            ip_stats[source_ip]["critical_count"] += 1

    results = []

    for ip, stat in ip_stats.items():
        scores = stat["risk_scores"]

        if not scores:
            continue

        avg_score = sum(scores) / len(scores)
        max_score = max(scores)

        final_score, final_level, summary_reasons = summarize_ip_risk(
            avg_score=avg_score,
            max_score=max_score,
            total_count=stat["total_count"],
            high_count=stat["high_count"],
            critical_count=stat["critical_count"],
            trusted_count=stat["trusted_count"]
        )

        # 중복 판단 근거 제거
        unique_event_reasons = []
        for reason in stat["risk_reasons"]:
            if reason not in unique_event_reasons:
                unique_event_reasons.append(reason)

        results.append({
            "SourceIP": ip,
            "total_count": stat["total_count"],
            "avg_risk_score": round(avg_score, 2),
            "max_risk_score": max_score,
            "final_risk_score": final_score,
            "risk_level": final_level,
            "high_count": stat["high_count"],
            "critical_count": stat["critical_count"],
            "trusted_count": stat["trusted_count"],
            "events": stat["events"],
            "reason": summary_reasons,
            "event_reasons": unique_event_reasons[:5]
        })

    # 위험도 높은 순으로 정렬
    results.sort(
        key=lambda x: x["final_risk_score"],
        reverse=True
    )

    return results
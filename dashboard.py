"""
Cloud AI Security Dashboard

실행 방법:
    streamlit run dashboard.py

역할:
- MongoDB에 분석 결과가 있으면 MongoDB를 우선 사용
- MongoDB 연결이 안 되면 logs.db(SQLite)를 사용
- SQLite에는 RiskScore/RiskLevel이 없을 수 있으므로 dashboard에서 risk_engine.calculate_risk()로 즉시 계산
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# 프로젝트 루트 기준으로 상대 경로(logs.db, trusted_ips.json 등)를 맞춘다.
BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

from risk_engine import calculate_risk  # noqa: E402
from ip_tracker import analyze_ip_activity  # noqa: E402

try:
    from dotenv import load_dotenv
    from pymongo import MongoClient, DESCENDING
except Exception:  # pragma: no cover - 설치 환경에 따라 없을 수 있음
    load_dotenv = None
    MongoClient = None
    DESCENDING = -1


RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
RISK_KR = {
    "CRITICAL": "긴급",
    "HIGH": "높음",
    "MEDIUM": "중간",
    "LOW": "낮음",
    "INFORMATIONAL": "정보",
}
RISK_BADGE_CLASS = {
    "CRITICAL": "badge-critical",
    "HIGH": "badge-high",
    "MEDIUM": "badge-medium",
    "LOW": "badge-low",
    "INFORMATIONAL": "badge-info",
}

REQUIRED_COLUMNS = [
    "EventId", "EventTime", "EventName", "Actor", "SourceIP", "Region", "EventSource",
    "TargetUser", "PolicyArn", "ErrorCode", "AccessKeyId", "GroupId", "CidrIp",
    "FromPort", "ToPort", "IpProtocol", "InstanceIds", "BucketName", "TrailName",
    "SecurityGroupRuleId", "AIStatus", "AIScore", "RiskScore", "RiskLevel", "RiskReasons",
    "ResponseActions",
]


def set_page_style() -> None:
    st.set_page_config(
        page_title="Cloud AI Security Dashboard",
        page_icon="🛡️",
        layout="wide",
    )

    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; }
        .hero {
            padding: 1.3rem 1.4rem;
            border-radius: 22px;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 52%, #334155 100%);
            color: white;
            margin-bottom: 1rem;
            box-shadow: 0 12px 30px rgba(15, 23, 42, 0.18);
        }
        .hero h1 { margin: 0 0 0.35rem 0; font-size: 2rem; }
        .hero p { margin: 0; opacity: 0.86; }
        .metric-card {
            padding: 1rem;
            border-radius: 18px;
            border: 1px solid #e5e7eb;
            background: #ffffff;
            box-shadow: 0 8px 22px rgba(15, 23, 42, 0.06);
        }
        .metric-label { color: #64748b; font-size: 0.86rem; margin-bottom: 0.25rem; }
        .metric-value { color: #0f172a; font-size: 1.65rem; font-weight: 800; }
        .metric-caption { color: #64748b; font-size: 0.8rem; margin-top: 0.25rem; }
        .badge {
            display: inline-block;
            padding: 0.18rem 0.55rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
            color: white;
        }
        .badge-critical { background: #7f1d1d; }
        .badge-high { background: #dc2626; }
        .badge-medium { background: #d97706; }
        .badge-low { background: #2563eb; }
        .badge-info { background: #64748b; }
        .small-muted { color: #64748b; font-size: 0.85rem; }
        .event-card {
            border: 1px solid #e5e7eb;
            border-radius: 18px;
            padding: 0.9rem 1rem;
            margin-bottom: 0.65rem;
            background: white;
        }
        .event-title { font-weight: 800; font-size: 1rem; color: #111827; }
        .event-meta { color: #64748b; font-size: 0.84rem; margin-top: 0.25rem; }
        .reason { color: #374151; font-size: 0.86rem; margin-top: 0.4rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def safe_json_loads(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def load_from_mongo(limit: int = 2000) -> Tuple[List[Dict[str, Any]], str]:
    if load_dotenv is None or MongoClient is None:
        return [], "MongoDB 라이브러리 미설치"

    load_dotenv()
    mongo_uri = os.getenv("MONGO_URI")
    db_name = os.getenv("MONGO_DB_NAME", "cloud_ai_security")
    collection_name = os.getenv("MONGO_COLLECTION_NAME", "logs")

    if not mongo_uri:
        return [], "MONGO_URI 미설정"

    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2500)
        client.admin.command("ping")
        collection = client[db_name][collection_name]
        docs = list(
            collection.find({}, {"_id": 0})
            .sort("EventTime", DESCENDING)
            .limit(limit)
        )
        return docs, "MongoDB"
    except Exception as exc:
        return [], f"MongoDB 연결 실패: {exc}"


def load_from_sqlite(limit: int = 2000) -> Tuple[List[Dict[str, Any]], str]:
    db_path = BASE_DIR / "logs.db"
    if not db_path.exists():
        return [], "logs.db 없음"

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM logs
            ORDER BY EventTime DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows, "SQLite"
    except Exception as exc:
        return [], f"SQLite 조회 실패: {exc}"


@st.cache_data(ttl=10)
def load_events(limit: int = 2000) -> Tuple[List[Dict[str, Any]], str, str]:
    mongo_rows, mongo_status = load_from_mongo(limit)
    if mongo_rows:
        return mongo_rows, "MongoDB", mongo_status

    sqlite_rows, sqlite_status = load_from_sqlite(limit)
    if sqlite_rows:
        return sqlite_rows, "SQLite", f"{mongo_status} → SQLite 사용"

    return [], "없음", f"{mongo_status} / {sqlite_status}"


def normalize_events(events: List[Dict[str, Any]]) -> pd.DataFrame:
    normalized: List[Dict[str, Any]] = []

    for event in events:
        row = dict(event)

        # MongoDB에 분석 결과가 없거나 SQLite 원본 로그만 있는 경우 위험도 즉시 계산
        ai_result = safe_json_loads(row.get("AIResult")) if row.get("AIResult") is not None else None
        risk = calculate_risk(row, ai_result=ai_result if isinstance(ai_result, dict) else None)

        row["RiskScore"] = row.get("RiskScore") if row.get("RiskScore") is not None else risk.get("risk_score")
        row["RiskLevel"] = row.get("RiskLevel") or risk.get("risk_level")
        row["RiskReasons"] = row.get("RiskReasons") or risk.get("reasons")
        row["AIStatus"] = row.get("AIStatus") or "-"
        row["AIScore"] = row.get("AIScore") if row.get("AIScore") is not None else "-"
        row["ResponseActions"] = safe_json_loads(row.get("ResponseActions")) or []

        for col in REQUIRED_COLUMNS:
            row.setdefault(col, None)

        normalized.append(row)

    df = pd.DataFrame(normalized)
    if df.empty:
        return pd.DataFrame(columns=REQUIRED_COLUMNS)

    df["EventTimeParsed"] = pd.to_datetime(df["EventTime"], errors="coerce", utc=True)
    try:
        df["EventTimeParsed"] = df["EventTimeParsed"].dt.tz_convert("Asia/Seoul")
    except Exception:
        pass
    df["EventDate"] = df["EventTimeParsed"].dt.date
    df["EventHour"] = df["EventTimeParsed"].dt.strftime("%Y-%m-%d %H:00")
    df["RiskScore"] = pd.to_numeric(df["RiskScore"], errors="coerce").fillna(0).astype(int)
    df["RiskLevel"] = df["RiskLevel"].fillna("LOW")
    df["RiskLevelKR"] = df["RiskLevel"].map(RISK_KR).fillna(df["RiskLevel"])

    # 서비스명은 signin.amazonaws.com → signin 식으로 짧게 표시
    df["Service"] = df["EventSource"].fillna("unknown").astype(str).str.replace(".amazonaws.com", "", regex=False)
    df["Actor"] = df["Actor"].fillna("-")
    df["SourceIP"] = df["SourceIP"].fillna("-")
    df["Region"] = df["Region"].fillna("-")
    return df


def apply_sidebar_filters(df: pd.DataFrame) -> pd.DataFrame:
    st.sidebar.header("필터")

    risk_options = [level for level in RISK_ORDER if level in set(df["RiskLevel"].dropna())]
    selected_risks = st.sidebar.multiselect(
        "위험도",
        options=risk_options,
        default=risk_options,
        format_func=lambda x: f"{RISK_KR.get(x, x)} ({x})",
    )

    event_options = sorted([x for x in df["EventName"].dropna().unique().tolist() if x])
    selected_events = st.sidebar.multiselect("이벤트 종류", options=event_options, default=[])

    actor_options = sorted([x for x in df["Actor"].dropna().unique().tolist() if x])
    selected_actors = st.sidebar.multiselect("행위자", options=actor_options, default=[])

    ip_keyword = st.sidebar.text_input("IP 검색", placeholder="예: 175.211")

    filtered = df.copy()
    if selected_risks:
        filtered = filtered[filtered["RiskLevel"].isin(selected_risks)]
    if selected_events:
        filtered = filtered[filtered["EventName"].isin(selected_events)]
    if selected_actors:
        filtered = filtered[filtered["Actor"].isin(selected_actors)]
    if ip_keyword.strip():
        filtered = filtered[filtered["SourceIP"].astype(str).str.contains(ip_keyword.strip(), case=False, na=False)]

    return filtered


def metric_card(label: str, value: str, caption: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-caption">{caption}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def risk_badge(level: str) -> str:
    css_class = RISK_BADGE_CLASS.get(level, "badge-info")
    label = RISK_KR.get(level, level)
    return f'<span class="badge {css_class}">{label}</span>'


def render_overview(df: pd.DataFrame) -> None:
    total = len(df)
    high_or_more = int(df["RiskLevel"].isin(["HIGH", "CRITICAL"]).sum())
    unique_ip = int(df[df["SourceIP"] != "-"]["SourceIP"].nunique())
    avg_risk = round(float(df["RiskScore"].mean()), 1) if total else 0
    latest_time = "-"
    if total and df["EventTimeParsed"].notna().any():
        latest_time = str(df["EventTimeParsed"].max()).replace("+09:00", " KST")

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        metric_card("전체 로그", f"{total:,}건", "수집·저장된 이벤트")
    with col2:
        metric_card("HIGH 이상", f"{high_or_more:,}건", "우선 검토 대상")
    with col3:
        metric_card("고유 IP", f"{unique_ip:,}개", "SourceIP 기준")
    with col4:
        metric_card("평균 위험 점수", f"{avg_risk}", "0~100점")
    with col5:
        metric_card("최근 이벤트", latest_time, "KST 기준 표시")

    st.divider()

    left, right = st.columns([1, 1])
    with left:
        st.subheader("위험도 분포")
        risk_counts = (
            df["RiskLevel"]
            .value_counts()
            .reindex(RISK_ORDER)
            .dropna()
            .rename_axis("RiskLevel")
            .reset_index(name="Count")
        )
        risk_counts["위험도"] = risk_counts["RiskLevel"].map(lambda x: f"{RISK_KR.get(x, x)} ({x})")
        st.bar_chart(risk_counts.set_index("위험도")["Count"])

    with right:
        st.subheader("시간대별 이벤트 추이")
        timeline = df.dropna(subset=["EventHour"]).groupby("EventHour").size().rename("Count")
        if timeline.empty:
            st.info("시간 데이터가 있는 로그가 없습니다.")
        else:
            st.line_chart(timeline)

    left2, right2 = st.columns([1, 1])
    with left2:
        st.subheader("이벤트 유형 Top 10")
        top_events = df["EventName"].value_counts().head(10).rename("Count")
        st.bar_chart(top_events)

    with right2:
        st.subheader("서비스별 로그 비율")
        top_services = df["Service"].value_counts().head(10).rename("Count")
        st.bar_chart(top_services)


def render_high_risk_events(df: pd.DataFrame) -> None:
    st.subheader("우선 확인해야 할 위험 이벤트")
    risk_df = df[df["RiskLevel"].isin(["CRITICAL", "HIGH", "MEDIUM"])].sort_values(
        ["RiskScore", "EventTimeParsed"], ascending=[False, False]
    )

    if risk_df.empty:
        st.success("현재 필터 기준으로 MEDIUM 이상 이벤트가 없습니다.")
        return

    for _, row in risk_df.head(20).iterrows():
        reasons = row.get("RiskReasons")
        if isinstance(reasons, list):
            reason_text = ", ".join(str(x) for x in reasons[:5])
        else:
            reason_text = str(reasons or "-")

        target_bits = []
        for key in ["TargetUser", "BucketName", "GroupId", "InstanceIds", "TrailName"]:
            value = row.get(key)
            if value and value != "None":
                target_bits.append(f"{key}: {value}")
        target_text = " / ".join(target_bits) if target_bits else "대상 필드 없음"

        st.markdown(
            f"""
            <div class="event-card">
                <div class="event-title">{risk_badge(row['RiskLevel'])} &nbsp; {row.get('EventName', '-')} · {row.get('RiskScore', 0)}점</div>
                <div class="event-meta">시간: {row.get('EventTime', '-')} · 행위자: {row.get('Actor', '-')} · IP: {row.get('SourceIP', '-')} · 리전: {row.get('Region', '-')}</div>
                <div class="event-meta">{target_text}</div>
                <div class="reason">판단 근거: {reason_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_ip_analysis(df: pd.DataFrame) -> None:
    st.subheader("IP 반복 활동 분석")
    records = df.to_dict("records")
    ip_results = analyze_ip_activity(records)

    if not ip_results:
        st.info("SourceIP가 있는 로그가 부족하여 IP 분석 결과가 없습니다.")
        return

    ip_df = pd.DataFrame(ip_results)
    ip_df["위험도"] = ip_df["risk_level"].map(lambda x: f"{RISK_KR.get(x, x)} ({x})")
    ip_df["대표 이벤트"] = ip_df["events"].apply(lambda items: ", ".join(pd.Series(items).value_counts().head(4).index.tolist()))
    ip_df["판단 근거"] = ip_df["reason"].apply(lambda items: ", ".join(items) if items else "-")

    st.dataframe(
        ip_df[[
            "SourceIP", "위험도", "final_risk_score", "total_count",
            "avg_risk_score", "max_risk_score", "high_count", "critical_count",
            "trusted_count", "대표 이벤트", "판단 근거",
        ]].rename(columns={
            "SourceIP": "IP",
            "final_risk_score": "최종점수",
            "total_count": "총 이벤트",
            "avg_risk_score": "평균점수",
            "max_risk_score": "최대점수",
            "high_count": "HIGH 수",
            "critical_count": "CRITICAL 수",
            "trusted_count": "정상IP 수",
        }),
        use_container_width=True,
        hide_index=True,
    )


def flatten_response_actions(df: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    for _, event in df.iterrows():
        actions = event.get("ResponseActions")
        if not isinstance(actions, list):
            continue

        for action in actions:
            if not isinstance(action, dict):
                continue
            result = action.get("result", {}) if isinstance(action.get("result"), dict) else {}
            rows.append({
                "EventTime": event.get("EventTime"),
                "EventName": event.get("EventName"),
                "Actor": event.get("Actor"),
                "SourceIP": event.get("SourceIP"),
                "RiskLevel": event.get("RiskLevel"),
                "RiskScore": event.get("RiskScore"),
                "ActionType": action.get("action_type"),
                "ActionStatus": action.get("status"),
                "DryRun": action.get("dry_run"),
                "ResultStatus": result.get("status"),
                "Message": result.get("message") or action.get("reason"),
                "ExecutedAt": action.get("executed_at"),
            })

    return pd.DataFrame(rows)


def render_response_actions(df: pd.DataFrame) -> None:
    st.subheader("자동 대응 이력")
    action_df = flatten_response_actions(df)

    if action_df.empty:
        st.info("저장된 ResponseActions가 없습니다. main.py를 실행하여 자동 대응 결과가 MongoDB에 저장되면 이 영역에 표시됩니다.")
        st.markdown(
            """
            <div class="small-muted">
            현재 SQLite 원본 로그만 있을 때는 실제 대응 이력이 없을 수 있습니다. 이 경우 이번 주차 보고서에는
            “대시보드 구조 구현 완료, MongoDB 분석 결과 연동 시 대응 이력 표시 가능”으로 설명하면 됩니다.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    st.dataframe(
        action_df.rename(columns={
            "EventTime": "이벤트 시간",
            "EventName": "이벤트",
            "Actor": "행위자",
            "SourceIP": "IP",
            "RiskLevel": "위험도",
            "RiskScore": "점수",
            "ActionType": "대응 유형",
            "ActionStatus": "대응 상태",
            "DryRun": "DRY_RUN",
            "ResultStatus": "실행 결과",
            "Message": "메시지",
            "ExecutedAt": "실행 시간",
        }),
        use_container_width=True,
        hide_index=True,
    )


def render_raw_logs(df: pd.DataFrame) -> None:
    st.subheader("로그 상세 조회")
    columns = [
        "EventTime", "RiskLevel", "RiskScore", "EventName", "Actor", "SourceIP", "Region",
        "EventSource", "TargetUser", "PolicyArn", "ErrorCode", "GroupId", "CidrIp",
        "FromPort", "ToPort", "InstanceIds", "BucketName", "TrailName",
    ]
    visible_columns = [col for col in columns if col in df.columns]
    table = df.sort_values("EventTimeParsed", ascending=False)[visible_columns].copy()
    table["RiskLevel"] = table["RiskLevel"].map(lambda x: f"{RISK_KR.get(x, x)} ({x})")

    st.dataframe(
        table.rename(columns={
            "EventTime": "시간",
            "RiskLevel": "위험도",
            "RiskScore": "점수",
            "EventName": "이벤트",
            "Actor": "행위자",
            "SourceIP": "IP",
            "Region": "리전",
            "EventSource": "서비스",
            "TargetUser": "대상 사용자",
            "PolicyArn": "정책 ARN",
            "ErrorCode": "오류",
            "GroupId": "보안그룹",
            "CidrIp": "CIDR",
            "FromPort": "시작 포트",
            "ToPort": "종료 포트",
            "InstanceIds": "인스턴스",
            "BucketName": "버킷",
            "TrailName": "Trail",
        }),
        use_container_width=True,
        hide_index=True,
    )


def main() -> None:
    set_page_style()

    st.markdown(
        """
        <div class="hero">
            <h1>Cloud AI Security Dashboard</h1>
            <p>CloudTrail 로그 수집 결과를 위험도, 이벤트 유형, IP 반복 활동, 자동 대응 이력 중심으로 시각화합니다.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    limit = st.sidebar.slider("조회할 최대 로그 수", min_value=50, max_value=5000, value=1000, step=50)

    st.sidebar.markdown("---")
    auto_refresh = st.sidebar.checkbox("자동 갱신", value=True)
    refresh_seconds = st.sidebar.selectbox(
        "갱신 주기",
        options=[5, 10],
        index=1,
        disabled=not auto_refresh,
        format_func=lambda sec: f"{sec}초",
    )
    if auto_refresh:
        st_autorefresh(interval=refresh_seconds * 1000, key="dashboard_auto_refresh")
        st.sidebar.caption(f"자동 갱신: {refresh_seconds}초마다 최신 데이터 확인")

    if st.sidebar.button("즉시 새로고침"):
        st.cache_data.clear()
        st.rerun()

    events, source, status = load_events(limit=limit)
    df = normalize_events(events)

    st.sidebar.caption(f"데이터 소스: {source}")
    st.sidebar.caption(status)

    if df.empty:
        st.warning("표시할 로그가 없습니다. 먼저 main.py를 실행해 CloudTrail 로그를 수집하거나 logs.db/MongoDB 데이터를 확인하세요.")
        return

    filtered_df = apply_sidebar_filters(df)

    if filtered_df.empty:
        st.warning("현재 필터 조건에 맞는 로그가 없습니다.")
        return

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "개요", "위험 이벤트", "IP 분석", "자동 대응", "로그 상세",
    ])

    with tab1:
        render_overview(filtered_df)
    with tab2:
        render_high_risk_events(filtered_df)
    with tab3:
        render_ip_analysis(filtered_df)
    with tab4:
        render_response_actions(filtered_df)
    with tab5:
        render_raw_logs(filtered_df)


if __name__ == "__main__":
    main()

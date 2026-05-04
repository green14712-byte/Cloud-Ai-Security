import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from datetime import datetime
import ipaddress


def is_external_ip(ip):
    if not ip:
        return 0

    try:
        ip_obj = ipaddress.ip_address(ip)
        return 0 if ip_obj.is_private else 1
    except ValueError:
        return 0


def preprocess(events):
    features = []

    for event in events:
        event_time_str = event.get("EventTime")

        try:
            event_time = datetime.fromisoformat(event_time_str)
            hour = event_time.hour
        except Exception:
            hour = 0

        dangerous_events = {
            "DeleteBucket",
            "DeleteUser",
            "StopInstances",
            "DetachUserPolicy",
            "TerminateInstances",
            "AttachUserPolicy",
            "PutUserPolicy",
            "DeleteUserPolicy",
            "CreateAccessKey",
            "AuthorizeSecurityGroupIngress"
        }

        event_name = event.get("EventName", "")
        is_dangerous = 1 if event_name in dangerous_events else 0

        is_error = 1 if event.get("ErrorCode") else 0
        is_night = 1 if hour <= 6 else 0

        actor = event.get("Actor")
        is_root = 1 if actor in ["root", "HIDDEN_DUE_TO_SECURITY_REASONS"] else 0

        source_ip = event.get("SourceIP")
        external_ip = is_external_ip(source_ip)

        features.append({
            "hour": hour,
            "is_dangerous": is_dangerous,
            "is_error": is_error,
            "is_night": is_night,
            "is_root": is_root,
            "is_external_ip": external_ip
        })

    df = pd.DataFrame(features)

    if df.empty:
        return None

    scaler = MinMaxScaler()
    df_scaled = scaler.fit_transform(df)

    return df_scaled
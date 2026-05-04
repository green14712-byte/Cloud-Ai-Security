import boto3
import json
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError

regions = [
    "ap-southeast-2",
    "ap-northeast-2",
    "us-east-1"
]

important_events = {
    "ConsoleLogin",
    "StartInstances",
    "StopInstances",
    "RunInstances",
    "TerminateInstances",
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress"
}

seen_event_ids = set()


def extract_request_details(parsed_event):
    request_params = parsed_event.get("requestParameters")

    if not isinstance(request_params, dict):
        request_params = {}

    details = {
        "TargetUser": request_params.get("userName"),
        "PolicyArn": request_params.get("policyArn"),
        "AccessKeyId": request_params.get("accessKeyId"),
        "GroupId": request_params.get("groupId"),
        "CidrIp": None,
        "FromPort": None,
        "ToPort": None,
        "IpProtocol": None,
        "InstanceIds": None
    }

    instances_set = request_params.get("instancesSet", {})
    if isinstance(instances_set, dict):
        items = instances_set.get("items", [])
        if isinstance(items, list):
            ids = []
            for item in items:
                if isinstance(item, dict) and item.get("instanceId"):
                    ids.append(item["instanceId"])
            if ids:
                details["InstanceIds"] = ",".join(ids)

    ip_permissions = request_params.get("ipPermissions", {})
    if isinstance(ip_permissions, dict):
        items = ip_permissions.get("items", [])
        if isinstance(items, list) and items:
            first_rule = items[0]
            if isinstance(first_rule, dict):
                details["FromPort"] = first_rule.get("fromPort")
                details["ToPort"] = first_rule.get("toPort")
                details["IpProtocol"] = first_rule.get("ipProtocol")

                ip_ranges = first_rule.get("ipRanges", {})
                if isinstance(ip_ranges, dict):
                    range_items = ip_ranges.get("items", [])
                    if isinstance(range_items, list) and range_items:
                        first_range = range_items[0]
                        if isinstance(first_range, dict):
                            details["CidrIp"] = first_range.get("cidrIp")

    return details


def collect_logs():
    collected = []

    for region in regions:
        try:
            client = boto3.client("cloudtrail", region_name=region)
            response = client.lookup_events(MaxResults=50)
            events = response.get("Events", [])

            for event in events:
                event_id = event.get("EventId")
                event_name = event.get("EventName")

                if event_id in seen_event_ids:
                    continue

                if event_name not in important_events:
                    continue

                seen_event_ids.add(event_id)

                details = {
                    "TargetUser": None,
                    "PolicyArn": None,
                    "AccessKeyId": None,
                    "GroupId": None,
                    "CidrIp": None,
                    "FromPort": None,
                    "ToPort": None,
                    "IpProtocol": None,
                    "InstanceIds": None
                }

                source_ip = None

                cloudtrail_event_str = event.get("CloudTrailEvent")

                if cloudtrail_event_str:
                    try:
                        parsed_event = json.loads(cloudtrail_event_str)
                        source_ip = parsed_event.get("sourceIPAddress")
                        details = extract_request_details(parsed_event)
                    except json.JSONDecodeError:
                        pass

                collected.append({
                    "EventId": event_id,
                    "EventName": event_name,
                    "EventTime": str(event.get("EventTime")),
                    "Actor": event.get("Username"),
                    "TargetUser": details["TargetUser"],
                    "PolicyArn": details["PolicyArn"],
                    "AccessKeyId": details["AccessKeyId"],
                    "GroupId": details["GroupId"],
                    "CidrIp": details["CidrIp"],
                    "FromPort": details["FromPort"],
                    "ToPort": details["ToPort"],
                    "IpProtocol": details["IpProtocol"],
                    "InstanceIds": details["InstanceIds"],
                    "SourceIP": source_ip,
                    "Region": region,
                    "EventSource": event.get("EventSource"),
                    "ErrorCode": event.get("ErrorCode")
                })

        except (ClientError, ConnectTimeoutError, EndpointConnectionError) as e:
            print(f"[{region}] AWS 연결/조회 오류:", e)
            continue

        except Exception as e:
            print(f"[{region}] 알 수 없는 오류:", e)
            continue

    return collected
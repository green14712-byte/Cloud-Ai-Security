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
    "RevokeSecurityGroupIngress",

    # CloudTrail 방어 회피
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",

    # S3 공개/삭제 관련
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeleteBucket"
}

seen_event_ids = set()


def extract_request_details(parsed_event):
    request_params = parsed_event.get("requestParameters")
    response_elements = parsed_event.get("responseElements")

    if not isinstance(request_params, dict):
        request_params = {}

    if not isinstance(response_elements, dict):
        response_elements = {}

    details = {
        "TargetUser": request_params.get("userName"),
        "PolicyArn": request_params.get("policyArn"),
        "AccessKeyId": request_params.get("accessKeyId"),
        "GroupId": request_params.get("groupId"),
        "CidrIp": None,
        "FromPort": None,
        "ToPort": None,
        "IpProtocol": None,
        "InstanceIds": None,
        "BucketName": request_params.get("bucketName") or request_params.get("bucket"),
        "TrailName": request_params.get("name") or request_params.get("trailName"),
        "SecurityGroupRuleId": None,
    }

    # CreateAccessKey 이벤트는 생성된 키 ID가 responseElements에 들어오는 경우가 많다.
    access_key = response_elements.get("accessKey")
    if isinstance(access_key, dict) and access_key.get("accessKeyId"):
        details["AccessKeyId"] = access_key.get("accessKeyId")
        details["TargetUser"] = details["TargetUser"] or access_key.get("userName")

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

    # 최신 EC2 이벤트는 responseElements에 securityGroupRuleId를 제공할 수 있다.
    sg_rule_set = response_elements.get("securityGroupRuleSet", {})
    if isinstance(sg_rule_set, dict):
        items = sg_rule_set.get("items", [])
        if isinstance(items, list) and items:
            first_rule = items[0]
            if isinstance(first_rule, dict):
                details["SecurityGroupRuleId"] = first_rule.get("securityGroupRuleId")
                details["GroupId"] = details["GroupId"] or first_rule.get("groupId")

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
                    "InstanceIds": None,
                    "BucketName": None,
                    "TrailName": None,
                    "SecurityGroupRuleId": None
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
                    "BucketName": details["BucketName"],
                    "TrailName": details["TrailName"],
                    "SecurityGroupRuleId": details["SecurityGroupRuleId"],
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
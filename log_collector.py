import boto3
import json
from botocore.config import Config
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

    # 자동 대응용 추가
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",

    "PutBucketPolicy",
    "PutBucketAcl",
    "DeleteBucket",

    # IAM Role 관련
    "CreateRole",
    "DeleteRole",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "DeleteRolePolicy",
    "AssumeRole",
    "UpdateAssumeRolePolicy"
}

seen_event_ids = set()

aws_config = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2}
)


def extract_actor(parsed_event, fallback_username):
    user_identity = parsed_event.get("userIdentity", {})

    user_type = user_identity.get("type")
    user_name = user_identity.get("userName")

    if user_type == "Root":
        return "root"

    if user_name:
        return user_name

    return fallback_username


def extract_request_details(parsed_event):
    request_params = parsed_event.get("requestParameters")
    response_elements = parsed_event.get("responseElements")

    if not isinstance(request_params, dict):
        request_params = {}

    if not isinstance(response_elements, dict):
        response_elements = {}

    details = {
        "TargetUser": None,
        "PolicyArn": None,
        "AccessKeyId": None,

        "GroupId": None,
        "SecurityGroupRuleId": None,
        "CidrIp": None,
        "FromPort": None,
        "ToPort": None,
        "IpProtocol": None,

        "InstanceIds": None,

        "TrailName": None,
        "TrailArn": None,

        "BucketName": None,

        "RoleName": None
    }

    # IAM User
    details["TargetUser"] = request_params.get("userName")
    details["PolicyArn"] = request_params.get("policyArn")

    # IAM Role
    details["RoleName"] = request_params.get("roleName")

    # Access Key
    details["AccessKeyId"] = request_params.get("accessKeyId")

    access_key = response_elements.get("accessKey")
    if isinstance(access_key, dict):
        details["AccessKeyId"] = access_key.get("accessKeyId", details["AccessKeyId"])
        details["TargetUser"] = access_key.get("userName", details["TargetUser"])

    # Security Group
    details["GroupId"] = request_params.get("groupId")

    security_group_rule_set = response_elements.get("securityGroupRuleSet", {})
    if isinstance(security_group_rule_set, dict):
        rule_items = security_group_rule_set.get("items", [])
        if isinstance(rule_items, list) and rule_items:
            first_rule = rule_items[0]
            if isinstance(first_rule, dict):
                details["SecurityGroupRuleId"] = first_rule.get("securityGroupRuleId")

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

    # EC2 Instance IDs
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

    # CloudTrail
    details["TrailName"] = (
        request_params.get("name")
        or request_params.get("trailName")
    )

    details["TrailArn"] = request_params.get("trailARN")

    # S3
    details["BucketName"] = (
        request_params.get("bucketName")
        or request_params.get("bucket")
    )

    return details


def extract_login_result(parsed_event):
    response_elements = parsed_event.get("responseElements", {})
    additional_data = parsed_event.get("additionalEventData", {})

    if not isinstance(response_elements, dict):
        response_elements = {}

    if not isinstance(additional_data, dict):
        additional_data = {}

    return {
        "ConsoleLoginResult": response_elements.get("ConsoleLogin"),
        "MFAUsed": additional_data.get("MFAUsed")
    }


def collect_logs():
    collected = []

    for region in regions:
        try:
            client = boto3.client(
                "cloudtrail",
                region_name=region,
                config=aws_config
            )

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
                    "SecurityGroupRuleId": None,
                    "CidrIp": None,
                    "FromPort": None,
                    "ToPort": None,
                    "IpProtocol": None,
                    "InstanceIds": None,
                    "TrailName": None,
                    "TrailArn": None,
                    "BucketName": None,
                    "RoleName": None
                }

                login_details = {
                    "ConsoleLoginResult": None,
                    "MFAUsed": None
                }

                source_ip = None
                actor = event.get("Username")
                user_type = None

                cloudtrail_event_str = event.get("CloudTrailEvent")

                if cloudtrail_event_str:
                    try:
                        parsed_event = json.loads(cloudtrail_event_str)

                        source_ip = parsed_event.get("sourceIPAddress")

                        user_identity = parsed_event.get("userIdentity", {})
                        if isinstance(user_identity, dict):
                            user_type = user_identity.get("type")

                        actor = extract_actor(parsed_event, event.get("Username"))
                        details = extract_request_details(parsed_event)
                        login_details = extract_login_result(parsed_event)

                    except json.JSONDecodeError:
                        pass

                collected.append({
                    "EventId": event_id,
                    "EventName": event_name,
                    "EventTime": str(event.get("EventTime")),

                    "Actor": actor,
                    "UserType": user_type,

                    "TargetUser": details["TargetUser"],
                    "PolicyArn": details["PolicyArn"],
                    "AccessKeyId": details["AccessKeyId"],

                    "GroupId": details["GroupId"],
                    "SecurityGroupRuleId": details["SecurityGroupRuleId"],
                    "CidrIp": details["CidrIp"],
                    "FromPort": details["FromPort"],
                    "ToPort": details["ToPort"],
                    "IpProtocol": details["IpProtocol"],

                    "InstanceIds": details["InstanceIds"],

                    "TrailName": details["TrailName"],
                    "TrailArn": details["TrailArn"],

                    "BucketName": details["BucketName"],

                    "RoleName": details["RoleName"],

                    "ConsoleLoginResult": login_details["ConsoleLoginResult"],
                    "MFAUsed": login_details["MFAUsed"],

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
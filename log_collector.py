#Cloudtrail 내의 로그 수집

#AWS를  Phython으로 제어하기 위한 라이브러리
import boto3
#AWS 오류 발생 시 잡아주는 예외 클래스 불러오기
from botocore.exceptions import ClientError

#로그 수집할 리전 목록
regions = [
    #시드니
    "ap-southeast-2",
    #서울
    "ap-northeast-2",
    #버지니아 북부
    "us-east-1"
]

#중요 이벤트 목록
important_events = {
    "ConsoleLogin",
    "StartInstances",
    "StopInstances",
    "RunInstances",
    "TerminateInstances",
    "CreateUser",
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress"
}

#이미 처리한 이벤트 저장
seen_event_ids = set()

# 함수로 감쌈 - 리스트에 저장 / 다른 파일로 넘겨 주기 가능
def collect_logs():
    collected = []

#리전 목록을 하나씩 돌면서 리전 로그 확인
    for region in regions:
        #코드 실행 중 오류 발생 시 except로 넘어가게함
        try:
            #해당 리전의 Cloudtrail로 연결되는 클라이언트 생성
            client = boto3.client("cloudtrail", region_name=region)
            #Cloudtrial에서 최근 이벤트 20개 가져오기
            response = client.lookup_events(MaxResults=50)
            #응답에서 Events키 값을 꺼내옴. 없다면 빈 리스트로 처리
            events = response.get("Events", [])
#가져온 이벤트 하나씩 확인
            for event in events:
                #각 이벤트의 이름과 ID 추출
                event_id = event.get("EventId")
                event_name = event.get("EventName")
#이미 처리한 이벤트면 스킵
                if event_id in seen_event_ids:
                    continue
                if event_name not in important_events:
                    continue
#처리한 이벤트에 seen_event_ids 추가하여 중복 방지
                seen_event_ids.add(event_id)
                #collected 리스트에 추가
                collected.append(event)

        except ClientError as e:
            print(f"[{region}] AWS 오류:", e)

# 수집한 이벤트 반환하여 main.py에서 사용가능하게 함
    return collected
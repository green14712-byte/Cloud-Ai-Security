#간단하게 앞 세 개 함수 작동 되는지 확인

#log_collector에서 collect_logs 함수 불러오기
from log_collector import collect_logs
#preprocessor에서 preprocess 함수 불러오기
from preprocessor import preprocess
#detector에서 detect_anomaly 함수 불러오기
from detector import detect_anomaly

#Cloudtrail에서 중요 이벤트 수집
#결과는 이벤트 딕셔너리로 반환
events = collect_logs()
print(f"수집된 이벤트: {len(events)}개")

#수집된 이벤트를 preprocess로 넘겨 숫자 데이터로 변환 / 결과는 정규화된 DataFrame
features = preprocess(events)
print("전처리 완료")

#이벤트가 0개라면 preprocess가 None으로 변환
if features is None:
    print("이벤트 없음")
else:
    #전처리된 데이터를 detect로 넘겨서 IForest 이상 탐지
    results = detect_anomaly(features)
    print(results)
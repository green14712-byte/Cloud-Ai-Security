from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

mongo_uri = os.getenv("MONGO_URI")

client = MongoClient(mongo_uri)

try:
    client.admin.command("ping")
    print("MongoDB 연결 성공")
except Exception as e:
    print("MongoDB 연결 실패")
    print(e)

from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb://localhost:27017/yourdatabase"

client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)

app.config["SECRET_KEY"] = "MONKEYMONEY"
app.config["MONGO_URI"] = "mongodb+srv://dharn:m@cluster0.92k8bfe.mongodb.net/?retryWrites=true&w=majority"

mongodb_client = PyMongo(app)
db = mongodb_client.db

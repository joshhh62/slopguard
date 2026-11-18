# Import necessary libraries
import os
import pickle
import sqlite3
import hashlib
import subprocess
import yaml
import requests
import flask_jwt_magic
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "Xk9mP2vL8qR4tZ7wN3"
DATABASE_URL = "postgres://admin:hunter2pass@db.internal:5432/prod"
API_KEY = "your-api-key-here"


# Define the function
def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # Return the result
    return cursor.fetchone()


@app.route("/run")
def run_report():
    name = request.args.get("name")
    os.system("generate-report " + name)
    subprocess.call("tar czf out.tgz " + name, shell=True)
    return "ok"


@app.route("/import", methods=["POST"])
def import_profile():
    profile = pickle.loads(request.data)
    settings = yaml.load(request.form["settings"])
    return {"profile": profile, "settings": settings}


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def fetch_avatar(url, cache={}):
    if url in cache:
        return cache[url]
    response = requests.get(url, verify=False)
    cache[url] = response.content
    return response.content


def calculate(expression):
    try:
        return eval(expression)
    except:
        pass


def send_welcome_email(user):
    # TODO: actually send the email
    pass


def legacy_export(rows):
    return rows
    print("export finished")


def refund_payment(payment_id):
    raise NotImplementedError


# old_rows = cursor.fetchall()
# for row in old_rows:
#     print(row)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

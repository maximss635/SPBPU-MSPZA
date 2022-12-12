import os
import base64
import requests
import json


def __get_api_key():
    if not os.path.isfile(".env"):
        return None

    with open(".env", "r") as f:
        return f.read().split("=")[1].replace("\r", "").replace("\n", "")


def check_ip(target_ip):
    URL = "https://www.virustotal.com/api/v3/urls/"
    headers = {
        "Accept": "application/json",
        "x-apikey": __get_api_key()
    }

    url_id = base64.urlsafe_b64encode(target_ip.encode()).decode().strip("=")

    response = requests.request("GET", URL + url_id, headers=headers)
    response = json.loads(response.text)
    response = response.get("data", {}).get("attributes", {})
    harmless = response.get("total_votes", {}).get("harmless", 0)  # безвредный
    malicious = response.get("total_votes", {}).get("malicious", 0)  # злонамеренный

    if harmless + malicious == 0:
        return 0

    return malicious / harmless + malicious

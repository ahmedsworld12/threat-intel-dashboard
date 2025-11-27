import os
import requests

VT_API = "https://www.virustotal.com/api/v3"

API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": API_KEY
}


def vt_lookup(ioc, ioc_type):
    if API_KEY is None:
        raise Exception("VT_API_KEY environment variable not set")

    # Map type to VT endpoints
    endpoints = {
        "ip": "ip_addresses",
        "domain": "domains",
        "url": "urls",
        "hash": "files"
    }

    if ioc_type not in endpoints:
        raise Exception(f"Unsupported IOC type: {ioc_type}")

    endpoint = endpoints[ioc_type]

    url = f"{VT_API}/{endpoint}/{ioc}"

    resp = requests.get(url, headers=headers)

    if resp.status_code == 404:
        return {"found": False}

    data = resp.json().get("data", {})
    attributes = data.get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    return {
        "found": True,
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
    }


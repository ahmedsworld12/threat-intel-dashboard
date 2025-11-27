import os
import requests

OTX_API = "https://otx.alienvault.com/api/v1"

API_KEY = os.getenv("OTX_API_KEY")

headers = {
    "X-OTX-API-KEY": API_KEY
}


def otx_lookup(ioc, ioc_type):
    if API_KEY is None:
        raise Exception("OTX_API_KEY environment variable not set")

    section = "general"

    url = f"{OTX_API}/indicators/{ioc_type}/{ioc}/{section}"

    resp = requests.get(url, headers=headers)

    if resp.status_code == 404:
        return {"found": False}

    data = resp.json()

    pulses = data.get("pulse_info", {}).get("pulses", [])

    pulse_count = len(pulses)

    malicious = pulse_count > 0

    return {
        "found": True,
        "pulse_count": pulse_count,
        "malicious": malicious
    }


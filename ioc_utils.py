import re

def parse_iocs(text):
    """Extract and classify IOCs from user input."""
    lines = text.split("\n")
    iocs = []

    ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_regex = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    url_regex = r"^https?://"
    hash_regex = r"^[A-Fa-f0-9]{32,}$"

    for line in lines:
        value = line.strip()
        if not value:
            continue

        # IP
        if re.match(ip_regex, value):
            iocs.append({"value": value, "type": "ip"})
            continue

        # URL
        if re.match(url_regex, value):
            iocs.append({"value": value, "type": "url"})
            continue

        # Domain
        if re.match(domain_regex, value):
            iocs.append({"value": value, "type": "domain"})
            continue

        # Hash
        if re.match(hash_regex, value):
            iocs.append({"value": value, "type": "hash"})
            continue

    return iocs


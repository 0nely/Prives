from urllib.parse import urlsplit


def build_api_version(url):
    path = urlsplit(url).path
    segments = path.strip("/").split("/")

    api_ver = ["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10",
               "beta", "preview", "alpha", "stable", "latest", "current",
               "v1beta", "v2beta", "v1alpha", "v2alpha",
               "v1-preview", "v2-preview", "v1-beta", "v2-beta",
               "2023-01-01", "2024-01-01", "2025-01-01", "2026-01-01"]

    if "api" not in segments:
        return {"techniques": "API Versioning", "msg": "Skipped API testing: '/api/' not found"}

    index = segments.index("api")

    if index + 1 < len(segments):
        segments.pop(index + 1)

    payloads = []

    for version in api_ver:
        new_segments = segments.copy()
        new_segments.insert(index + 1, version)
        payloads.append(url.split("://")[0] + "://" + url.split("://")[1].split("/", 1)[0] + "/" + "/".join(new_segments))

    return {"techniques": "API Versioning", "payload": payloads, "location": "url",}
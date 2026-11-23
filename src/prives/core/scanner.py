from urllib.parse import urlsplit

from prives.core.colors import colors
from prives.core.tasks import GENERATORS
from prives.core.requester import send_request
from prives.core.analyzer import analyze_response


def print_stage(message):
    print(f"{colors['yellow']}[+] {message}{colors['reset']}")


def print_finding(url, result):
    print(f"{colors['red']}[!] Anomaly: {url}{colors['reset']}")
    for key, value in result.items():
        if isinstance(value, dict) and value.get("match") is False:
            print(f"    {key}: {value}")


def is_local_url(url):
    hostname = (urlsplit(url).hostname or "").lower()
    return hostname in {"localhost", "127.0.0.1", "::1"}


def start_scanner(base_request, tasks):
    findings = []

    print_stage("Sending baseline request")
    baseline = send_request(base_request)

    if baseline is None:
        print_stage("Baseline request failed")
        return findings

    print(f"[+] Status: {baseline.status_code} | Length: {len(baseline.content)}")

    grouped = {}
    for task in tasks:
        grouped.setdefault(task["techniques"], []).append(task)

    for technique in GENERATORS:
        technique_tasks = grouped.get(technique, [])

        if not technique_tasks:
            print_stage(f"Skipping {technique}")
            continue

        print_stage(f"Test {technique}")

        for task in technique_tasks:
            added_headers = {
                key: value
                for key, value in task.get("headers", {}).items()
                if base_request["headers"].get(key) != value
            }

            if added_headers:
                payload = ", ".join(f"{key}: {value}" for key, value in added_headers.items())
                label = f"{task['url']} > {payload}"
            else:
                label = task["url"]

            response = send_request(task)

            if response is None:
                print(label)
                continue

            result = analyze_response(baseline, response)

            finding = {
                "technique": technique,
                "url": task["url"],
                "headers": task.get("headers", {}),
                "status_code": response.status_code,
                "analysis": result
            }

            findings.append(finding)

            anomalous = any(
                isinstance(value, dict) and value.get("match") is False
                for value in result.values()
            )

            if anomalous:
                print(f"\n{colors['red']}[!] {label} - Anomaly Detection{colors['reset']}")

                for key, value in result.items():
                    if isinstance(value, dict) and value.get("match") is False:
                        print(f"    {key}: {value}")

                print()
            else:
                print(label)

    return findings
import os
import threading
import time
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor

from prives.core.colors import colors
from prives.core.tasks import GENERATORS
from prives.core.requester import send_request
from prives.core.analyzer import analyze_response

print_lock = threading.Lock()
rate_lock = threading.Lock()
last_request_time = [0.0]
stop_event = threading.Event()


def print_stage(message):
    with print_lock:
        print(f"{colors['yellow']}[+] {message}{colors['reset']}")


def print_finding(url, result):
    with print_lock:
        print(f"{colors['red']}[!] Anomaly: {url}{colors['reset']}")
        for key, value in result.items():
            if isinstance(value, dict) and value.get("match") is False:
                print(f"    {key}: {value}")


def throttle(rate, delay):
    # ???
    min_interval = max(1 / rate if rate > 0 else 0, delay)

    with rate_lock:
        now = time.monotonic()
        wait = last_request_time[0] + min_interval - now
        if wait > 0:
            stop_event.wait(wait)
        last_request_time[0] = time.monotonic()


def process_task(base_request, technique, task, baseline, rate, delay):
    if stop_event.is_set():
        return None

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

    throttle(rate, delay)

    if stop_event.is_set():
        return None

    response = send_request(task)

    if response is None:
        with print_lock:
            print(label)
        return None

    result = analyze_response(baseline, response)

    finding = {
        "technique": technique,
        "url": task["url"],
        "headers": task.get("headers", {}),
        "status_code": response.status_code,
        "analysis": result
    }

    anomalous = any(
        isinstance(value, dict) and value.get("match") is False
        for value in result.values()
    )

    with print_lock:
        if anomalous:
            print(f"\n{colors['red']}[!] {label} - Anomaly Detection{colors['reset']}")
            for key, value in result.items():
                if isinstance(value, dict) and value.get("match") is False:
                    print(f"    {key}: {value}")
            print()
        else:
            print(label)

    return finding


def start_scanner(base_request, tasks, performance):
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

    threads = performance["threads"]
    rate = performance["rate"]
    delay = performance["delay"]

    for technique in GENERATORS:
        technique_tasks = grouped.get(technique, [])

        if not technique_tasks:
            print_stage(f"Skipping {technique}")
            continue

        print_stage(f"Test {technique}")

        executor = ThreadPoolExecutor(max_workers=threads)
        futures = [
            executor.submit(process_task, base_request, technique, task, baseline, rate, delay)
            for task in technique_tasks
        ]

        try:
            for future in futures:
                finding = future.result()
                if finding is not None:
                    findings.append(finding)
        except KeyboardInterrupt:
            stop_event.set()
            with print_lock:
                print(f"\n{colors['red']}[!] Scan interrupted by user. Killing process...{colors['reset']}")
            executor.shutdown(wait=False, cancel_futures=True)
            os._exit(130)

    return findings
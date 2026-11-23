import hashlib
import json

from importlib.resources import files


def load_sensitive_keys():
    path = files("prives.db").joinpath("sensitive_keys.txt")
    return {
        key.strip()
        for key in path.read_text(encoding="utf-8").splitlines()
        if key.strip()
    }


SENSITIVE_KEYS = load_sensitive_keys()


def get_content_type(response):
    return response.headers.get("Content-Type", "").lower()


def get_body(response):
    return response.content or b""


def get_hash(body):
    return hashlib.sha256(body).hexdigest()


def parse_json(response):
    try:
        return True, response.json()
    except ValueError:
        return False, None


def extract_sensitive_keys(data, path="$"):
    found = {}

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}"

            if key in SENSITIVE_KEYS:
                found[current_path] = value

            found.update(extract_sensitive_keys(value, current_path))

    elif isinstance(data, list):
        for index, value in enumerate(data):
            found.update(extract_sensitive_keys(value, f"{path}[{index}]"))

    return found


def analyze_sensitive_keys(baseline_data, response_data):
    baseline_keys = extract_sensitive_keys(baseline_data)
    response_keys = extract_sensitive_keys(response_data)

    newly_exposed = {}
    changed = {}
    missing = {}

    for path, value in response_keys.items():
        if path not in baseline_keys:
            newly_exposed[path] = True
        elif baseline_keys[path] != value:
            changed[path] = True

    for path in baseline_keys:
        if path not in response_keys:
            missing[path] = True

    return {
        "baseline_count": len(baseline_keys),
        "response_count": len(response_keys),
        "newly_exposed": newly_exposed,
        "changed": changed,
        "missing": missing,
        "match": not (newly_exposed or changed or missing)
    }


def analyze_response(baseline, response):
    baseline_body = get_body(baseline)
    response_body = get_body(response)

    baseline_type = get_content_type(baseline)
    response_type = get_content_type(response)

    baseline_json, baseline_data = parse_json(baseline)
    response_json, response_data = parse_json(response)

    result = {
        "status_code": {
            "baseline": baseline.status_code,
            "response": response.status_code,
            "match": baseline.status_code == response.status_code
        },
        "content_length": {
            "baseline": len(baseline_body),
            "response": len(response_body),
            "match": len(baseline_body) == len(response_body)
        },
        "content_type": {
            "baseline": baseline_type,
            "response": response_type,
            "match": baseline_type == response_type
        },
        "body": {
            "type": "json" if baseline_json and response_json else "text",
            "match": None
        },
        "sensitive_keys": None
    }

    if baseline_json and response_json:
        result["body"]["match"] = baseline_data == response_data
        result["sensitive_keys"] = analyze_sensitive_keys(
            baseline_data,
            response_data
        )
    else:
        result["body"]["match"] = (
            get_hash(baseline_body) == get_hash(response_body)
        )

    return result
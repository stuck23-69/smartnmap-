"""Scan one target with nmap.

Examples:
    python3 nmap_scans.py 192.168.1.10
    python3 nmap_scans.py 192.168.1.10 --quick
    python3 nmap_scans.py 192.168.1.10 --windows
    python3 nmap_scans.py 192.168.1.10 --ai --model qwen2.5:1.5b
"""

from __future__ import annotations

import shutil
import subprocess
import sys

FAST_FLAGS = ("-Pn", "-sS", "-T4", "-F")
WINDOWS_FLAGS = (
    "-Pn",
    "-sS",
    "-sV",
    "-T4",
    "--source-port",
    "53",
    "-p",
    "21,53,80,135,3389",
)
OTHER_FLAGS = ("-Pn", "-sS", "-sV", "-T4", "--top-ports", "100")

# Strings that showed up on the Windows lab hosts.
WINDOWS_MARKERS = (
    "135/tcp",
    "3389/tcp",
    "msrpc",
    "ms-wbt-server",
    "microsoft iis",
)


def require_nmap() -> None:
    """Stop immediately when the nmap binary is not available."""
    if shutil.which("nmap") is None:
        print("Error: nmap is not installed or not on PATH.", file=sys.stderr)
        sys.exit(1)


def run_nmap(target: str, flags: tuple[str, ...]) -> str:
    """Run one nmap command, print its output as it arrives, and return the text."""
    cmd = ["nmap", *flags, target]
    print("$ " + " ".join(cmd), flush=True)
    print(flush=True)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        print(f"Error: could not start nmap: {exc}", file=sys.stderr)
        sys.exit(1)

    lines: list[str] = []
    if proc.stdout is None:
        print("Error: could not read nmap output.", file=sys.stderr)
        sys.exit(1)
    for line in proc.stdout:
        print(line, end="", flush=True)
        lines.append(line)

    code = proc.wait()
    if code != 0:
        print(f"Error: nmap exited with status {code}.", file=sys.stderr)
        sys.exit(1)
    return "".join(lines)


def host_is_windows(output: str) -> bool:
    """True when the fast scan text contains a Windows marker."""
    lowered = output.lower()
    return any(marker in lowered for marker in WINDOWS_MARKERS)


def open_port_lines(output: str) -> list[str]:
    """Open-port rows from nmap. A later row for the same port replaces an earlier one."""
    order: list[str] = []
    by_port: dict[str, str] = {}
    for raw in output.splitlines():
        parts = raw.split()
        if len(parts) < 2 or parts[1] != "open":
            continue
        port = parts[0]
        if "/tcp" not in port and "/udp" not in port:
            continue
        if port not in by_port:
            order.append(port)
        by_port[port] = raw.strip()
    return [by_port[port] for port in order]


def port_numbers(port_lines: list[str]) -> str:
    """'80/tcp open http' lines become '80,443'."""
    numbers: list[str] = []
    for line in port_lines:
        number = line.split()[0].split("/")[0]
        if number not in numbers:
            numbers.append(number)
    return ",".join(numbers)


def next_command(target: str, windows: bool, port_lines: list[str], did_follow_up: bool) -> str:
    """One follow-up command. It is printed, not run."""
    if not did_follow_up:
        if windows:
            flags = " ".join(WINDOWS_FLAGS)
        else:
            flags = " ".join(OTHER_FLAGS)
        return f"nmap {flags} {target}"

    if not port_lines:
        return f"nmap -Pn -sS -sV -T4 --top-ports 1000 {target}"

    ports = port_numbers(port_lines)
    if windows:
        return f"nmap -Pn -sS -sV -sC -T4 --source-port 53 -p {ports} {target}"
    return f"nmap -Pn -sS -sV -sC -T4 -p {ports} {target}"


def print_summary(port_lines: list[str], follow_up: str) -> None:
    print()
    print("Summary")
    print("-------")
    if not port_lines:
        print("Open ports: none")
    else:
        print("Open ports:")
        for line in port_lines:
            print(f"  {line}")
    print(f"Next: {follow_up}")


def scan(target: str, quick: bool, windows: bool) -> tuple[str, bool]:
    """Run the chosen scans. Returns the combined output and the Windows flag."""
    if quick:
        output = run_nmap(target, FAST_FLAGS)
        return output, host_is_windows(output)

    if windows:
        output = run_nmap(target, WINDOWS_FLAGS)
        return output, True

    first = run_nmap(target, FAST_FLAGS)
    is_windows = host_is_windows(first)
    print()
    if is_windows:
        print("Windows markers found. Running the Windows port scan.")
        second_flags = WINDOWS_FLAGS
    else:
        print("No Windows markers found. Running a top-100 version scan.")
        second_flags = OTHER_FLAGS
    print()
    second = run_nmap(target, second_flags)
    return first + "\n" + second, is_windows


def ask_ai(output: str, model: str | None) -> None:
    """Send the real Nmap text to Ollama. Failures are reported inside ai_analysis."""
    from ai_analysis import DEFAULT_MODEL, analyze_scan, print_analysis

    analysis = analyze_scan(output, model=model or DEFAULT_MODEL)
    if analysis:
        print_analysis(analysis)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan one IP address or hostname with nmap.",
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Only run the fast scan (nmap -Pn -sS -T4 -F) and stop.",
    )
    parser.add_argument(
        "--windows",
        action="store_true",
        help="Skip detection and run only the Windows command.",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="After the scan, send the Nmap output to a local Ollama model.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Ollama model name. Used only with --ai (default: llama3.1).",
    )
    args = parser.parse_args()

    if args.quick and args.windows:
        print("Error: pass either --quick or --windows, not both.", file=sys.stderr)
        sys.exit(1)

    require_nmap()
    output, is_windows = scan(args.target, quick=args.quick, windows=args.windows)
    ports = open_port_lines(output)
    print_summary(
        ports,
        next_command(args.target, is_windows, ports, did_follow_up=not args.quick),
    )
    if args.ai:
        ask_ai(output, args.model)


if __name__ == "__main__":
    main()

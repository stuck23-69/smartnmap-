"""Build nmap commands for one target.

Example:
    python3 nmap_scans.py 192.168.1.10
    python3 nmap_scans.py scanme.nmap.org --ai
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ScanType = Literal["quick", "full", "version", "udp", "stealth"]


@dataclass
class ScanProfile:
    """One scan shape. The target is filled in later."""

    name: str
    scan_type: ScanType | None = None
    ports: str | None = None  # e.g. "22,80,443" or "1-1000"
    extra_args: str = ""
    # Exact nmap flags, in order. Used by the Windows profiles.
    flags: tuple[str, ...] | None = None


@dataclass
class NmapScan:
    name: str
    target: str
    scan_type: ScanType | None = None
    ports: str | None = None
    extra_args: str = ""
    flags: tuple[str, ...] | None = None

    def command(self) -> list[str]:
        """Build an nmap argv list (without shell)."""
        if self.flags:
            return ["nmap", *self.flags, self.target]

        cmd = ["nmap"]
        if self.scan_type == "quick":
            cmd.append("-F")
        elif self.scan_type == "full":
            cmd.extend(["-p-"])
        elif self.scan_type == "version":
            cmd.append("-sV")
        elif self.scan_type == "udp":
            cmd.append("-sU")
        elif self.scan_type == "stealth":
            cmd.extend(["-sS"])
        if self.ports:
            cmd.extend(["-p", self.ports])
        if self.extra_args:
            cmd.extend(self.extra_args.split())
        cmd.append(self.target)
        return cmd


# Used for every target.
COMMON_PROFILES: list[ScanProfile] = [
    ScanProfile("quick", "quick"),
    ScanProfile("common_ports", "version", ports="22,80,443,8080"),
    ScanProfile("full_tcp", "full", extra_args="-T4"),
    ScanProfile("stealth_syn", "stealth", ports="1-1024", extra_args="-Pn"),
]

# Indicators from testing: ports 135 or 3389, or services
# msrpc, ms-wbt-server, Microsoft IIS. The user passes --windows
# when they already know the host matches. This script does not run nmap.
WINDOWS_PROFILES: list[ScanProfile] = [
    ScanProfile(
        "windows_ports",
        flags=(
            "-Pn",
            "-sS",
            "-sV",
            "-T4",
            "--source-port",
            "53",
            "-p",
            "21,53,80,135,3389",
        ),
    ),
    ScanProfile(
        "windows_fast",
        flags=("-Pn", "-sS", "-sV", "-T4", "-F"),
    ),
]


def extra_profiles(target: str, windows: bool = False) -> list[ScanProfile]:
    """Windows commands. Returned only when --windows is set."""
    if windows and target:
        return list(WINDOWS_PROFILES)
    return []


def scans_for_target(target: str, windows: bool = False) -> list[NmapScan]:
    """Commands for this IP or hostname.

    --windows replaces the common list with WINDOWS_PROFILES.
    """
    if windows:
        profiles = extra_profiles(target, windows=True)
    else:
        profiles = list(COMMON_PROFILES)
    return [
        NmapScan(
            name=profile.name,
            target=target,
            scan_type=profile.scan_type,
            ports=profile.ports,
            extra_args=profile.extra_args,
            flags=profile.flags,
        )
        for profile in profiles
    ]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Build nmap commands for one IP address or hostname.",
        epilog="Example: python3 nmap_scans.py 192.168.1.10 --ai",
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "--windows",
        action="store_true",
        help=(
            "Host is Windows (ports 135 or 3389, or msrpc, ms-wbt-server, "
            "Microsoft IIS). Print the two Windows commands instead of the usual four."
        ),
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="After the scan output, ask a local Ollama model for a short analysis.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Ollama model name. Used only with --ai (default: llama3.1).",
    )
    args = parser.parse_args()

    # Normal output. This block does not know about the model.
    lines = []
    for scan in scans_for_target(args.target, windows=args.windows):
        line = f"{scan.name}: {' '.join(scan.command())}"
        print(line)
        lines.append(line)

    # Optional step. Import the AI module only when the user asked for it.
    if args.ai:
        from ai_analysis import DEFAULT_MODEL, analyze_scan, print_analysis

        summary = "Planned nmap commands:\n" + "\n".join(lines)
        analysis = analyze_scan(summary, model=args.model or DEFAULT_MODEL)
        if analysis:
            print_analysis(analysis)


if __name__ == "__main__":
    main()

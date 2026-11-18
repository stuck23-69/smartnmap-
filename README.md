# smartnmap

Scans one target with Nmap and prints a short summary.

The first scan is always:

```text
nmap -Pn -sS -T4 -F TARGET
```

If that output contains `135/tcp`, `3389/tcp`, `msrpc`, `ms-wbt-server`, or `Microsoft IIS`, the host is treated as Windows and the next command is:

```text
nmap -Pn -sS -sV -T4 --source-port 53 -p 21,53,80,135,3389 TARGET
```

Any other host gets:

```text
nmap -Pn -sS -sV -T4 --top-ports 100 TARGET
```

Nmap's output is printed as it arrives. At the end you get the open ports and one recommended next command. That next command is not run.

SYN scans (`-sS`) need root on Linux. The tool never uses `-sN`, `-sF`, `-sX`, `-sA`, or `-f`.

## Usage

```bash
python3 nmap_scans.py 10.65.166.153
python3 nmap_scans.py 10.65.166.153 --quick
python3 nmap_scans.py 10.65.166.153 --windows
python3 nmap_scans.py 10.65.166.153 --ai --model qwen2.5:1.5b
```

`--quick` runs only the fast scan and stops.

`--windows` skips detection and runs only the Windows command. Do not combine it with `--quick`.

If `nmap` is missing, or a scan exits non-zero, the tool prints an error and exits.

## AI

`--ai` needs Ollama running on your machine: https://ollama.com
The default model name is `llama3.1`. Pass `--model` to use another one, for example `qwen2.5:1.5b`.

The model sees the real Nmap output. If Ollama is down, the scan results still print.

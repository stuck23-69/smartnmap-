# smartnmap

Prints Nmap commands for one target. It does not run Nmap.

`--windows` uses the scan types that worked on the Windows lab hosts I tested. `--ai` sends the command list to a local Ollama model.

## Usage

```bash
python3 nmap_scans.py 10.65.166.153
python3 nmap_scans.py 10.65.166.153 --windows
python3 nmap_scans.py 10.65.166.153 --windows --ai --model qwen2.5:1.5b
```

Pass `--windows` when the host already looks like Windows: port 135 or 3389, or services `msrpc`, `ms-wbt-server`, or Microsoft IIS.

On those hosts, NULL, FIN, Xmas, ACK, and packet fragmentation were useless or hid open ports. A SYN scan with `--source-port 53` worked, so that is what `--windows` prints:

```text
nmap -Pn -sS -sV -T4 --source-port 53 -p 21,53,80,135,3389 TARGET
nmap -Pn -sS -sV -T4 -F TARGET
```

## AI

`--ai` needs Ollama running on your machine: https://ollama.com
The default model name is `llama3.1`. Pass `--model` to use another one, for example `qwen2.5:1.5b`.

If Ollama is down, the command list still prints.

The model only sees the planned commands, not live Nmap output.

## Not done yet

- Running the scans
- Detecting Windows without `--windows`
- Sending real Nmap results to the model

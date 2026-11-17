"""Optional local analysis of a scan summary via Ollama.

This module is not imported unless the user passes --ai.
Scanning code should stay in the main tool; call analyze_scan()
with a plain-text summary after the scan (or command list) is done.

To point this at another local model later, edit the settings below
or pass model= / endpoint= into analyze_scan().
To change what the model is asked, edit ANALYSIS_PROMPT.
"""

from __future__ import annotations

# --- settings (edit these) ---
OLLAMA_HOST = "http://localhost:11434"
GENERATE_PATH = "/api/generate"  # Ollama's simple one-shot endpoint
DEFAULT_MODEL = "llama3.1"
REQUEST_TIMEOUT_SECONDS = 120

# The only prompt sent to the model. {summary} is filled in at call time.
ANALYSIS_PROMPT = """You are reviewing the text summary of an nmap scan.

Scan summary:
{summary}

Reply in three short sections:
1. Analysis — what these findings show
2. Interesting points — anything unusual or worth a closer look
3. Next steps — follow-up nmap commands or ways to improve the scan

Stay concise and use only the summary above.
"""


def build_prompt(scan_summary: str) -> str:
    """Fill the prompt template. Edit ANALYSIS_PROMPT, not this function."""
    return ANALYSIS_PROMPT.format(summary=scan_summary.strip())


def analyze_scan(
    scan_summary: str,
    model: str = DEFAULT_MODEL,
    endpoint: str | None = None,
) -> str | None:
    """Send a scan summary to a local Ollama model and return its reply.

    Returns the reply text, or None if the model cannot be reached.
    Errors are printed here so the caller can keep going.
    """
    # Imported here so the rest of the tool runs without this library.
    try:
        import requests
    except ImportError:
        print("AI analysis skipped: the 'requests' library is not installed.")
        return None

    url = endpoint or f"{OLLAMA_HOST}{GENERATE_PATH}"
    payload = {
        "model": model,
        "prompt": build_prompt(scan_summary),
        "stream": False,
    }

    try:
        response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException:
        print("AI analysis skipped: Ollama is not running or not reachable at " + url)
        return None

    if response.status_code != 200:
        # Ollama uses 404 when the model name is not installed.
        detail = ""
        try:
            detail = (response.json().get("error") or "").strip()
        except ValueError:
            detail = ""
        if detail:
            print(f"AI analysis skipped: {detail}")
        else:
            print(f"AI analysis skipped: Ollama returned HTTP {response.status_code}.")
        return None

    try:
        body = response.json()
    except ValueError:
        print("AI analysis skipped: Ollama's reply was not valid JSON.")
        return None

    # /api/generate puts the text in "response".
    # If you switch to /api/chat, use body["message"]["content"] instead.
    text = (body.get("response") or "").strip()
    if not text:
        print("AI analysis skipped: the model returned an empty response.")
        return None
    return text


def print_analysis(text: str) -> None:
    """Print the model reply apart from the normal scan output."""
    line = "=" * 60
    print()
    print(line)
    print("AI analysis (local model)")
    print(line)
    print(text)
    print(line)

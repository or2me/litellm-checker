# litellm-check

Incident-response-safe detection of compromised `litellm` installations.
**Filesystem inspection only** — no suspect interpreter is ever executed.

## Why Filesystem-Only?

Versions 1.82.7 and 1.82.8 of `litellm` shipped malicious code:

| Version | Payload                               | Trigger                                        |
|---------|---------------------------------------|------------------------------------------------|
| 1.82.7  | `litellm/proxy/proxy_server.py`       | `import litellm.proxy`                         |
| 1.82.8  | `litellm_init.pth` in `site-packages` | **Any** Python startup (`python`, `pip`, etc.) |

Running `python`, `pip`, or any entrypoint from an affected environment
**executes the payload**.  These tools avoid that entirely — they read package
metadata and directory listings as ordinary files.

See [BerriAI/litellm#24512](https://github.com/BerriAI/litellm/issues/24512).

## Tools

### `safe_litellm_detector.py` — single-target detector

Point it at a venv, conda env, or `site-packages` directory:

```bash
python3 safe_litellm_detector.py /path/to/venv
python3 safe_litellm_detector.py /path/to/site-packages --json
python3 safe_litellm_detector.py ~/work --recursive
python3 safe_litellm_detector.py /opt/envs --strict-1827 --quiet
```

### `audit_litellm.py` — fleet scanner

Walks `~/projects`, `~/work`, any extra CLI paths, and every global Python
installation:

```bash
python3 audit_litellm.py
python3 audit_litellm.py ~/src --json
python3 audit_litellm.py --strict-1827 --quiet
```

## Classification Model

| Classification            | Meaning                                                                                                                  |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **clean**                 | No `litellm` artifacts found                                                                                             |
| **suspicious**            | `litellm` present but no high-confidence IOCs (e.g. benign version, malformed metadata, missing dist-info)               |
| **compromised-candidate** | Matches known IOCs: version 1.82.8, `litellm_init.pth`, RECORD references `.pth`, or version 1.82.7 with `--strict-1827` |

## What It Checks

For every `site-packages` directory:

| Artifact                       | Signal                          |
|--------------------------------|---------------------------------|
| `litellm/` directory           | Package present                 |
| `litellm-*.dist-info/METADATA` | Version extraction              |
| `litellm-*.dist-info/RECORD`   | Manifest reference to `.pth`    |
| `litellm_init.pth`             | **Backdoor** (1.82.8 indicator) |
| Multiple `dist-info` dirs      | Suspicious (version conflict)   |
| Missing / malformed metadata   | Suspicious                      |

## Exit Codes

| Code | Meaning               |
|------|-----------------------|
| `0`  | clean                 |
| `1`  | suspicious            |
| `2`  | compromised-candidate |
| `3`  | operational error     |

## Sample Output

### Human-readable

```
Target: /opt/app/.venv
  ✘ /opt/app/.venv/lib/python3.11/site-packages
    Status: compromised-candidate
    Reasons:
      - version=1.82.8
      - litellm_init.pth present
      - RECORD mentions litellm_init.pth
    Version: 1.82.8
    litellm_init.pth BACKDOOR PRESENT
    RECORD references litellm_init.pth
```

### JSON (`--json`)

```json
[
  {
    "target": "/opt/app/.venv",
    "site_packages": [
      {
        "path": "/opt/app/.venv/lib/python3.11/site-packages",
        "litellm_present": true,
        "version": "1.82.8",
        "pth_present": true,
        "record_mentions_pth": true,
        "classification": "compromised-candidate",
        "reasons": ["version=1.82.8", "litellm_init.pth present", "RECORD mentions litellm_init.pth"]
      }
    ]
  }
]
```

## Architecture

```
safe_litellm_detector.py                audit_litellm.py
┌───────────────────────┐         ┌──────────────────────────┐
│ discover_site_packages│◄─────── │ RepoVenvDiscovery        │
│ inspect_site_packages │◄─────── │ GlobalPythonDiscovery    │
│ classify()            │         │ Auditor                  │
│ scan_target()         │         │ print_report()           │
│ format_report_json()  │         │ print_json_report()      │
└───────────────────────┘         └──────────────────────────┘
     core detector                   fleet-scanning wrapper
```

## Testing

```bash
# All tests
python3 -m unittest test_detector test_audit -v

# Detector only (42 tests)
python3 -m unittest test_detector -v

# Fleet scanner only (14 tests)
python3 -m unittest test_audit -v
```

## Requirements

- Python 3.10+
- Standard library only — no third-party dependencies
- **Zero subprocess calls** — safe by design
- Cross-platform: macOS, Linux, Windows

# litellm-check

Incident-response-safe detection of compromised `litellm` installations.
Filesystem inspection only — no suspect interpreter is ever executed.

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

---

## Quick Start

```bash
# Scan your entire home folder — finds every venv, conda env, IDE cache, and global install
python3 safe_litellm_detector.py ~ --recursive

# Or let the fleet scanner check all the common places automatically
python3 audit_litellm.py
```

## Two Tools

### `safe_litellm_detector.py` — point-and-shoot detector

Accepts any path: a single venv, a `site-packages` dir, or a whole directory
tree with `--recursive`.

```bash
python3 safe_litellm_detector.py /path/to/.venv
python3 safe_litellm_detector.py ~/projects/my-app --recursive
python3 safe_litellm_detector.py /mnt/shared --recursive --json
python3 safe_litellm_detector.py ~ --recursive --no-global      # skip system Pythons
python3 safe_litellm_detector.py ~/code --recursive --quiet && echo "clean"
```

### `audit_litellm.py` — zero-argument fleet scanner

Scans default project locations, IDE caches, standalone venvs, and global
Python installations with no arguments. Pass extra directories to widen the
search.

```bash
python3 audit_litellm.py
python3 audit_litellm.py ~/src /mnt/shared-envs --json
python3 audit_litellm.py --strict-1827 --quiet
```

Default scan roots:

| Platform      | Directories                                                                    |
|---------------|--------------------------------------------------------------------------------|
| macOS / Linux | `~/projects`, `~/work`, `~` (IDE caches & standalone venvs), global Pythons    |
| Windows       | `~/projects`, `~/work`, `C:\ws`, `C:\ws_*` (all caps variants), global Pythons |

### Which tool should I use?

| Scenario                                  | Recommended                                 |
|-------------------------------------------|---------------------------------------------|
| Quick check of the most common places     | `audit_litellm.py`                          |
| Thorough scan of `~` or an arbitrary path | `safe_litellm_detector.py PATH --recursive` |
| CI / scripting (exit-code only)           | either tool with `--quiet`                  |
| Machine-readable output                   | either tool with `--json`                   |

Both tools discover the same union of environments and deduplicate by resolved
path, so overlapping scan roots are safe.

---

## Classification

| Result                    | Meaning                                                                                     |
|---------------------------|---------------------------------------------------------------------------------------------|
| **clean**                 | No `litellm` artifacts found.                                                               |
| **suspicious**            | `litellm` present but no high-confidence IOCs (benign version, missing/malformed metadata). |
| **compromised-candidate** | Known IOCs: version 1.82.8, `litellm_init.pth`, RECORD→`.pth`, or 1.82.7 + `--strict-1827`. |

### Inspected artifacts

| Artifact                       | Signal                          |
|--------------------------------|---------------------------------|
| `litellm/` directory           | Package present                 |
| `litellm-*.dist-info/METADATA` | Version extraction              |
| `litellm-*.dist-info/RECORD`   | Manifest reference to `.pth`    |
| `litellm_init.pth`             | **Backdoor** (1.82.8 indicator) |
| Multiple `dist-info` dirs      | Suspicious (version conflict)   |
| Missing / malformed metadata   | Suspicious                      |

### Exit codes

| Code | Meaning               |
|------|-----------------------|
| `0`  | clean                 |
| `1`  | suspicious            |
| `2`  | compromised-candidate |
| `3`  | operational error     |

---

## Output Examples

<details>
<summary>Human-readable</summary>

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

</details>

<details>
<summary>JSON (<code>--json</code>)</summary>

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
        "reasons": [
          "version=1.82.8",
          "litellm_init.pth present",
          "RECORD mentions litellm_init.pth"
        ]
      }
    ]
  }
]
```

</details>

---

## CLI Reference

### `safe_litellm_detector.py [OPTIONS] TARGET [TARGET ...]`

| Flag            | Description                                                               |
|-----------------|---------------------------------------------------------------------------|
| `TARGET`        | Paths to inspect — venv roots, `site-packages` dirs, or directory trees.  |
| `--recursive`   | Recursively find all `site-packages` under each target; includes globals. |
| `--no-global`   | Skip global Python installs (only meaningful with `--recursive`).         |
| `--json`        | Emit JSON instead of human-readable text.                                 |
| `--strict-1827` | Treat version 1.82.7 as **compromised-candidate** instead of suspicious.  |
| `--quiet`       | Suppress output; exit code only.                                          |

### `audit_litellm.py [OPTIONS] [DIR ...]`

| Flag            | Description                                                              |
|-----------------|--------------------------------------------------------------------------|
| `DIR`           | Extra directories to scan beyond the defaults.                           |
| `--json`        | Emit JSON instead of human-readable text.                                |
| `--strict-1827` | Treat version 1.82.7 as **compromised-candidate** instead of suspicious. |
| `--quiet`       | Suppress output; exit code only.                                         |

---

## Architecture

```
safe_litellm_detector.py                  audit_litellm.py
┌──────────────────────────────┐    ┌──────────────────────────┐
│ discover_site_packages       │◄───│ RepoVenvDiscovery        │
│ inspect_site_packages        │◄───│ StandaloneVenvDiscovery  │
│ discover_global_site_packages│◄───│ GlobalPythonDiscovery    │
│ classify()                   │    │ Auditor                  │
│ scan_target()                │    │ print_report()           │
│ format_report_json()         │    │ print_json_report()      │
└──────────────────────────────┘    └──────────────────────────┘
     core detector                    fleet-scanning wrapper
```

## Testing

```bash
python3 -m unittest test_detector test_audit -v   # all 66 tests
python3 -m unittest test_detector -v              # detector only (42)
python3 -m unittest test_audit -v                 # fleet scanner only (24)
```

## Requirements

Python 3.10+ · standard library only · zero subprocess calls · cross-platform (macOS, Linux, Windows)

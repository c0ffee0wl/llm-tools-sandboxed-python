# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An `llm` CLI plugin that provides secure Python code execution inside a bubblewrap (bwrap) sandbox. Registered as the `execute_python` tool via `@llm.hookimpl`. Requires Linux with bubblewrap installed (`apt-get install bubblewrap`).

## Commands

```bash
pip install -e ".[test]"       # Install with test deps
pytest tests/                  # Run all tests
pytest tests/ -k test_name     # Run a single test
ruff check .                   # Lint
ruff format .                  # Format
```

## Architecture

Single-module plugin (`llm_tools_sandboxed_python.py`) with one public function: `execute_python(code, cwd)`.

**Execution flow:** User code is wrapped in a template that captures stdout/stderr and enforces RLIMIT_FSIZE (10MB/file), then executed inside a bubblewrap sandbox with read-only filesystem, no network, isolated namespaces (PID/cgroup/IPC/UTS/net), and all capabilities dropped. Only `/tmp` is writable (mapped to a host output directory). Results are returned as JSON with stdout, stderr, exit_code, and any files created.

**Template injection safety:** The wrapper template uses `__SANDBOX_*__` placeholder strings (replaced via `str.replace`) instead of Python format strings. This prevents user code containing `{}` (dicts, f-strings, sets) from breaking template substitution.

**Variable namespace:** All internal wrapper variables use `__sbx_*__` prefix to avoid collisions with user code.

**CWD validation:** Rejects relative paths and `/tmp`, `/var`, `/run` (these are sandbox-internal mounts). Root `/` is allowed.

**Output handling:** Files written to `/tmp` in the sandbox persist to `/tmp/llm-sandbox-output/{id}/` on the host. Files under 10KB have contents included inline in the JSON response; larger/binary files get metadata only.

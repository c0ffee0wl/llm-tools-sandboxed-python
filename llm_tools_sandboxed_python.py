"""
LLM plugin for executing Python code in a sandboxed environment using bubblewrap.

This plugin provides secure Python code execution by isolating processes in a sandbox where:
- No files on the host system can be modified (read-only filesystem)
- No network access is possible
- Commands run in an isolated namespace environment
- Files created in /tmp persist to a host directory and are returned as metadata
- Individual file size limited to 10MB (kernel-enforced via RLIMIT_FSIZE)
"""

import subprocess
import os
import json
import uuid
import shutil
import llm


# Maximum file size (10MB) - enforced by RLIMIT_FSIZE in sandbox
MAX_FILE_SIZE = 10 * 1024 * 1024

# Maximum file size to include content preview (10KB)
PREVIEW_LIMIT = 10 * 1024

# Base directory for sandbox outputs
OUTPUT_BASE_DIR = "/tmp/llm-sandbox-output"


# Simplified wrapper - only captures stdout/stderr, no file handling
# File handling happens on host after sandbox exits
# NOTE: Uses __SANDBOX_*__ placeholders instead of {format} to avoid
# conflicts with user code containing curly braces (dicts, f-strings, etc.)
WRAPPER_TEMPLATE = '''
import sys as __sbx_sys__
import json as __sbx_json__
import resource as __sbx_resource__
from io import StringIO as __sbx_StringIO__

# Enforce 10MB per-file limit (kernel-enforced, cannot be bypassed)
__sbx_resource__.setrlimit(__sbx_resource__.RLIMIT_FSIZE, (__SANDBOX_MAX_FILE_SIZE__, __SANDBOX_MAX_FILE_SIZE__))

# Capture stdout/stderr
__sbx_stdout__ = __sbx_StringIO__()
__sbx_stderr__ = __sbx_StringIO__()
__sbx_orig_stdout__ = __sbx_sys__.stdout
__sbx_orig_stderr__ = __sbx_sys__.stderr
__sbx_sys__.stdout = __sbx_stdout__
__sbx_sys__.stderr = __sbx_stderr__

__sbx_exit__ = 0
try:
    # === USER CODE START ===
__SANDBOX_USER_CODE__
    # === USER CODE END ===
except SystemExit as __sbx_e__:
    # sys.exit() with no args sets code=None, which means success (0)
    # sys.exit(0) sets code=0, sys.exit(1) sets code=1, etc.
    # sys.exit("error msg") sets code to a string (treat as 1)
    if __sbx_e__.code is None:
        __sbx_exit__ = 0
    elif isinstance(__sbx_e__.code, int):
        __sbx_exit__ = __sbx_e__.code
    else:
        __sbx_exit__ = 1
except Exception as __sbx_e__:
    __sbx_sys__.stderr.write(f"{type(__sbx_e__).__name__}: {__sbx_e__}\\n")
    import traceback as __sbx_tb__
    __sbx_tb__.print_exc(file=__sbx_sys__.stderr)
    __sbx_exit__ = 1

# Restore stdout/stderr and output result
__sbx_sys__.stdout = __sbx_orig_stdout__
__sbx_sys__.stderr = __sbx_orig_stderr__

print(__sbx_json__.dumps({
    "stdout": __sbx_stdout__.getvalue(),
    "stderr": __sbx_stderr__.getvalue(),
    "exit_code": __sbx_exit__
}))
'''


def execute_python(code: str) -> str:
    """
    Execute Python code in a secure bubblewrap sandbox.

    The sandbox provides:
    - Read-only access to entire host filesystem (visible but not modifiable)
    - No network access
    - Isolated PID, IPC, and cgroup namespaces
    - Writable /tmp that persists to host for file output
    - 10MB per-file size limit (kernel-enforced via RLIMIT_FSIZE)
    - Access to installed Python packages (read-only)

    Args:
        code: Python code to execute (multi-line supported)

    Returns:
        JSON string with stdout, stderr, exit_code, output_dir, and file metadata.
        Small text files (< 10KB) include content directly.
    """

    uid = os.getuid()

    # Create persistent output directory
    output_id = uuid.uuid4().hex[:12]
    os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)
    output_dir = os.path.join(OUTPUT_BASE_DIR, output_id)
    os.makedirs(output_dir)

    # Indent user code to fit in the wrapper's try block
    indented_code = '\n'.join('    ' + line if line.strip() else line
                              for line in code.split('\n'))

    # Create the wrapped script (using replace() to avoid conflicts with user's {})
    wrapped_code = (WRAPPER_TEMPLATE
        .replace('__SANDBOX_USER_CODE__', indented_code)
        .replace('__SANDBOX_MAX_FILE_SIZE__', str(MAX_FILE_SIZE)))

    # Write script to output directory (will be in /tmp inside sandbox)
    script_name = '_sandbox_script.py'
    script_path = os.path.join(output_dir, script_name)
    with open(script_path, 'w') as f:
        f.write(wrapped_code)

    try:
        # Build the secure bubblewrap command
        bwrap_args = [
            'bwrap',

            # Die if parent process dies
            '--die-with-parent',

            # Mount entire filesystem as read-only
            '--ro-bind', '/', '/',

            # Mount /dev and /proc for command functionality
            '--dev', '/dev',
            '--proc', '/proc',

            # Bind output directory as /tmp (writable, persistent)
            '--bind', output_dir, '/tmp',

            # Other tmpfs for system directories
            '--tmpfs', '/var',
            '--tmpfs', '/run',
            '--dir', f'/run/user/{uid}',

            # Isolate specific namespaces
            '--unshare-pid',     # Isolate process namespace
            '--unshare-cgroup',  # Isolate cgroup namespace
            '--unshare-ipc',     # Isolate IPC namespace
            '--unshare-net',     # Block network access

            # Drop all capabilities for maximum security
            '--cap-drop', 'ALL',

            # Clear environment for isolation
            '--clearenv',

            # Set essential environment variables
            '--setenv', 'PATH', os.environ.get('PATH', '/usr/bin:/bin:/usr/sbin:/sbin'),
            '--setenv', 'HOME', '/tmp',
            '--setenv', 'USER', os.environ.get('USER', 'sandbox'),
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
            '--setenv', 'PYTHONUNBUFFERED', '1',
        ]

        # Add safe display/locale environment variables
        safe_env_vars = ['LANG', 'COLORTERM']
        for var in safe_env_vars:
            if var in os.environ:
                bwrap_args.extend(['--setenv', var, os.environ[var]])

        # Add all LC_* locale variables
        for var, value in os.environ.items():
            if var.startswith('LC_'):
                bwrap_args.extend(['--setenv', var, value])

        # Add final arguments
        bwrap_args.extend([
            '--chdir', '/tmp',
            '--new-session',
            '--',
            'python3', f'/tmp/{script_name}'
        ])

        # Execute the sandboxed command
        result = subprocess.run(
            bwrap_args,
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )

        # Parse wrapper output
        try:
            data = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            data = {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }

        # Add bwrap stderr if present
        if result.stderr:
            data["stderr"] = data.get("stderr", "") + "\n[bwrap]: " + result.stderr.strip()

        # Delete the script file
        try:
            os.unlink(script_path)
        except OSError:
            pass

        # Collect file metadata from output directory
        files = {}
        for name in os.listdir(output_dir):
            if name == script_name:
                continue  # Skip our script (shouldn't exist, but just in case)

            path = os.path.join(output_dir, name)
            if not os.path.isfile(path):
                continue

            size = os.path.getsize(path)
            file_info = {
                "path": path,
                "size": size
            }

            # Include content for small text files
            if size <= PREVIEW_LIMIT:
                try:
                    with open(path, 'r') as f:
                        file_info["content"] = f.read()
                except UnicodeDecodeError:
                    file_info["binary"] = True
            elif size > MAX_FILE_SIZE:
                # This shouldn't happen due to RLIMIT_FSIZE, but handle it
                file_info["warning"] = "exceeds 10MB limit"

            files[name] = file_info

        # Check if output directory has any content (files or subdirectories)
        remaining_items = os.listdir(output_dir)
        has_content = bool(files) or bool(remaining_items)

        # Add output directory and files to result
        if has_content:
            data["output_dir"] = output_dir
            if files:
                data["files"] = files
        else:
            # Truly empty, clean up
            try:
                os.rmdir(output_dir)
            except OSError:
                pass

        return json.dumps(data, indent=2)

    except subprocess.TimeoutExpired:
        # Clean up on timeout
        _cleanup_output_dir(output_dir)
        return json.dumps({
            "stdout": "",
            "stderr": "Error: Command timed out after 60 seconds",
            "exit_code": -1
        }, indent=2)

    except FileNotFoundError:
        _cleanup_output_dir(output_dir)
        return json.dumps({
            "stdout": "",
            "stderr": "Error: bubblewrap (bwrap) not found. Please install: apt-get install bubblewrap",
            "exit_code": -1
        }, indent=2)

    except Exception as e:
        _cleanup_output_dir(output_dir)
        return json.dumps({
            "stdout": "",
            "stderr": f"Error executing code: {str(e)}",
            "exit_code": -1
        }, indent=2)


def _cleanup_output_dir(output_dir: str) -> None:
    """Remove output directory and its contents (including subdirectories)."""
    try:
        shutil.rmtree(output_dir, ignore_errors=True)
    except Exception:
        pass


@llm.hookimpl
def register_tools(register):
    """Register the sandboxed Python execution tool."""
    register(execute_python)

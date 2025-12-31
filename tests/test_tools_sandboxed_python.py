"""
Tests for the sandboxed Python execution plugin.
"""

import json
import os
import pytest
from llm.plugins import pm
from llm_tools_execute_python import execute_python


def test_plugin_is_installed():
    """Verify the plugin is properly installed."""
    names = [mod.__name__ for mod in pm.get_plugins()]
    assert "llm_tools_execute_python" in names


def test_basic_execution():
    """Test basic Python code execution in sandbox."""
    result = execute_python("print('Hello from sandbox')")
    data = json.loads(result)
    assert "Hello from sandbox" in data["stdout"]
    assert data["exit_code"] == 0


def test_multiline_code():
    """Test multi-line Python scripts execute correctly."""
    code = '''
x = 5
y = 10
result = x + y
print(f"Result: {result}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "Result: 15" in data["stdout"]
    assert data["exit_code"] == 0


def test_imports_work():
    """Test that standard library imports work."""
    code = '''
import os
import sys
import json
print(f"Python version: {sys.version_info.major}.{sys.version_info.minor}")
print(f"CWD: {os.getcwd()}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "Python version:" in data["stdout"]
    assert data["exit_code"] == 0


def test_filesystem_readonly():
    """Test that filesystem is properly isolated (read-only)."""
    code = '''
try:
    with open('/etc/test_file', 'w') as f:
        f.write('test')
    print("FAIL: Write succeeded")
except (PermissionError, OSError) as e:
    print(f"PASS: {type(e).__name__}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "PASS:" in data["stdout"]


def test_network_blocked():
    """Test that network access is blocked."""
    code = '''
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('8.8.8.8', 53))
    print("FAIL: Network access succeeded")
except (OSError, socket.error) as e:
    print(f"PASS: Network blocked - {type(e).__name__}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "PASS:" in data["stdout"] or "Network" in data["stderr"]


def test_tmp_writable():
    """Test that /tmp is writable in sandbox."""
    code = '''
with open('/tmp/testfile.txt', 'w') as f:
    f.write('test content')
with open('/tmp/testfile.txt', 'r') as f:
    content = f.read()
print(f"Content: {content}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "Content: test content" in data["stdout"]
    assert data["exit_code"] == 0
    # File should persist and be in the files dict
    assert "files" in data
    assert "testfile.txt" in data["files"]
    # Clean up
    if "output_dir" in data:
        try:
            os.unlink(os.path.join(data["output_dir"], "testfile.txt"))
            os.rmdir(data["output_dir"])
        except OSError:
            pass


def test_environment_isolated():
    """Test that environment is properly isolated."""
    code = '''
import os
env = dict(os.environ)
print(f"PATH exists: {'PATH' in env}")
print(f"HOME exists: {'HOME' in env}")
print(f"USER exists: {'USER' in env}")
# Should not have sensitive variables
print(f"SSH_AUTH_SOCK exists: {'SSH_AUTH_SOCK' in env}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "PATH exists: True" in data["stdout"]
    assert "HOME exists: True" in data["stdout"]
    assert "SSH_AUTH_SOCK exists: False" in data["stdout"]


def test_syntax_error():
    """Test that syntax errors are handled cleanly."""
    code = '''
def broken(
    print("missing closing paren"
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] != 0 or "SyntaxError" in data["stderr"]


def test_exception_handling():
    """Test that exceptions are captured and returned."""
    code = '''
raise ValueError("Test error message")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] != 0
    assert "ValueError" in data["stderr"]
    assert "Test error message" in data["stderr"]


def test_file_output_persists():
    """Test that files created in /tmp persist and are returned."""
    code = '''
with open('/tmp/output.txt', 'w') as f:
    f.write('Hello, World!')
print("File created")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "File created" in data["stdout"]
    assert "files" in data
    assert "output.txt" in data["files"]
    # Small text file should have content included directly
    assert data["files"]["output.txt"]["content"] == "Hello, World!"
    # File should exist on disk
    assert os.path.exists(data["files"]["output.txt"]["path"])
    # Clean up
    try:
        os.unlink(data["files"]["output.txt"]["path"])
        os.rmdir(data["output_dir"])
    except OSError:
        pass


def test_multiple_file_outputs():
    """Test that multiple files are all returned."""
    code = '''
with open('/tmp/file1.txt', 'w') as f:
    f.write('Content 1')
with open('/tmp/file2.txt', 'w') as f:
    f.write('Content 2')
print("Files created")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "file1.txt" in data["files"]
    assert "file2.txt" in data["files"]
    assert data["files"]["file1.txt"]["content"] == "Content 1"
    assert data["files"]["file2.txt"]["content"] == "Content 2"
    # Clean up
    if "output_dir" in data:
        try:
            for f in os.listdir(data["output_dir"]):
                os.unlink(os.path.join(data["output_dir"], f))
            os.rmdir(data["output_dir"])
        except OSError:
            pass


def test_binary_file_detected():
    """Test that binary files are detected (not content-included)."""
    code = '''
# Write some binary data
data = bytes([0, 1, 2, 255, 254, 253])
with open('/tmp/binary.bin', 'wb') as f:
    f.write(data)
print("Binary file created")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "binary.bin" in data["files"]
    assert data["files"]["binary.bin"].get("binary") is True
    assert "content" not in data["files"]["binary.bin"]
    # But file should exist on disk
    assert os.path.exists(data["files"]["binary.bin"]["path"])
    # Clean up
    try:
        os.unlink(data["files"]["binary.bin"]["path"])
        os.rmdir(data["output_dir"])
    except OSError:
        pass


def test_read_host_file():
    """Test that host files can be read (read-only access)."""
    code = '''
try:
    with open('/etc/hostname', 'r') as f:
        hostname = f.read().strip()
    print(f"Hostname: {hostname}")
except FileNotFoundError:
    print("Hostname file not found")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "Hostname:" in data["stdout"] or "not found" in data["stdout"]
    assert data["exit_code"] == 0


def test_subprocess_inherits_sandbox():
    """Test that subprocess calls also run in the sandbox."""
    code = '''
import subprocess
result = subprocess.run(['ls', '/tmp'], capture_output=True, text=True)
print(f"Exit code: {result.returncode}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "Exit code: 0" in data["stdout"]


def test_empty_output():
    """Test handling of code that produces no output."""
    code = '''
x = 1 + 1
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["stdout"] == ""
    assert data["exit_code"] == 0
    # No files, so no output_dir
    assert "output_dir" not in data


def test_json_output_format():
    """Test that output is always valid JSON with expected fields."""
    code = '''print("test")'''
    result = execute_python(code)
    data = json.loads(result)
    assert "stdout" in data
    assert "stderr" in data
    assert "exit_code" in data


def test_no_files_means_no_output_dir():
    """Test that output_dir is not included when no files created."""
    code = '''print("no files here")'''
    result = execute_python(code)
    data = json.loads(result)
    assert "output_dir" not in data
    assert "files" not in data


def test_wrapper_robustness():
    """Test that user code cannot sabotage wrapper variables."""
    code = '''
# Try to sabotage wrapper internals
_json = None
_sys = None
_os = None
_result = "hacked"
json = None
os = None
sys = None

print("Wrapper survived sabotage attempt")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "Wrapper survived sabotage attempt" in data["stdout"]
    assert data["exit_code"] == 0


def test_user_code_can_use_standard_names():
    """Test that user code can freely use common variable names."""
    code = '''
import json
import os
import sys

data = {"key": "value"}
result = json.dumps(data)
print(f"JSON: {result}")
print(f"CWD: {os.getcwd()}")
print(f"Python: {sys.version_info.major}")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "JSON: " in data["stdout"]
    assert "CWD: " in data["stdout"]
    assert "Python: " in data["stdout"]
    assert data["exit_code"] == 0


def test_rlimit_fsize_enforced():
    """Test that RLIMIT_FSIZE prevents large file creation."""
    code = '''
import resource
# Check that the limit is set
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
print(f"RLIMIT_FSIZE: soft={soft}, hard={hard}")
# Verify it's 10MB
assert soft == 10 * 1024 * 1024, f"Expected 10MB, got {soft}"
print("RLIMIT_FSIZE correctly set to 10MB")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "RLIMIT_FSIZE correctly set to 10MB" in data["stdout"]
    assert data["exit_code"] == 0


def test_home_is_tmp():
    """Test that HOME is set to /tmp (our output directory)."""
    code = '''
import os
print(f"HOME: {os.environ.get('HOME')}")
# Writing to ~ should work and persist
with open(os.path.expanduser('~/homefile.txt'), 'w') as f:
    f.write('written to home')
print("Wrote to home")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "HOME: /tmp" in data["stdout"]
    assert "Wrote to home" in data["stdout"]
    # File should be in output
    assert "homefile.txt" in data["files"]
    # Clean up
    if "output_dir" in data:
        try:
            for f in os.listdir(data["output_dir"]):
                os.unlink(os.path.join(data["output_dir"], f))
            os.rmdir(data["output_dir"])
        except OSError:
            pass


def test_curly_braces_in_code():
    """Test that code with curly braces (dicts, f-strings) works correctly.

    This verifies the fix for format string injection - using {} in user code
    should not break the wrapper template substitution.
    """
    code = '''
# Dict literals with curly braces
data = {"name": "test", "value": 42}
print(f"Dict: {data}")

# F-strings with braces
name = "world"
print(f"Hello, {name}!")

# Nested braces
nested = {"outer": {"inner": "value"}}
print(f"Nested: {nested['outer']}")

# Format strings
template = "Value is {}"
print(template.format(123))
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] == 0
    assert "Dict:" in data["stdout"]
    assert "Hello, world!" in data["stdout"]
    assert "Nested:" in data["stdout"]
    assert "Value is 123" in data["stdout"]


def test_subdirectory_reported():
    """Test that output_dir is reported when subdirectories are created."""
    code = '''
import os
os.makedirs('/tmp/subdir', exist_ok=True)
with open('/tmp/subdir/nested.txt', 'w') as f:
    f.write('nested content')
print("Created subdirectory with file")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] == 0
    # output_dir should be reported even if no top-level files
    assert "output_dir" in data
    # Verify the subdirectory exists
    assert os.path.isdir(os.path.join(data["output_dir"], "subdir"))
    assert os.path.exists(os.path.join(data["output_dir"], "subdir", "nested.txt"))
    # Clean up
    if "output_dir" in data:
        import shutil
        try:
            shutil.rmtree(data["output_dir"])
        except OSError:
            pass


def test_sys_exit_none():
    """Test that sys.exit() with no argument returns exit code 0."""
    code = '''
import sys
print("About to exit")
sys.exit()  # None argument means success
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "About to exit" in data["stdout"]
    assert data["exit_code"] == 0  # None should be treated as 0


def test_sys_exit_zero():
    """Test that sys.exit(0) returns exit code 0."""
    code = '''
import sys
print("Exiting with 0")
sys.exit(0)
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] == 0


def test_sys_exit_nonzero():
    """Test that sys.exit(1) returns exit code 1."""
    code = '''
import sys
print("Exiting with 1")
sys.exit(1)
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] == 1


def test_sys_exit_string():
    """Test that sys.exit('error') returns exit code 1."""
    code = '''
import sys
sys.exit("Some error message")
'''
    result = execute_python(code)
    data = json.loads(result)
    assert data["exit_code"] == 1


@pytest.mark.skipif(
    True,  # Skip by default as it tests timeout which takes 60+ seconds
    reason="Timeout test takes too long for regular test runs"
)
def test_timeout_handling():
    """Test that long-running code is timed out."""
    code = '''
import time
while True:
    time.sleep(1)
'''
    result = execute_python(code)
    data = json.loads(result)
    assert "timeout" in data["stderr"].lower() or data["exit_code"] == -1

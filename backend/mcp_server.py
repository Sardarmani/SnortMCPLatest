from mcp.server.fastmcp import FastMCP
import shutil
import subprocess
import os

# Initialize FastMCP Server
mcp = FastMCP("Snort Service")

@mcp.tool()
def is_snort_installed() -> bool:
    """Check if snort is installed on the system."""
    return shutil.which("snort") is not None

@mcp.tool()
def get_snort_version() -> str:
    """Get the version of the installed Snort instance."""
    if not shutil.which("snort"):
        return "Error: Snort not found"
    
    try:
        # Some snort versions/configurations print version to stderr
        result = subprocess.run(["snort", "-V"], capture_output=True, text=True)
        combined = (result.stdout + "\n" + result.stderr).strip()
        if not combined:
            return "Error: Snort ran but produced NO output."
        return combined
    except Exception as e:
        return f"Error executing snort: {e}"

@mcp.tool()
def verify_config(config_path: str = "/etc/snort/snort.conf") -> str:
    """
    Verify the Snort configuration file.
    Args:
        config_path: Absolute path to the snort.conf file. Defaults to /etc/snort/snort.conf.
    """
    if not shutil.which("snort"):
        return "Error: Snort not found"
        
    # Security: Ensure we aren't passing dangerous flags, though subprocess list usage protects against shell injection.
    cmd = ["snort", "-T", "-c", config_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout + "\n" + result.stderr
        
        if "Snort successfully validated the configuration" in output:
            return "✅ Configuration is VALID."
        else:
            return f"❌ Configuration Invalid:\n{output[-500:]}" # Return last 500 chars
    except Exception as e:
        return f"Error running verification: {str(e)}"

@mcp.tool()
def run_sniffer(interface: str = "eth0", packet_count: int = 10) -> str:
    """
    Run Snort in packet sniffer mode (verbose).
    Args:
        interface: Network interface to listen on (e.g., eth0, lo).
        packet_count: Number of packets to capture. restricted to max 50 for safety.
    """
    if not shutil.which("snort"):
        return "Error: Snort not found"
    
    # Enforce safety limits
    count = min(packet_count, 50)
    
    # snort -i <interface> -v -n <count>
    # Note: Depending on permissions, this might require sudo in a real deployment.
    # We run as current user for now.
    cmd = ["snort", "-i", interface, "-v", "-n", str(count)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        # Combine stdout/stderr because snort often logs to stderr
        output = result.stdout + "\n" + result.stderr
        return output if output.strip() else "No packets captured (or permission denied)."
    except subprocess.TimeoutExpired:
        return "Error: Sniffer timed out."
    except Exception as e:
        return f"Error running sniffer: {str(e)}"

@mcp.tool()
def read_snort_logs(log_type: str = "alert.fast", lines: int = 20) -> str:
    """
    Read the latest entries from Snort log files.
    Args:
        log_type: Type of log to read. Options: 'alert', 'alert.fast', 'log'. Defaults to 'alert.fast'.
        lines: Number of latest lines to read. Max 100. Defaults to 20.
    """
    log_dir = "/var/log/snort/"
    
    # Map friendly names to actual files
    log_files = {
        "alert": "snort.alert",
        "alert.fast": "snort.alert.fast",
        "log": "snort.log"
    }
    
    if log_type not in log_files:
        return f"Error: Invalid log_type. Available types: {', '.join(log_files.keys())}"
    
    file_path = os.path.join(log_dir, log_files[log_type])
    
    if not os.path.exists(file_path):
        return f"Error: Log file {file_path} not found."
    
    # Safety limit
    lines = min(max(1, lines), 100)
    
    try:
        # Use tail command for efficiency with large files
        result = subprocess.run(["tail", "-n", str(lines), file_path], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return f"Error reading log: {result.stderr}"
        
        output = result.stdout.strip()
        if not output:
            return f"No entries found in {log_files[log_type]}."
            
        return f"--- Latest {lines} lines from {log_files[log_type]} ---\n{output}"
    except Exception as e:
        return f"Error executing tail: {str(e)}"

if __name__ == "__main__":
    mcp.run()

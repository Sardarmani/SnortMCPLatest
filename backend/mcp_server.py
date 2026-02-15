from mcp.server.fastmcp import FastMCP
import shutil
import subprocess
import os
import json

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
        result = subprocess.run(["sudo", "snort", "-V"], capture_output=True, text=True)
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
    cmd = ["sudo", "snort", "-T", "-c", config_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout + "\n" + result.stderr
        
        if "Snort successfully validated the configuration" in output:
            return "✅ Configuration is VALID."
        else:
            return f"❌ Configuration Invalid:\n{output[-1000:]}" # Return last 1000 chars for better debug
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
    # Note: Packet capture REQUIRES sudo.
    cmd = ["sudo", "snort", "-i", interface, "-v", "-n", str(count)]
    
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

def parse_snort_rule(rule_text: str) -> dict:
    """Helper to parse a single snort rule line into basic components."""
    rule_text = rule_text.strip()
    if not rule_text or rule_text.startswith("#"):
        return None
        
    try:
        # Standard format: action proto src_ip src_port direction dst_ip dst_port (options)
        parts = rule_text.split(" ", 7)
        if len(parts) < 7:
            return None
            
        action, proto, src, src_port, direction, dst, dst_port = parts[:7]
        options_str = parts[7] if len(parts) > 7 else ""
        
        # Extract options (msg, sid, rev, etc.)
        options = {}
        if "(" in options_str and ")" in options_str:
            inner = options_str[options_str.find("(")+1 : options_str.rfind(")")]
            opt_parts = [p.strip() for p in inner.split(";") if p.strip()]
            for op in opt_parts:
                if ":" in op:
                    key, val = op.split(":", 1)
                    options[key.strip()] = val.strip().replace('"', '')

        return {
            "Action": action,
            "Proto": proto,
            "Src": f"{src}:{src_port}",
            "Dir": direction,
            "Dst": f"{dst}:{dst_port}",
            "Msg": options.get("msg", "N/A"),
            "SID": options.get("sid", "N/A"),
            "Raw": rule_text
        }
    except Exception:
        return {"Raw": rule_text, "Error": "Parsing failed"}

@mcp.tool()
def list_snort_rules() -> str:
    """
    List current custom rules from /etc/snort/rules/local.rules in a structured JSON format.
    """
    rules_path = "/etc/snort/rules/local.rules"
    try:
        if not os.path.exists(rules_path):
            return json.dumps({"error": f"Rules file {rules_path} not found."})
        
        parsed_rules = []
        with open(rules_path, "r") as f:
            for line in f:
                parsed = parse_snort_rule(line)
                if parsed:
                    parsed_rules.append(parsed)
            
        return json.dumps(parsed_rules)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def add_snort_rule(rule: str) -> str:
    """
    Add a new Snort rule to /etc/snort/rules/local.rules and verify configuration.
    Args:
        rule: The full snort rule string (e.g., 'alert tcp any any -> any any (msg:"Test"; sid:1000001;)')
    """
    rules_path = "/etc/snort/rules/local.rules"
    
    # Basic check to ensure it looks like a rule
    if not rule.strip().startswith(("alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")):
        return "Error: Rule must start with a valid Snort action (alert, log, etc.)"

    try:
        # Use subprocess with sudo tee -a to append the rule safely with permissions
        # This is more robust than trying to open the file directly if it's root-owned.
        cmd = ["sudo", "tee", "-a", rules_path]
        rule_with_newlines = f"\n{rule.strip()}\n"
        
        result = subprocess.run(cmd, input=rule_with_newlines, capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            return f"Error adding rule (sudo): {result.stderr}"
        
        # 2. Verify configuration
        verification_result = verify_config()
        
        if "VALID" in verification_result:
            return f"✅ Rule added and verified successfully:\n{rule}"
        else:
            return f"⚠️ Rule added but Snort configuration is now INVALID:\n{verification_result}\n\nPlease check and fix the rule manually."

    except Exception as e:
        return f"Error adding rule: {str(e)}"

if __name__ == "__main__":
    mcp.run()

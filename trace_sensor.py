"""
Arista EOS Sensor Tracer (Ultra-Fast)
--------------------------------------------
Copyright (c) 2025 Arista Networks
Author: chris.li@arista.com

Features: 
- RAM Caching for high performance
- Dual Mode: Local (FastCli) and Remote (SNMP)
- Strict Arista 7800 Series Model Enforcement
- Real-time Debug Streaming
- Input Validation and Memory Cleanup
"""

import subprocess
import re
import sys
import argparse
from typing import Dict, Optional, Tuple, List


# ============================================================================
# Constants
# ============================================================================

# SNMP OIDs for ENTITY-MIB
ENTITY_MIB_OIDS = {
    'names': '1.3.6.1.2.1.47.1.1.1.1.7',      # entPhysicalName
    'classes': '1.3.6.1.2.1.47.1.1.1.1.5',    # entPhysicalClass
    'parents': '1.3.6.1.2.1.47.1.1.1.1.4',    # entPhysicalContainedIn
    'relpos': '1.3.6.1.2.1.47.1.1.1.1.6'      # entPhysicalParentRelPos
}

# MIB node names for FastCli commands
MIB_NODES = {
    'names': 'entPhysicalName',
    'classes': 'entPhysicalClass',
    'parents': 'entPhysicalContainedIn',
    'relpos': 'entPhysicalParentRelPos'
}

# Sensor class IDs (entPhysicalClass values)
SENSOR_CLASSES = ['7', '8']  # fan(7) and sensor(8)

# Physical class IDs that indicate terminal modules
TERMINAL_CLASSES = ['1', '6', '9']  # other(1), powerSupply(6), container(9)

# Table formatting constants
TABLE_COLUMNS = {
    'index': 15,
    'sensor_name': 55,
    'module_type': 60,
    'module_id': 0  # Variable width
}
TABLE_WIDTH = 155

# SNMP configuration defaults
SNMP_DEFAULTS = {
    'community': 'public',
    'version': '2c',
    'timeout': 60,
    'packet_timeout': 5
}

# Maximum depth for parent traversal
MAX_PARENT_DEPTH = 15


# ============================================================================
# Regex Patterns
# ============================================================================

def _compile_regex_patterns():
    """Compile regex patterns for parsing SNMP output."""
    # Base pattern components
    oid_base = r"(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1"
    index_pattern = r"(?:\[|\.)(\d+)(?:\]|\s+)"
    
    return {
        'name': re.compile(
            r"(?:entPhysicalName|" + oid_base + r"\.7)" + index_pattern + r".*?STRING:\s*(.*)"
        ),
        'class': re.compile(
            r"(?:entPhysicalClass|" + oid_base + r"\.5)" + index_pattern + r".*?INTEGER:\s*.*?\(?(\d+)\)?"
        ),
        'parent': re.compile(
            r"(?:entPhysicalContainedIn|" + oid_base + r"\.4)" + index_pattern + r".*?INTEGER:\s*(\d+)"
        ),
        'relpos': re.compile(
            r"(?:entPhysicalParentRelPos|" + oid_base + r"\.6)" + index_pattern + r".*?INTEGER:\s*(-?\d+)"
        )
    }


# ============================================================================
# FastTracer Class
# ============================================================================

class FastTracer:
    """
    High-speed Arista EOS Sensor Tracer.
    
    Traces sensor indices to their parent modules using SNMP ENTITY-MIB data.
    Supports both on-device (FastCli) and remote (snmpwalk) data fetching.
    """
    
    # Compiled regex patterns (class-level for efficiency)
    _regex_patterns = _compile_regex_patterns()
    
    def __init__(self, debug: bool = False):
        """Initialize the tracer with empty caches."""
        self.debug = debug
        self.names: Dict[str, str] = {}      # Index -> Name
        self.classes: Dict[str, str] = {}    # Index -> Class ID
        self.parents: Dict[str, str] = {}   # Index -> Parent Index
        self.relpos: Dict[str, str] = {}    # Index -> Relative Position
    
    # ========================================================================
    # Initialization and Cleanup
    # ========================================================================
    
    def cleanup(self):
        """Explicitly deallocate memory for large dictionaries."""
        if self.debug:
            print("[DEBUG] Cleaning up RAM cache...")
        self.names.clear()
        self.classes.clear()
        self.parents.clear()
        self.relpos.clear()
        self.names = None
        self.classes = None
        self.parents = None
        self.relpos = None
    
    # ========================================================================
    # Environment Detection
    # ========================================================================
    
    def check_eos_environment(self, is_remote: bool = False, exit_on_fail: bool = True) -> bool:
        """
        Check if running on Arista EOS environment or bypass if remote.
        
        Args:
            is_remote: If True, bypass check (assume remote EOS).
            exit_on_fail: If True, exit with code 2 when EOS not detected.
            
        Returns:
            True if EOS environment detected or bypassed, False otherwise.
        """
        # Bypass for remote mode
        if is_remote:
            if self.debug:
                print('[DEBUG] Environment check: Bypassed (Remote Mode)')
            return True

        # Local Mode: FastCli presence check
        if self._check_fastcli():
            return True
        
        if exit_on_fail:
            print("❌ Error: Not running on Arista EOS environment. "
                  "This tool requires EOS access (FastCli) or must be run on an EOS host.")
            sys.exit(2)
        return False
    
    def _check_fastcli(self) -> bool:
        """Check for FastCli presence and EOS indicators."""
        try:
            proc = subprocess.Popen(['FastCli', '-v'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=5)
            text = (out + err).decode('utf-8', errors='ignore').lower()
            if 'arista' in text or 'eos' in text:
                if self.debug:
                    print('[DEBUG] Environment check: FastCli indicates EOS')
                return True
        except FileNotFoundError:
            if self.debug:
                print('[DEBUG] Environment check: FastCli not found in PATH')
        except Exception as e:
            if self.debug:
                print(f'[DEBUG] Environment check: FastCli check error: {e}')
        return False
    

    
    def check_model_compatibility(self, is_remote: bool = False, host: str = "") -> bool:
        """
        Check if the target device is an Arista 7800 series.
        
        Args:
            is_remote: If True, check via SNMP on 'host'.
            host: Hostname/IP for remote check.
            
        Returns:
            True if 7800 series detected, False otherwise.
        """
        if is_remote:
            return self._check_model_remote(host)
        else:
            return self._check_model_local()
        
    def _check_model_local(self) -> bool:
        """Check local device model via FastCli."""
        try:
            cmd = "show version"
            proc = subprocess.Popen(['FastCli', '-p', '15', '-c', cmd],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=5)
            text = (out + err).decode('utf-8', errors='ignore')
            
            # Look for 7800 indicators
            # Output typically contains: "Model: DCS-7800R3-..."
            if "7800" in text or "DCS-78" in text:
                if self.debug:
                    print('[DEBUG] Model check: Detected 7800 series (local)')
                return True
            
            if self.debug:
                print(f'[DEBUG] Model check failed. Output excerpt: {text[:200]}')
        except Exception as e:
            if self.debug:
                print(f'[DEBUG] Model check error: {e}')
        
        return False

    def _check_model_remote(self, host: str) -> bool:
        """Check remote device model via SNMP sysDescr."""
        # sysDescr OID: 1.3.6.1.2.1.1.1.0
        oid = "1.3.6.1.2.1.1.1.0"
        
        cmd = [
            'snmpwalk', '-v2c', '-c', SNMP_DEFAULTS['community'], 
            '-On', '-t', str(SNMP_DEFAULTS['packet_timeout']), 
            host, oid
        ]
        
        try:
            output = self._run_snmpwalk(cmd, oid)
            if output and ("7800" in output or "DCS-78" in output):
                if self.debug:
                    print(f'[DEBUG] Model check: Detected 7800 series (remote {host})')
                return True
            
            if self.debug:
                print(f'[DEBUG] Remote model check failed. Output: {output}')
        except Exception as e:
            if self.debug:
                print(f'[DEBUG] Remote model check error: {e}')
                
        return False
    
    # ========================================================================
    # Data Fetching (FastCli - On-Device)
    # ========================================================================
    
    def fetch_data_via_fastcli(self) -> bool:
        """
        Fetch SNMP data using FastCli (on-device method).
        
        Returns:
            True if data was successfully fetched and parsed.
        """
        if self.debug:
            print("\n[Loading] Bulk walking MIB into RAM cache...")
        
        try:
            raw_data = {}
            for key, mib_node in MIB_NODES.items():
                raw_data[key] = self._run_fastcli_walk(mib_node)
            
            self._parse_raw_data(
                raw_data.get('names', ''),
                raw_data.get('classes', ''),
                raw_data.get('parents', ''),
                raw_data.get('relpos', '')
            )
            return True
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error fetching data via FastCli: {e}")
            return False
    
    def _run_fastcli_walk(self, mib_node: str) -> str:
        """
        Execute a FastCli SNMP MIB walk command.
        
        Args:
            mib_node: MIB node name (e.g., 'entPhysicalName')
            
        Returns:
            Decoded output string, empty string on error.
        """
        cmd = f"show snmp mib walk {mib_node}"
        if self.debug:
            print(f"[DEBUG] Executing CLI: {cmd}")
        
        try:
            process = subprocess.Popen(
                ['FastCli', '-p', '15', '-c', cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            output_lines = []
            if process.stdout:
                for line_bytes in process.stdout:
                    line_str = line_bytes.decode('utf-8', errors='ignore')
                    if self.debug:
                        sys.stdout.write(line_str)
                        sys.stdout.flush()
                    output_lines.append(line_str)
            
            _, stderr = process.communicate()
            decoded = "".join(output_lines)
            err_decoded = stderr.decode('utf-8', errors='ignore')
            
            if self.debug:
                print(f"\n[DEBUG] FastCli cmd: {cmd}")
                print(f"[DEBUG] FastCli returncode: {process.returncode}")
                if err_decoded:
                    err_preview = err_decoded[:200].replace('\n', ' ')
                    print(f"[DEBUG] FastCli stderr (truncated): {err_preview}")
                print(f"[DEBUG] Received {len(decoded)} characters from {mib_node}")
            
            return decoded
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] CLI Execution Error: {e}")
            return ""
    
    # ========================================================================
    # Data Fetching (SNMP - Remote)
    # ========================================================================
    
    def fetch_data_via_snmp(self, 
                           host: str, 
                           community: str = SNMP_DEFAULTS['community'],
                           version: str = SNMP_DEFAULTS['version'],
                           timeout: int = SNMP_DEFAULTS['timeout']) -> bool:
        """
        Fetch SNMP data from remote EOS device using snmpwalk.
        
        Args:
            host: Remote EOS hostname or IP address
            community: SNMP community string
            version: SNMP version ('1' or '2c')
            timeout: Overall timeout in seconds (not strictly enforced)
            
        Returns:
            True if data was successfully fetched and parsed.
        """
        if self.debug:
            print(f'[DEBUG] Fetching SNMP data from {host} '
                  f'(community={community}, version={version})')
        
        proto = '-v2c' if version == '2c' else '-v1'
        base_cmd = [
            'snmpwalk', '-On', '-t', str(SNMP_DEFAULTS['packet_timeout']),
            proto, '-c', community, host
        ]
        
        outputs = {}
        for key, oid in ENTITY_MIB_OIDS.items():
            cmd = base_cmd + [oid]
            try:
                if self.debug:
                    print(f'[DEBUG] running: {" ".join(cmd)}')
                
                output = self._run_snmpwalk(cmd, oid)
                if output is None:
                    return False
                outputs[key] = output
            except Exception as e:
                print(f'❌ Error running snmpwalk for {oid}: {e}')
                return False
        
        # Parse fetched raw outputs into caches
        self._parse_raw_data(
            outputs.get('names', ''),
            outputs.get('classes', ''),
            outputs.get('parents', ''),
            outputs.get('relpos', '')
        )
        return True
    
    def _run_snmpwalk(self, cmd: List[str], oid: str) -> Optional[str]:
        """
        Execute snmpwalk command and return output.
        
        Args:
            cmd: Complete snmpwalk command as list
            oid: OID being queried (for error messages)
            
        Returns:
            Output text or None on error.
        """
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            output_lines = []
            if proc.stdout:
                for line_bytes in proc.stdout:
                    line_str = line_bytes.decode('utf-8', errors='ignore')
                    if self.debug:
                        sys.stdout.write(line_str)
                        sys.stdout.flush()
                    output_lines.append(line_str)
            
            _, err = proc.communicate()
            ret = proc.returncode
            
            text = "".join(output_lines)
            err_text = err.decode('utf-8', errors='ignore')
            
            # Sometimes snmpwalk writes useful info to stderr
            if not text:
                text = err_text
            
            if self.debug:
                print(f'\n[DEBUG] snmpwalk oid={oid} returncode={ret} output_len={len(text)}')
                if err_text:
                    print(f'[DEBUG] snmpwalk stderr: {err_text}')
            
            return text
        except FileNotFoundError:
            print('❌ Error: `snmpwalk` not found in PATH. Install net-snmp client tools.')
            return None
        except Exception as e:
            print(f'❌ Error running snmpwalk for {oid}: {e}')
            return None
    
    # ========================================================================
    # Data Parsing
    # ========================================================================
    
    def _parse_raw_data(self, 
                       raw_names: str, 
                       raw_classes: str, 
                       raw_parents: str, 
                       raw_relpos: str):
        """
        Parse raw SNMP walk output and populate internal caches.
        
        Args:
            raw_names: Raw output from entPhysicalName walk
            raw_classes: Raw output from entPhysicalClass walk
            raw_parents: Raw output from entPhysicalContainedIn walk
            raw_relpos: Raw output from entPhysicalParentRelPos walk
        """
        # Reset caches
        self.names = {}
        self.classes = {}
        self.parents = {}
        self.relpos = {}
        
        # Parse each data type
        self._parse_names(raw_names)
        self._parse_classes(raw_classes)
        self._parse_parents(raw_parents)
        self._parse_relpos(raw_relpos)
        
        if self.debug:
            self._debug_parse_results(raw_names, raw_classes)
    
    def _parse_names(self, raw_data: str):
        """Parse entPhysicalName data."""
        matches = self._regex_patterns['name'].findall(raw_data)
        for idx, val in matches:
            name = val.strip('" \r\n')
            # Normalize "Switch Chassis." variations
            if "Switch Chassis." in name:
                name = "Switch Chassis"
            self.names[idx] = name
    
    def _parse_classes(self, raw_data: str):
        """Parse entPhysicalClass data."""
        matches = self._regex_patterns['class'].findall(raw_data)
        for idx, val in matches:
            self.classes[idx] = val
    
    def _parse_parents(self, raw_data: str):
        """Parse entPhysicalContainedIn data."""
        matches = self._regex_patterns['parent'].findall(raw_data)
        for idx, val in matches:
            self.parents[idx] = val
    
    def _parse_relpos(self, raw_data: str):
        """Parse entPhysicalParentRelPos data."""
        matches = self._regex_patterns['relpos'].findall(raw_data)
        for idx, val in matches:
            self.relpos[idx] = val
    
    def _debug_parse_results(self, raw_names: str, raw_classes: str):
        """Print debug information about parsed data."""
        print('[DEBUG] parse_bulk_from_raw loaded: '
              f'Names={len(self.names)} Classes={len(self.classes)} '
              f'Parents={len(self.parents)} RelPos={len(self.relpos)}')
        
        # Show small samples for quick inspection
        sample_names = list(self.names.items())[:3]
        sample_classes = list(self.classes.items())[:3]
        print(f'[DEBUG] sample names: {sample_names}')
        print(f'[DEBUG] sample classes: {sample_classes}')
        
        if not self.names:
            preview = raw_names[:300].replace('\n', ' ')
            print(f'[DEBUG] Warning: No name matches found; raw_names preview: {preview}')
        if not self.classes:
            preview = raw_classes[:300].replace('\n', ' ')
            print(f'[DEBUG] Warning: No class matches found; raw_classes preview: {preview}')
    
    # ========================================================================
    # Module Classification and Mapping
    # ========================================================================
    
    def classify_module(self, index: str) -> Optional[str]:
        """
        Classify a module by its index.
        
        Args:
            index: Physical entity index
            
        Returns:
            Module category string or None if not a recognized module type.
            Categories: 'Supervisor', 'Linecard', 'Fabric', 'FanTray', 
                       'PowerSupply', 'System'
        """
        name = self.names.get(index, "")
        n_lower = name.lower()
        p_class = self.classes.get(index, "0")
        parent_id = self.parents.get(index, "0")
        
        # Classification rules (order matters)
        if "supervisor" in n_lower and "slot" not in n_lower:
            return "Supervisor"
        if "linecard" in n_lower and "slot" not in n_lower:
            return "Linecard"
        if "fabric module" in n_lower:
            return "Fabric"
        if "fan tray" in n_lower and " fan" not in n_lower:
            return "FanTray"
        if p_class == '6' or ("power supply" in n_lower and "slot" not in n_lower):
            return "PowerSupply"
        if parent_id == "0" and "chassis" in n_lower:
            return "System"
        
        return None
    
    def get_module_mapping(self, start_index: str) -> Dict[str, str]:
        """
        Trace a sensor index to its parent module.
        
        Recursively climbs the parent tree until finding a recognized module.
        
        Args:
            start_index: Starting physical entity index (typically a sensor)
            
        Returns:
            Dictionary with keys:
            - 'type': Module type name (e.g., "DCS-7280SR3-48YC6-F")
            - 'id': Module identifier (e.g., "Linecard 1" or "Chassis")
        """
        current = start_index
        result = {"type": "Unknown", "id": "N/A"}
        
        for _ in range(MAX_PARENT_DEPTH):
            mod_category = self.classify_module(current)
            if mod_category:
                result["type"] = self.names.get(current, "Unknown")
                relpos = self.relpos.get(current, "0")
                
                if mod_category == "System":
                    result["id"] = "Chassis"
                else:
                    result["id"] = f"{mod_category} {relpos}"
                
                # Stop at terminal classes or FanTray
                p_class = self.classes.get(current, "0")
                if p_class in TERMINAL_CLASSES or mod_category == "FanTray":
                    break
            
            current = self.parents.get(current, "0")
            if current == "0":
                break
        
        return result
    
    # ========================================================================
    # Output and Formatting
    # ========================================================================
    
    def print_table(self, rows: List[Tuple[str, str, str, str]]):
        """
        Print a formatted table of sensor mappings.
        
        Args:
            rows: List of tuples (index, sensor_name, module_type, module_id)
        """
        header = (f"{'Index':<{TABLE_COLUMNS['index']}} | "
                 f"{'Sensor Name':<{TABLE_COLUMNS['sensor_name']}} | "
                 f"{'Module Type (Model)':<{TABLE_COLUMNS['module_type']}} | "
                 f"{'Module ID'}")
        sep_line = "-" * TABLE_WIDTH
        
        print("=" * TABLE_WIDTH)
        print(header)
        print(sep_line)
        
        last_module_id = None
        for idx, s_name, m_type, m_id in rows:
            if last_module_id is not None and last_module_id != m_id:
                print(sep_line)
            
            print(f"{idx:<{TABLE_COLUMNS['index']}} | "
                 f"{s_name:<{TABLE_COLUMNS['sensor_name']}} | "
                 f"{m_type:<{TABLE_COLUMNS['module_type']}} | "
                 f"{m_id}")
            last_module_id = m_id
        
        print("=" * TABLE_WIDTH + "\n")
    
    # ========================================================================
    # Public API Methods
    # ========================================================================
    
    def ensure_data_loaded(self):
        """Ensure SNMP data is loaded, fetching if necessary."""
        if self.names is None or not self.names:
            self.fetch_data_via_fastcli()
        elif self.debug:
            print("[Info] Using existing RAM cache (Remote/Pre-loaded)...")
    
    def dump_all_sensors(self):
        """Map all sensors to their parent modules and print results."""
        self.ensure_data_loaded()
        
        # Find all sensor indices (class 7 or 8)
        sensor_indices = [
            idx for idx, cls in self.classes.items() 
            if cls in SENSOR_CLASSES
        ]
        
        if not sensor_indices:
            print(f"❌ No sensors found. Indices in cache: {len(self.classes)}")
            return
        
        print(f"Mapping {len(sensor_indices)} sensors (Wide Mode - Grouped)...")
        
        rows = []
        for idx in sorted(sensor_indices, key=int):
            s_name = self.names.get(idx, "Unknown")
            mapping = self.get_module_mapping(idx)
            rows.append((idx, s_name, mapping['type'], mapping['id']))
        
        self.print_table(rows)
    
    def trace_single_sensor(self, index: str):
        """
        Trace a single sensor index to its parent module.
        
        Args:
            index: Physical entity index to trace
        """
        self.ensure_data_loaded()
        
        if index not in self.names:
            print(f"❌ Index {index} not found in MIB.")
            return
        
        info = self.get_module_mapping(index)
        s_name = self.names.get(index, "Unknown")
        
        print(f"Mapping Single Sensor: {index}...")
        rows = [(index, s_name, info['type'], info['id'])]
        self.print_table(rows)


# ============================================================================
# Main Entry Point
# ============================================================================

def create_argument_parser():
    """Create and configure the argument parser."""
    usage_epilog = """
ALGORITHM:
  1. Bulk Ingest: Retrieves complete ENTITY-MIB tables into RAM using 4 specific commands:
       - 'show snmp mib walk entPhysicalName'          (Maps Index -> Name)
       - 'show snmp mib walk entPhysicalClass'         (Maps Index -> Class ID)
       - 'show snmp mib walk entPhysicalContainedIn'   (Maps Index -> Parent Index)
       - 'show snmp mib walk entPhysicalParentRelPos'  (Maps Index -> Slot/RelPos)
  
  2. Filter: Identifies all indices with entPhysicalClass 'sensor(8)' or 'fan(7)'.
  
  3. Trace: For each sensor, recursively climbs the 'entPhysicalContainedIn' tree 
     until it finds a Parent Module (Linecard, Supervisor, Fabric, FanTray, PowerSupply, System).
  
  4. Map: Combines the Parent Module type with its 'entPhysicalParentRelPos' (Slot ID)
     to generate the unique Module ID. Note: 'System' is mapped to 'Chassis'.

NOTES:
  - This tool is STRICTLY for Arista 7800 Series devices (7804, 7808, 7812, 7816, 7816L).
  - The tool performs an active check for the 7800 series model and will exit if not matched.
  - RAM caching reduces 900+ sensor processing from minutes to seconds.
  - Results are grouped and separated by physical Module ID.

AUTHOR:
  chris.li@arista.com
  Copyright (c) 2025 Arista Networks
"""
    parser = argparse.ArgumentParser(
        description="High-speed Arista Sensor Tracer (7800 Series Only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_epilog
    )
    parser.add_argument(
        "index", 
        nargs='?', 
        help="Physical index to trace."
    )
    parser.add_argument(
        "-a", "--all", 
        action="store_true", 
        help="Bulk map all sensors to module ID."
    )
    parser.add_argument(
        "-d", "--debug", 
        action="store_true", 
        help="Show real-time execution outputs and parse counts."
    )
    parser.add_argument(
        "-s", "--snmp-host", 
        help="Remote EOS host to query via SNMP (when not on-device)."
    )
    parser.add_argument(
        "-c", "--snmp-community", 
        default=SNMP_DEFAULTS['community'], 
        help=f"SNMP community string (default: {SNMP_DEFAULTS['community']})."
    )
    parser.add_argument(
        "-v", "--snmp-version", 
        choices=['1', '2c'], 
        default=SNMP_DEFAULTS['version'], 
        help=f"SNMP version (default: {SNMP_DEFAULTS['version']})."
    )
    parser.add_argument(
        "-t", "--snmp-timeout", 
        type=int, 
        default=SNMP_DEFAULTS['timeout'], 
        help=f"SNMP query timeout in seconds (default: {SNMP_DEFAULTS['timeout']})."
    )
    parser.add_argument(
        "-V", "--version", 
        action="version", 
        version="%(prog)s 2.0", 
        help="Show program version and exit."
    )
    return parser


def validate_index(index: Optional[str]) -> bool:
    """
    Validate that index is a positive integer if provided.
    
    Args:
        index: Index string to validate
        
    Returns:
        True if valid, False otherwise
    """
    if index and not index.isdigit():
        print(f"❌ Error: Invalid index '{index}'. Index must be a positive integer.")
        return False
    return True


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    tracer = FastTracer(debug=args.debug)
    
    # Determine mode: Remote (SNMP) vs Local (FastCli)
    # If --snmp-host is provided, we ALWAYS use remote mode, even if running on an EOS box.
    is_remote = bool(args.snmp_host)
    
    # 1. Environment & Connectivity Check
    # If is_remote is True, the check is bypassed inside the function.
    if is_remote and args.debug:
        print(f"[DEBUG] Mode: Remote SNMP query to {args.snmp_host}")
    elif not is_remote and args.debug:
        print("[DEBUG] Mode: Local FastCli execution")

    tracer.check_eos_environment(is_remote=is_remote, exit_on_fail=True)

    # 2. Model Compatibility Check (7800 Series)
    target_host = args.snmp_host if is_remote else "localhost"
    
    if args.debug:
        print(f"[DEBUG] Checking if target is Arista 7800 series (Remote={is_remote})...")

    if not tracer.check_model_compatibility(is_remote=is_remote, host=target_host):
        print("❌ Error: Target device is not an Arista 7800 series.")
        print("   This tool is optimized for Arista 7800 chassis architecture.")
        sys.exit(4)

    # 3. Data Fetching
    if is_remote:
        ok = tracer.fetch_data_via_snmp(
            args.snmp_host,
            community=args.snmp_community,
            version=args.snmp_version,
            timeout=args.snmp_timeout
        )
        if not ok:
            print(f"❌ Error: Failed to fetch SNMP data from {args.snmp_host}")
            sys.exit(3)
    else:
        # For local mode, data is fetched on-demand by dump_all_sensors/trace_single_sensor
        # checking EnsureDataLoaded, but we can also pre-fetch here if we wanted.
        # The original code did it lazily. We'll stick to that.
        pass
    
    # Input validation
    if not validate_index(args.index):
        sys.exit(1)
    
    # Execute main logic
    try:
        if args.all:
            tracer.dump_all_sensors()
        elif args.index:
            tracer.trace_single_sensor(args.index)
        else:
            parser.print_help()
    finally:
        tracer.cleanup()


if __name__ == "__main__":
    main()

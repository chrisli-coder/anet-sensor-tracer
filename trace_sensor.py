import subprocess
import re
import sys
import argparse

"""
Arista EOS Sensor Tracer (Ultra-Fast)
--------------------------------------------
Copyright (c) 2025 Arista Networks
Author: chris.li@arista.com

Features: RAM Caching, Input Validation, Algo Description, Memory Cleanup.
"""

class FastTracer:
    def __init__(self, debug=False):
        self.debug = debug
        self.names = {}      
        self.classes = {}    
        self.parents = {}    
        self.relpos = {}     



    def run_bulk_walk(self, mib_node):
        cmd = "show snmp mib walk " + mib_node
        if self.debug:
            print("[DEBUG] Executing CLI: " + cmd)
        try:
            process = subprocess.Popen(['FastCli', '-p', '15', '-c', cmd],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            
            output_lines = []
            
            # Read stdout line by line
            if process.stdout:
                for line_bytes in process.stdout:
                    line_str = line_bytes.decode('utf-8', errors='ignore')
                    if self.debug:
                        sys.stdout.write(line_str)
                        sys.stdout.flush()
                    output_lines.append(line_str)
            
            # Wait for process and capture stderr
            _, stderr = process.communicate()
            
            decoded = "".join(output_lines)
            err_decoded = stderr.decode('utf-8', errors='ignore')

            if self.debug:
                print("\n[DEBUG] FastCli cmd: {0}".format(cmd))
                print("[DEBUG] FastCli returncode: {0}".format(process.returncode))
                if err_decoded:
                    print("[DEBUG] FastCli stderr (truncated): {0}".format(err_decoded[:200].replace('\n', ' ')))
                print("[DEBUG] Received {0} characters from {1}".format(len(decoded), mib_node))
            return decoded
        except Exception as e:
            if self.debug: print("[DEBUG] CLI Execution Error: " + str(e))
            return ""

    def parse_bulk_data(self):
        """Populates RAM cache and shortens Chassis names"""
        # 1. Names
        raw_names = self.run_bulk_walk("entPhysicalName")
        matches = re.findall(r"(?:entPhysicalName|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.7)(?:\[|\.)(\d+)(?:\]|\s+).*?STRING:\s*(.*)", raw_names)
        for idx, val in matches:
            name = val.strip('" \r\n')
            if "Switch Chassis." in name:
                name = "Switch Chassis"
            self.names[idx] = name

        # 2. Classes
        raw_classes = self.run_bulk_walk("entPhysicalClass")
        matches = re.findall(r"(?:entPhysicalClass|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.5)(?:\[|\.)(\d+)(?:\]|\s+).*?INTEGER:\s*.*?\(?(\d+)\)?", raw_classes)
        for idx, val in matches:
            self.classes[idx] = val

        # 3. Containment
        raw_parents = self.run_bulk_walk("entPhysicalContainedIn")
        matches = re.findall(r"(?:entPhysicalContainedIn|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.4)(?:\[|\.)(\d+)(?:\]|\s+).*?INTEGER:\s*(\d+)", raw_parents)
        for idx, val in matches:
            self.parents[idx] = val

        # 4. Relative Position
        raw_relpos = self.run_bulk_walk("entPhysicalParentRelPos")
        matches = re.findall(r"(?:entPhysicalParentRelPos|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.6)(?:\[|\.)(\d+)(?:\]|\s+).*?INTEGER:\s*(-?\d+)", raw_relpos)
        for idx, val in matches:
            self.relpos[idx] = val

        if self.debug:
            print("[DEBUG] RAM Cache Load Complete:")
            print("  - Names:   {0}".format(len(self.names)))
            print("  - Classes: {0}".format(len(self.classes)))
            print("  - Parents: {0}".format(len(self.parents)))
            print("  - RelPos:  {0}".format(len(self.relpos)))

    def parse_bulk_from_raw(self, raw_names, raw_classes, raw_parents, raw_relpos):
        """Populate internal caches from raw SNMP walk strings."""
        # reset caches
        self.names = {}
        self.classes = {}
        self.parents = {}
        self.relpos = {}
        # Helper regex to match either "Name" or ".1.3.6...7" or "SNMPv2-SMI::mib-2...7"
        # We expect: (prefix)(index) = (type): (value)
        
        # 1. Names (.7)
        name_matches = re.findall(r"(?:entPhysicalName|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.7)(?:\[|\.)(\d+)(?:\]|\s+).*?STRING:\s*(.*)", raw_names)
        for idx, val in name_matches:
            name = val.strip('" \r\n')
            if "Switch Chassis." in name:
                name = "Switch Chassis"
            self.names[idx] = name

        # 2. Classes (.5)
        class_matches = re.findall(r"(?:entPhysicalClass|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.5)(?:\[|\.)(\d+)(?:\]|\s+).*?INTEGER:\s*.*?\(?(\d+)\)?", raw_classes)
        for idx, val in class_matches:
            self.classes[idx] = val

        # 3. Parents (.4)
        parent_matches = re.findall(r"(?:entPhysicalContainedIn|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.4)(?:\[|\.)(\d+)(?:\]|\s+).*?INTEGER:\s*(\d+)", raw_parents)
        for idx, val in parent_matches:
            self.parents[idx] = val

        # 4. RelPos (.6)
        relpos_matches = re.findall(r"(?:entPhysicalParentRelPos|(?:\.1\.3\.6\.1\.2\.1|SNMPv2-SMI::mib-2)\.47\.1\.1\.1\.1\.6)(?:\[|\.)(\d+)(?:\]|\s+).*?INTEGER:\s*(-?\d+)", raw_relpos)
        for idx, val in relpos_matches:
            self.relpos[idx] = val

        if self.debug:
            print('[DEBUG] parse_bulk_from_raw loaded: Names={0} Classes={1} Parents={2} RelPos={3}'.format(
                len(self.names), len(self.classes), len(self.parents), len(self.relpos)
            ))
            # show small samples for quick inspection
            sample_names = list(self.names.items())[:3]
            sample_classes = list(self.classes.items())[:3]
            print('[DEBUG] sample names: {0}'.format(sample_names))
            print('[DEBUG] sample classes: {0}'.format(sample_classes))
            if not self.names:
                print('[DEBUG] Warning: No name matches found; raw_names preview: {0}'.format(raw_names[:300].replace('\n', ' ')))
            if not self.classes:
                print('[DEBUG] Warning: No class matches found; raw_classes preview: {0}'.format(raw_classes[:300].replace('\n', ' ')))

    def fetch_remote_via_snmp(self, host, community='public', version='2c', timeout=30):
        """Use local `snmpwalk` to query a remote EOS device and populate caches.

        Requires `snmpwalk` available in PATH. Uses numeric OIDs (ENTITY-MIB).
        """
        if self.debug:
            print('[DEBUG] Fetching SNMP data from {0} (community={1}, version={2})'.format(host, community, version))

        proto = '-v2c' if version == '2c' else '-v1'
        # -On forces numeric OIDs, avoiding MIB parsing issues
        # -t 5 sets timeout to 5 seconds per packet (default is 1s, often too short)
        base_cmd = ['snmpwalk', '-On', '-t', '5', proto, '-c', community, host]
        # Use numeric OIDs for ENTITY-MIB (more reliable than MIB names)
        oids = {
            'names': '1.3.6.1.2.1.47.1.1.1.1.7',      # entPhysicalName
            'classes': '1.3.6.1.2.1.47.1.1.1.1.5',    # entPhysicalClass
            'parents': '1.3.6.1.2.1.47.1.1.1.1.4',    # entPhysicalContainedIn
            'relpos': '1.3.6.1.2.1.47.1.1.1.1.6'      # entPhysicalParentRelPos
        }

        outputs = {}
        for key, oid in oids.items():
            cmd = base_cmd + [oid]
            try:
                if self.debug:
                    print('[DEBUG] running: {0}'.format(' '.join(cmd)))
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                output_lines = []
                if proc.stdout:
                    for line_bytes in proc.stdout:
                        line_str = line_bytes.decode('utf-8', errors='ignore')
                        if self.debug:
                            sys.stdout.write(line_str)
                            sys.stdout.flush()
                        output_lines.append(line_str)
                
                # Wait for completion and capture stderr
                # Note: We rely on the external tool to timeout or the user to interrupt if it hangs too long,
                # as strictly streaming with a python-side timeout is complex without threading.
                _, err = proc.communicate() 
                ret = proc.returncode
                
                text = "".join(output_lines)
                err_text = err.decode('utf-8', errors='ignore')
                
                if not text:
                    # sometimes snmpwalk writes useful info to stderr
                    text = err_text
                outputs[key] = text
                if self.debug:
                    print('\n[DEBUG] snmpwalk oid={0} returncode={1} output_len={2}'.format(oid, ret, len(text)))
                    if err_text:
                        print('[DEBUG] snmpwalk stderr: {0}'.format(err_text))
            except FileNotFoundError:
                print('❌ Error: `snmpwalk` not found in PATH. Install net-snmp client tools.')
                return False
            except Exception as e:
                print('❌ Error running snmpwalk for {0}: {1}'.format(oid, e))
                return False

        # parse fetched raw outputs into caches
        self.parse_bulk_from_raw(outputs.get('names', ''), outputs.get('classes', ''), outputs.get('parents', ''), outputs.get('relpos', ''))
        return True

    def check(self, exit_on_fail=True):
        """Environment check: determine if running on Arista EOS.

        
        
        Detection strategy (best-effort):
        1. Attempt to run `FastCli -v` and look for 'arista' or 'eos' in output.
        2. Inspect `/etc/os-release` for 'arista' or 'eos'.
        3. Fallback to `uname -a` looking for 'arista' or 'eos'.

        If `exit_on_fail` is True, prints an error and exits with code 2 when
        no EOS indicators are found. Returns True when EOS looks present.
        """
        # 1) FastCli presence
        try:
            proc = subprocess.Popen(['FastCli', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=5)
            text = (out + err).decode('utf-8', errors='ignore').lower()
            if 'arista' in text or 'eos' in text:
                if self.debug: print('[DEBUG] Environment check: FastCli indicates EOS')
                return True
        except FileNotFoundError:
            if self.debug: print('[DEBUG] Environment check: FastCli not found in PATH')
        except Exception as e:
            if self.debug: print('[DEBUG] Environment check: FastCli check error: {0}'.format(e))

        # 2) /etc/os-release
        try:
            with open('/etc/os-release', 'r') as fh:
                content = fh.read().lower()
                if 'arista' in content or 'eos' in content:
                    if self.debug: print('[DEBUG] Environment check: /etc/os-release indicates EOS')
                    return True
        except Exception:
            if self.debug: print('[DEBUG] Environment check: /etc/os-release not readable')

        # 3) uname fallback
        try:
            proc = subprocess.Popen(['uname', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = proc.communicate(timeout=3)
            if b'arista' in out.lower() or b'eos' in out.lower():
                if self.debug: print('[DEBUG] Environment check: uname indicates EOS')
                return True
        except Exception:
            if self.debug: print('[DEBUG] Environment check: uname check failed')



        if exit_on_fail:
            print("❌ Error: Not running on Arista EOS environment. This tool requires EOS access (FastCli) or must be run on an EOS host.")
            sys.exit(2)
        return False

    def classify_module(self, index):
        name = self.names.get(index, "")
        n_lower = name.lower()
        p_class = self.classes.get(index, "0")
        parent_id = self.parents.get(index, "0")
        
        if "supervisor" in n_lower and "slot" not in n_lower:
            return "Supervisor"
        if "linecard" in n_lower and "slot" not in n_lower:
            return "Linecard"
        if "fabric module" in n_lower:
            return "Fabric"
        # Check for fan tray but allow component names to pass through if needed
        if "fan tray" in n_lower and " fan" not in n_lower:
            return "FanTray"
        if p_class == '6' or ("power supply" in n_lower and "slot" not in n_lower):
            return "PowerSupply"
        if parent_id == "0" and "chassis" in n_lower:
            return "System"
        return None

    def get_module_mapping(self, start_index):
        current = start_index
        result = {"type": "Unknown", "id": "N/A"}
        
        for _ in range(15):
            mod_category = self.classify_module(current)
            if mod_category:
                result["type"] = self.names.get(current, "Unknown")
                relpos = self.relpos.get(current, "0")
                if mod_category == "System":
                    result["id"] = "Chassis"
                else:
                    result["id"] = "{0} {1}".format(mod_category, relpos)
                
                p_class = self.classes.get(current, "0")
                if p_class in ['1', '6', '9'] or mod_category == "FanTray":
                    break
            
            current = self.parents.get(current, "0")
            if current == "0": break
        return result

    def print_table(self, rows):
        """Helper to print consistent table format"""
        header = "{0:<15} | {1:<55} | {2:<60} | {3}".format('Index', 'Sensor Name', 'Module Type (Model)', 'Module ID')
        line_width = 155
        sep_line = "-" * line_width
        
        print("=" * line_width)
        print(header)
        print(sep_line)

        last_module_id = None
        for idx, s_name, m_type, m_id in rows:
            if last_module_id is not None and last_module_id != m_id:
                print(sep_line)
            
            print("{0:<15} | {1:<55} | {2:<60} | {3}".format(idx, s_name, m_type, m_id))
            last_module_id = m_id
        
        print("=" * line_width + "\n")

    def dump_sensors(self):
        if not self.names:
            print("\n[Loading] Bulk walking MIB into RAM cache...")
            self.parse_bulk_data()
        else:
            if self.debug: print("[Info] Using existing RAM cache (Remote/Pre-loaded)...")
        
        sensor_indices = [idx for idx, cls in self.classes.items() if cls in ['7', '8']]

        if not sensor_indices:
            print("❌ No sensors found. Indices in cache: {0}".format(len(self.classes)))
            return

        print("Mapping {0} sensors (Wide Mode - Grouped)...".format(len(sensor_indices)))
        
        rows = []
        for idx in sorted(sensor_indices, key=int):
            s_name = self.names.get(idx, "Unknown")
            mapping = self.get_module_mapping(idx)
            rows.append((idx, s_name, mapping['type'], mapping['id']))
            
        self.print_table(rows)

    def trace_single(self, index):
        if not self.names:
            print("\n[Loading] Bulk walking MIB into RAM cache...")
            self.parse_bulk_data()
        else:
            if self.debug: print("[Info] Using existing RAM cache (Remote/Pre-loaded)...")
        
        if index not in self.names:
            print("❌ Index {0} not found in MIB.".format(index))
            return

        info = self.get_module_mapping(index)
        s_name = self.names.get(index, "Unknown")
        
        print("Mapping Single Sensor: {0}...".format(index))
        rows = [(index, s_name, info['type'], info['id'])]
        self.print_table(rows)

    def cleanup(self):
        """Explicitly deallocate memory for large dictionaries"""
        if self.debug: print("[DEBUG] Cleaning up RAM cache...")
        self.names.clear()
        self.classes.clear()
        self.parents.clear()
        self.relpos.clear()
        self.names = None
        self.classes = None
        self.parents = None
        self.relpos = None

if __name__ == "__main__":
    usage_epilog = """
ALGORITHM:
  1. Bulk Ingest: Retrieves complete ENTITY-MIB tables into RAM using 4 specific commands:
       - 'show snmp mib walk entPhysicalName'          (Maps Index -> Name)
       - 'show snmp mib walk entPhysicalClass'         (Maps Index -> Class ID)
       - 'show snmp mib walk entPhysicalContainedIn'   (Maps Index -> Parent Index)
       - 'show snmp mib walk entPhysicalParentRelPos'  (Maps Index -> Slot/RelPos)
  
  2. Filter: Identifies all indices with entPhysicalClass 'sensor(8)' or 'fan(7)'.
  
  3. Trace: For each sensor, recursively climbs the 'entPhysicalContainedIn' tree 
     until it finds a Parent Module (Linecard, Supervisor, Fabric, FanTray, PowerSupply).
  
  4. Map: Combines the Parent Module type with its 'entPhysicalParentRelPos' (Slot ID)
     to generate the unique Module ID.

NOTES:
  - RAM caching reduces 900+ sensor processing from minutes to seconds.
  - Results are grouped and separated by physical Module ID.

AUTHOR:
  chris.li@arista.com
  Copyright (c) 2025 Arista Networks
"""
    parser = argparse.ArgumentParser(
        description="High-speed Arista Sensor Tracer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_epilog
    )
    parser.add_argument("index", nargs='?', help="Physical index to trace.")
    parser.add_argument("-a", "--all", action="store_true", help="Bulk map all sensors to module ID.")
    parser.add_argument("-d", "--debug", action="store_true", help="Show raw CLI execution and parse counts.")
    parser.add_argument("-s", "--snmp-host", help="Remote EOS host to query via SNMP (when not on-device).")
    parser.add_argument("-c", "--snmp-community", default="public", help="SNMP community string (default: public).")
    parser.add_argument("-v", "--snmp-version", choices=['1','2c'], default='2c', help="SNMP version (default: 2c).")
    parser.add_argument("-t", "--snmp-timeout", type=int, default=60, help="SNMP query timeout in seconds (default: 60).")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s 1.0", help="Show program version and exit.")

    args = parser.parse_args()
    tracer = FastTracer(debug=args.debug)
    is_eos = tracer.check(exit_on_fail=False)
    if not is_eos:
        # Not on-device: require SNMP host to be provided
        if not args.snmp_host:
            print("❌ Error: Not on Arista EOS. Provide --snmp-host to fetch SNMP data from a remote EOS device.")
            sys.exit(2)

        ok = tracer.fetch_remote_via_snmp(args.snmp_host, community=args.snmp_community, version=args.snmp_version, timeout=args.snmp_timeout)
        if not ok:
            print("❌ Error: Failed to fetch SNMP data from {0}".format(args.snmp_host))
            sys.exit(3)

    # Input Validation: Ensure index is a positive integer if provided
    if args.index and not args.index.isdigit():
        print("❌ Error: Invalid index '{0}'. Index must be a positive integer.".format(args.index))
        sys.exit(1)

    try:
        if args.all:
            tracer.dump_sensors()
        elif args.index:
            tracer.trace_single(args.index)
        else:
            parser.print_help()
    finally:
        tracer.cleanup()
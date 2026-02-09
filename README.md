# Arista EOS Sensor Tracer

**Version 2.0**

High-speed Arista EOS Sensor Tracer that maps sensor indices to their parent modules using SNMP ENTITY-MIB data. Features RAM caching for ultra-fast processing of hundreds of sensors.

## Features

- **Strictly for Arista 7800 Series**: Optimized trace algorithm specifically for 7800 chassis architecture (7804/7808/7812/7816/7816L). Actively enforced via model check.
- **RAM Caching**: Bulk loads ENTITY-MIB tables into memory for fast processing
- **Dual Mode Operation**: Works both on-device (FastCli) and remotely (SNMP)
- **Input Validation**: Validates sensor indices before processing
- **Memory Cleanup**: Explicit memory deallocation for large datasets
- **Organized Code**: Clean, maintainable codebase with logical separation of concerns

## Requirements

### On-Device Mode (EOS)
- Arista EOS device (7800 Series) with `FastCli` available
- Python 3.6 or higher

### Remote Mode (SNMP)
- `snmpwalk` command-line tool (from net-snmp package)
- Python 3.6 or higher
- Network access to target EOS device (7800 Series)

## Installation

No installation required. Simply ensure Python 3.6+ is available and (for remote mode) `snmpwalk` is in your PATH.

```bash
# Install net-snmp tools (for remote mode on Linux/macOS)
# Ubuntu/Debian:
sudo apt-get install snmp

# macOS:
brew install net-snmp

# RHEL/CentOS:
sudo yum install net-snmp-utils
```

## Usage

### Basic Usage

**Trace all sensors (on-device):**
```bash
python3 trace_sensor.py -a
```

**Trace a single sensor by index:**
```bash
python3 trace_sensor.py 12345
```

**Trace all sensors with debug output:**
```bash
python3 trace_sensor.py -a -d
```

### Remote SNMP Mode

**Query remote EOS device via SNMP:**
```bash
python3 trace_sensor.py -a -s 10.0.0.1
```

**With custom SNMP community and version:**
```bash
python3 trace_sensor.py -a -s 10.0.0.1 -c private -v 2c
```

**With custom timeout:**
```bash
python3 trace_sensor.py -a -s 10.0.0.1 -t 120
```

**Trace single sensor remotely:**
```bash
python3 trace_sensor.py 12345 -s 10.0.0.1 -c public
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--all` | `-a` | Bulk map all sensors to module ID |
| `--debug` | `-d` | Show real-time streaming of CLI/SNMP execution and parse counts |
| `--snmp-host` | `-s` | Remote EOS host to query via SNMP (required when not on-device) |
| `--snmp-community` | `-c` | SNMP community string (default: `public`) |
| `--snmp-version` | `-v` | SNMP version: `1` or `2c` (default: `2c`) |
| `--snmp-timeout` | `-t` | SNMP query timeout in seconds (default: `60`) |
| `--version` | `-V` | Show program version and exit |
| `index` | | Physical index to trace (optional positional argument) |

## Algorithm

The tracer uses a 4-step process:

1. **Bulk Ingest**: Retrieves complete ENTITY-MIB tables into RAM using 4 specific commands:
   - `show snmp mib walk entPhysicalName` (Maps Index → Name)
   - `show snmp mib walk entPhysicalClass` (Maps Index → Class ID)
   - `show snmp mib walk entPhysicalContainedIn` (Maps Index → Parent Index)
   - `show snmp mib walk entPhysicalParentRelPos` (Maps Index → Slot/RelPos)

2. **Filter**: Identifies all indices with `entPhysicalClass` 'sensor(8)' or 'fan(7)'

3. **Trace**: For each sensor, recursively climbs the `entPhysicalContainedIn` tree until it finds a Parent Module (Linecard, Supervisor, Fabric, FanTray, PowerSupply, System)

4. **Map**: Combines the Parent Module type with its `entPhysicalParentRelPos` (Slot ID) to generate the unique Module ID. ('System' type is mapped to 'Chassis' ID).

## Output Format

The tool outputs a formatted table with the following columns:

- **Index**: Physical entity index
- **Sensor Name**: Name of the sensor/fan
- **Module Type (Model)**: Full module model name (e.g., "DCS-7800R3-36p")
- **Module ID**: Module identifier (e.g., "Linecard 1", "Supervisor 0", "Chassis")

Results are grouped and separated by physical Module ID for easy reading.

## Performance

- **RAM caching** reduces 900+ sensor processing from minutes to seconds
- Efficient regex pattern compilation
- Optimized parent tree traversal (max depth: 15 levels)

## Code Structure

The codebase is organized into logical sections:

- **Constants**: OIDs, MIB nodes, class mappings, configuration defaults
- **Regex Patterns**: Compiled patterns for SNMP output parsing
- **FastTracer Class**: Main tracer class with organized methods:
  - Initialization and cleanup
  - Environment detection
  - Data fetching (FastCli and SNMP)
  - Data parsing
  - Module classification and mapping
  - Output formatting
  - Public API methods

## Examples

### Example 1: On-Device Full Scan
```bash
$ python3 trace_sensor.py -a
[Loading] Bulk walking MIB into RAM cache...
Mapping 942 sensors (Wide Mode - Grouped)...
===============================================================================================================
Index           | Sensor Name                                          | Module Type (Model)                                    | Module ID
---------------------------------------------------------------------------------------------------------------
1001            | Temp: CPU Core 0                                     | DCS-7800R3-36p                                         | Supervisor 0
1002            | Temp: CPU Core 1                                     | DCS-7800R3-36p                                         | Supervisor 0
...
```

### Example 2: Remote SNMP Query
```bash
$ python3 trace_sensor.py -a -s 192.168.1.100 -c private -d
[DEBUG] Fetching SNMP data from 192.168.1.100 (community=private, version=2c)
[DEBUG] running: snmpwalk -On -t 5 -v2c -c private 192.168.1.100 1.3.6.1.2.1.47.1.1.1.1.7
...
Mapping 942 sensors (Wide Mode - Grouped)...
```

### Example 3: Single Sensor Trace
```bash
$ python3 trace_sensor.py 1001
[Loading] Bulk walking MIB into RAM cache...
Mapping Single Sensor: 1001...
===============================================================================================================
Index           | Sensor Name                                          | Module Type (Model)                                    | Module ID
---------------------------------------------------------------------------------------------------------------
1001            | Temp: CPU Core 0                                     | DCS-7800R3-36p                                         | Supervisor 0
===============================================================================================================
```

## Troubleshooting

**Error: Not running on Arista EOS environment**
- Solution: Use `-s` flag to specify a remote SNMP host
- Note: If using `-s`, the local environment check is bypassed.

**Error: Target device is not an Arista 7800 series**
- Cause: The tool detected a device model that is not part of the 7800 series.
- Solution: Run this tool against an Arista 7800 series device.

**Error: `snmpwalk` not found in PATH**
- Solution: Install net-snmp client tools (see Installation section)

**Error: Failed to fetch SNMP data**
- Check network connectivity to target device
- Verify SNMP community string is correct
- Ensure SNMP is enabled on target device
- Try increasing timeout with `-t` option

**No sensors found**
- Verify SNMP access to ENTITY-MIB
- Check that sensors exist on the device
- Use `-d` flag for debug output

## Exit Codes

The tool uses the following exit codes to indicate different error conditions:

- `0`: Success
- `1`: Invalid index argument (non-numeric)
- `2`: Not running on Arista EOS environment (FastCli not available)
- `3`: Failed to fetch SNMP data from remote host
- `4`: Target device is not an Arista 7800 series

## Author

chris.li@arista.com

## Copyright

Copyright (c) 2025 Arista Networks

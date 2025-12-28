# anet_code

Arista sensor tracer utilities.

Usage examples:

- Run on an EOS device:

```bash
python3 trace_sensor.py -a
```

- Run from a workstation against a remote EOS via SNMP:

```bash
python3 trace_sensor.py -a --snmp-host 10.0.0.1 --snmp-community public -d
```

Requires: `snmpwalk` for remote mode, `FastCli` on-device.

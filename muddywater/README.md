# MuddyWater APT -- Sigma Detection Rules

Sigma detection rules targeting [MuddyWater](https://attack.mitre.org/groups/G0069/) (G0069), an Iranian cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS). Active since at least 2017, MuddyWater targets government, telecommunications, defense, and oil & gas organizations across the Middle East, Asia, Africa, Europe, and North America.

Also tracked as: Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450.

## Rules

### Execution (5 rules)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `execution/muddy_powershell_obfuscation.yml` | Invoke-Obfuscation patterns, long Base64 `-EncodedCommand`, string concatenation with `iex` | T1059.001, T1027.010 | high |
| `execution/muddy_mshta_powershell.yml` | mshta.exe spawning PowerShell/cmd, inline VBScript/JS execution | T1218.005, T1059.001 | high |
| `execution/muddy_cmstp_inf_execution.yml` | CMSTP.exe with `/s` flag, child processes, INF files from temp directories | T1218.003 | high |
| `execution/muddy_dde_execution.yml` | Office apps (Word/Excel/PowerPoint/Outlook) spawning script interpreters via DDE | T1559.002 | high |
| `execution/muddy_csc_compile_after_delivery.yml` | csc.exe compiling C# from temp/user-writable directories | T1027.004 | medium |

### Persistence (3 rules)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `persistence/muddy_registry_run_key.yml` | The specific `SystemTextEncoding` Run key (near-zero false positive rate) | T1547.001 | critical |
| `persistence/muddy_normal_dotm_modification.yml` | Normal.dotm template modification outside of Office self-updates | T1137.001 | high |
| `persistence/muddy_dll_sideloading.yml` | DLL loads from user-writable paths by non-system executables | T1574.001 | medium |

### Credential Access (2 rules)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `credential_access/muddy_credential_dumping_tools.yml` | Mimikatz commands, procdump targeting LSASS, Browser64 | T1003.001, T1003.004, T1555.003 | critical |
| `credential_access/muddy_lazagne_execution.yml` | LaZagne binary, Python-invoked, and module-specific command lines | T1555, T1003.004, T1003.005 | critical |

### Defense Evasion (3 rules)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `defense_evasion/muddy_proxy_disable.yml` | Registry changes disabling ProxyEnable, clearing ProxyServer | T1562.001 | medium |
| `defense_evasion/muddy_rundll32_registry.yml` | rundll32.exe loading DLLs from AppData/Temp/ProgramData | T1218.011, T1547.001 | high |
| `defense_evasion/muddy_masquerading_defender.yml` | Defender-named executables running from non-Defender paths | T1036.005 | high |

### Discovery (2 rules + 1 correlation)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `discovery/muddy_recon_commands.yml` | Individual recon commands (`net user /domain`, `systeminfo`, `ipconfig /all`, `whoami`, `hostname`, `tasklist`) | T1087.002, T1082, T1016, T1033 | low |
| `discovery/muddy_recon_commands.yml` (correlation) | Burst of 3+ recon commands from the same host within 5 minutes | T1087.002, T1082 | high |
| `discovery/muddy_security_software_check.yml` | ProgramData enumeration for "Kasper", "Panda", "ESET" keywords | T1518.001, T1083 | high |

### Command and Control (2 rules)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `command_and_control/muddy_remote_access_tools.yml` | ScreenConnect, ConnectWise, AteraAgent, RemoteUtilities, SimpleHelp | T1219 | medium |
| `command_and_control/muddy_file_sharing_c2.yml` | DNS queries to OneHub, Sync.com, TeraBox, Dubox domains | T1583.006, T1102.002 | medium |

### Collection (1 rule)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `collection/muddy_makecab_staging.yml` | makecab.exe usage outside Windows Update/servicing contexts | T1560.001 | medium |

### Lateral Movement (1 file, 2 rules)

| File | Detection | ATT&CK | Level |
|------|-----------|--------|-------|
| `lateral_movement/muddy_zerologon_exploit.yml` | Netlogon events 5827-5831 (CVE-2020-1472 indicators) | T1210 | critical |
| `lateral_movement/muddy_zerologon_exploit.yml` | Event 4742 machine account password changes | T1210 | medium |

### Correlation (1 file, 5 rules)

| File | Detection | Level |
|------|-----------|-------|
| `correlation/muddy_attack_chain.yml` | `temporal_ordered` correlation: initial execution (mshta/DDE) &rarr; PowerShell payload &rarr; registry persistence &rarr; credential dumping, all within 1 hour on the same host | critical |

## Totals

- **20 rule files** across 9 tactic directories
- **25 individual rules**: 23 detection rules + 2 correlation rules
- **25 unique UUIDs**

## Log Source Requirements

| Logsource Category | Required Telemetry |
|---|---|
| `process_creation` | Sysmon Event 1, Windows Security 4688, or EDR process telemetry |
| `registry_set` | Sysmon Event 13 or equivalent registry monitoring |
| `file_change` | Sysmon Event 2/11 or file integrity monitoring |
| `image_load` | Sysmon Event 7 (DLL load monitoring) |
| `dns_query` | Sysmon Event 22 or DNS server logs |
| `windows/system` | Windows System event log |
| `windows/security` | Windows Security event log |

## Usage

### With rsigma (direct evaluation)

```bash
rsigma eval -r muddywater/ -e '{"Image": "C:\\Windows\\System32\\mshta.exe", "CommandLine": "mshta vbscript:Execute(\"CreateObject...\")"}'
```

### With sigma-cli (SIEM conversion)

```bash
# Splunk
sigma convert -t splunk -p sysmon muddywater/

# Elasticsearch
sigma convert -t elasticsearch -p ecs_windows muddywater/

# Microsoft Sentinel
sigma convert -t kusto -p sentinel_asim muddywater/
```

### Linting

```bash
rsigma lint muddywater/
```

## References

- [MITRE ATT&CK -- MuddyWater (G0069)](https://attack.mitre.org/groups/G0069/)
- [CISA Alert AA22-055A -- Iranian Government-Sponsored Actors](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a)
- [FireEye -- Iranian Threat Group Updates TTPs](https://www.fireeye.com/blog/threat-research/2018/03/iranian-threat-group-updates-ttps-in-spear-phishing-campaign.html)
- [Kaspersky -- MuddyWater Expands Operations](https://securelist.com/muddywater/88059/)
- [Symantec -- Seedworm Espionage Group](https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group)
- [Trend Micro -- Earth Vetala](https://www.trendmicro.com/en_us/research/21/c/earth-vetala---muddywater-continues-to-target-organizations-in-t.html)
- [ClearSky -- MuddyWater Operations](https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf)
- [Cisco Talos -- MuddyWater Targets Turkey](https://blog.talosintelligence.com/2022/01/iranian-apt-muddywater-targets-turkey.html)
- [Group-IB -- SimpleHarm: Tracking MuddyWater's Infrastructure](https://www.group-ib.com/blog/muddywater-infrastructure/)

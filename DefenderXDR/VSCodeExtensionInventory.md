# Assembling a VSCode extension inventory

## MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1176.002 | Software Extensions: IDE Extensions | https://attack.mitre.org/techniques/T1176/002/ |

### Description
This query uses RegEx to extract extension IDs from your MDE process telemetry.

### Author <Optional>
- **Name:** MI5not9to5
- **Github:** https://github.com/UserNotHome
- **Twitter:** https://x.com/MI5not9to5

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where (FolderPath has_any (@"\.vscode\extensions\", @"/.vscode/extensions/")) or (InitiatingProcessFolderPath has_any (@"\.vscode\extensions\", @"/.vscode/extensions/"))
| extend extension_windows = extract(@"\\extensions\\([^\\]+)\\", 1, FolderPath)
| extend extension_unix = extract(@"/extensions/([^/]+)/", 1, FolderPath)
| extend extension_windows_1 = extract(@"\\extensions\\([^\\]+)\\", 1, InitiatingProcessFolderPath)
| extend extension_unix_1 = extract(@"/extensions/([^/]+)/", 1, InitiatingProcessFolderPath)
| extend extension_id_windows = extract(@"^(.+?)-\d+(?:\.\d+){1,3}(?:-.+)?$", 1, extension_windows)
| extend extension_id_unix = extract(@"^(.+?)-\d+(?:\.\d+){1,3}(?:-.+)?$", 1, extension_unix)
| extend extension_id_windows_1 = extract(@"^(.+?)-\d+(?:\.\d+){1,3}(?:-.+)?$", 1, extension_windows_1)
| extend extension_id_unix_1 = extract(@"^(.+?)-\d+(?:\.\d+){1,3}(?:-.+)?$", 1, extension_unix_1)
| extend extension_id = coalesce(extension_id_windows, extension_id_unix, extension_id_windows_1, extension_id_unix_1)
| distinct extension_id
```

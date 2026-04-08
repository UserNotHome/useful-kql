# Assembling a VSCode extension inventory

## MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1176.002 | Software Extensions: IDE Extensions | https://attack.mitre.org/techniques/T1176/002/ |

### Description
These queries use RegEx to extract extension IDs from your MDE process telemetry and matches them against known bad lists of extensions.

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
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```
let extensions = externaldata(extension_id: string, publisher_id: string, extension_name: string, metadata_comment: string, metadata_severity: string, metadata_category: string, metadata_source: string, metadata_reference: string, metadata_status: string, removal_date: string)
    [h'https://vsxsentry.github.io/feeds/vsxsentry_feed.csv']
with (format="csv", ignoreFirstRecord=true)
| project extension_id, extension_name, metadata_comment, metadata_category;
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
| distinct extension_id, DeviceName, FolderPath, AccountUpn
| join kind=inner (
    extensions
    | project extension_id, extension_name, metadata_comment, metadata_category
) on $left.extension_id == $right.extension_id
```

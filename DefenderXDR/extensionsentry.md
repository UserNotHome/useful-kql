# Extension Sentry (extsentry.io) external data query

## MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1176.001 | Software Extensions: Browser Extensions  | https://attack.mitre.org/techniques/T1176/001/ |

### Description
This query matches malicous extension ids from extsentry and compares them with your MDE browser extension inventory.

This query can be easily modified to other tables if desired.

### Author <Optional>
- **Name:** MI5not9to5
- **Github:** https://github.com/UserNotHome
- **Twitter:** https://x.com/MI5not9to5

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceTvmBrowserExtensions ###
```KQL
let extensions = externaldata(extension_id: string, extension_name: string, wildcard_pattern: string, category: string, threat_type: string, reference_url: string, description: string, chrome_webstore_url: string, severity: string, crx_sha256: string, first_seen: string, feed_source: string)
    [h'https://extsentry.github.io/feeds/extsentry_ioc_feed.csv']
with (format="csv", ignoreFirstRecord=true)
| project extension_id, extension_name, description, reference_url;
DeviceTvmBrowserExtensions
| join kind=leftouter (
    extensions
    | project extension_id, extension_name, description, reference_url
) on $left.ExtensionId == $right.extension_id
| where isnotempty (extension_id)
| project DeviceId, ExtensionId, ExtensionName, description, reference_url, InstallationTime, BrowserName
```

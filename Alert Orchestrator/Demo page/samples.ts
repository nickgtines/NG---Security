// Sanitized Contoso sample payloads (mocked; documentation-range IPs, fixed timestamps).
const signin = {
  SystemAlertId: "4b7d3f0e-9c1a-4e7b-8a52-1f2c3d4e5f60",
  AlertName: "Unfamiliar sign-in properties",
  DisplayName: "Suspicious sign-in for ngilling@tines.io",
  Description: "Sign-ins for this user from the United States and Argentina within 40 minutes.",
  AlertSeverity: "Medium",
  Tactics: "InitialAccess",
  Techniques: ["T1078"],
  StartTime: "2026-11-04T14:02:11Z",
  EndTime: "2026-11-04T14:41:37Z",
  AlertLink: "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/4b7d3f0e-9c1a-4e7b-8a52-1f2c3d4e5f60",
  ProviderName: "IPC",
  Entities: [
    { Type: "account", Name: "ngilling", UPNSuffix: "tines.io", DisplayName: "ngilling" },
    { Type: "ip", Address: "10.20.4.15", Location: { CountryCode: "US" } },
    { Type: "ip", Address: "143.105.137.139", Location: { CountryCode: "AR" } },
  ],
  SignInLogs: [
    { TimeGenerated: "2026-11-04T14:02:11Z", IPAddress: "10.20.4.15", Location: "US", ResultType: "0", ClientAppUsed: "Browser", AppDisplayName: "Office 365" },
    { TimeGenerated: "2026-11-04T14:41:37Z", IPAddress: "143.105.137.139", Location: "AR", ResultType: "0", ClientAppUsed: "Browser", AppDisplayName: "Office 365" },
  ],
};

const scanner = {
  detection_id: "ldt:9a1f0c3e5b7d4e21:4295012345",
  name: "Network discovery activity",
  max_severity_displayname: "Low",
  first_behavior: "2026-11-04T02:15:00Z",
  last_behavior: "2026-11-04T02:19:42Z",
  falcon_host_link: "https://falcon.crowdstrike.com/activity/detections/detail/9a1f0c3e5b7d4e21/4295012345",
  device: { device_id: "9a1f0c3e5b7d4e21a0b1c2d3e4f50617", hostname: "VULNSCAN01", platform_name: "Linux", os_version: "Ubuntu 22.04", local_ip: "10.0.8.21", external_ip: "10.0.8.21" },
  behaviors: [{
    timestamp: "2026-11-04T02:15:00Z", scenario: "Network discovery", display_name: "NetworkScanActivity",
    description: "Host performed a large number of port connections across internal subnets.",
    tactic: "Discovery", technique_id: "T1046", user_name: "svc-scanner", filename: "nmap",
    cmdline: "nmap -sS -p 1-1024 10.0.0.0/16", network_accesses: [{ remote_address: "10.0.1.10", remote_port: 445 }],
  }],
};

const malicious = {
  detection_id: "ldt:3c5e7a9b1d2f4a68:8590034567",
  name: "Malicious PowerShell execution",
  max_severity_displayname: "High",
  first_behavior: "2026-11-04T16:20:05Z",
  last_behavior: "2026-11-04T16:21:30Z",
  falcon_host_link: "https://falcon.crowdstrike.com/activity/detections/detail/3c5e7a9b1d2f4a68/8590034567",
  device: { device_id: "3c5e7a9b1d2f4a68b9c0d1e2f3a4b5c6", hostname: "EC2AMAZ-O8N692E", platform_name: "Windows", os_version: "Windows 11", local_ip: "10.30.2.42", external_ip: "203.0.113.42" },
  behaviors: [
    {
      timestamp: "2026-11-04T16:20:05Z", scenario: "Suspicious encoded PowerShell", display_name: "EncodedPowerShellDownloadCradle",
      description: "PowerShell launched with an encoded command that downloads and runs a payload.",
      tactic: "Execution", technique_id: "T1059.001", user_name: "megan.bowen@contoso.com", filename: "powershell.exe",
      cmdline: "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
      sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      parent_details: { parent_cmdline: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" },
      dns_requests: [{ domain_name: "malware.wicar.org" }],
    },
    {
      timestamp: "2026-11-04T16:21:30Z", scenario: "Command and control", display_name: "KnownBadDomain",
      description: "Connection to a domain with known-malicious reputation.",
      tactic: "Command and Control", technique_id: "T1071.001", user_name: "megan.bowen@contoso.com",
      ioc_type: "domain", ioc_value: "malware.wicar.org", network_accesses: [{ remote_address: "10.30.0.1", remote_port: 53 }],
    },
  ],
};

export const SAMPLES = [
  { key: "signin", label: "Sentinel: suspicious sign-in", route: "/ingest/sentinel", expect: "INVESTIGATE → needs_user_confirmation", body: signin },
  { key: "dup", label: "Sentinel: duplicate of open case", route: "/ingest/sentinel", expect: "SUPPRESS_DUPLICATE (run 1 first)", body: signin },
  { key: "scanner", label: "CrowdStrike: known-good scanner", route: "/ingest/crowdstrike", expect: "DISMISS_KNOWN_GOOD", body: scanner },
  { key: "malicious", label: "CrowdStrike: malicious process", route: "/ingest/crowdstrike", expect: "INVESTIGATE → escalate", body: malicious },
  { key: "malformed", label: "Malformed payload", route: "/ingest/sentinel", expect: "400 error path", body: { AlertName: "", Entities: "not-json" } },
];

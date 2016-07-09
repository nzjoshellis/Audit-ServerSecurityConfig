# Audit-ServerSecurityConfig.ps1
Validates Server Security Settings (Advanced Audit Policies, EventLog Settings and Basic Firewall Settings).

### Advanced Audit Policy
The Script uses auditpol to gather the auditing information and then validate it against a list of known 'correct' settings. It will then report on if the settings are correct or not, and then provide the setting it should be changed too.

### Event Log Reporting
Validates the Event Log sizes and that they are configured to overwrite old events when the eventlog becomes full.

### Firewall Checks
Confirms all 3 firewall profiles are enabled.

### Example Output
![alt text](https://github.com/nzjoshellis/Audit-ServerSecurityConfig/blob/master/ScriptOutput.JPG)

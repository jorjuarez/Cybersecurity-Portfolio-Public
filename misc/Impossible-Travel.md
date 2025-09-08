```kql
let failedThreshold = 5;
let successThreshold = 1;
let authWindow = 5m;
SigninLogs
| where TimeGenerated >= ago(30d)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| extend FailureOrSuccess = iff(ResultType in ("0", "50125", "50140"), "Success", "Failure")
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), make_set(IPAddress), make_set(City), FailureCount = countif(FailureOrSuccess == "Failure"), SuccessCount = countif(FailureOrSuccess == "Success") by bin(TimeGenerated, authWindow), UserPrincipalName
| where FailureCount >= failedThreshold and SuccessCount >= successThreshold
| project TimeGenerated, UserPrincipalName, StartTimeUtc, EndTimeUtc, set_IPAddress, set_City, FailureCount, SuccessCount
```
  At its core, this query is designed to detect a potential security threat, specifically a type of cyberattack called a brute-force attack or password spray attack. It's looking for a suspicious pattern: a burst of failed login attempts for a user, immediately followed by a successful login, all happening within a very short time frame.

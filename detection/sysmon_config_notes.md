# Sysmon Configuration Notes

## Root cause: a silent logging blackout

During this project, Sysmon Event ID 1 (Process Create) stopped
appearing in the log entirely — even for simple commands like `whoami`.
The **Sysmon service** was confirmed `RUNNING`, and the underlying
**ETW trace session** (`EventLog-Microsoft-Windows-Sysmon-Operational`)
was also confirmed `Running` via `logman query -ets`. Despite that,
no new Process Create events were being written.

The cause was in `sysmonconfig.xml` itself:

```xml
<EventFiltering>
  <ProcessCreate onmatch="include"/>
  <ProcessTerminate onmatch="include"/>
</EventFiltering>
```

`onmatch="include"` tells Sysmon: *"only log events that match one of
the rules listed inside this block."* Because no `<Rule>` entries were
present, the include list was empty — so **nothing matched, and nothing
was logged.** The service and the ETW session both looked completely
healthy, which made this a deceptively hard problem to spot.

## The fix

```xml
<EventFiltering>
  <ProcessCreate onmatch="exclude"/>
  <ProcessTerminate onmatch="exclude"/>
</EventFiltering>
```

`onmatch="exclude"` with an empty rule list means the opposite:
*"exclude nothing"* → log everything. Reloading this configuration
restored full Process Create / Process Terminate visibility:

```
Sysmon64.exe -c sysmonconfig.xml
```

## Why this matters for detection engineering

This is a realistic failure mode, not a lab artifact. An `include`
filter with an empty or incorrectly-scoped rule set will make an
endpoint go dark for that event type while every health check (service
status, ETW session status) still reports green. It's a good example
of why detection coverage should be validated with a **known-good
test event** (e.g. run `whoami` and confirm it appears in the log)
any time a Sysmon config is deployed or changed — not just by checking
that the service is running.

## Layering config-level tagging vs. SIEM detection

Sysmon only allows **one `onmatch` mode per event type**. Since this
lab intentionally logs *all* process creation (`onmatch="exclude"`,
empty list) to preserve full visibility, LotL-specific tagging rules
(e.g., flagging `vssadmin.exe` + `delete shadows`) were **not** added
into `sysmonconfig.xml` — doing so would force a switch back to
`onmatch="include"`, which reproduces the exact blackout bug described
above.

Instead, the detection logic (matching on `vssadmin.exe` /
`certutil.exe` command-line patterns) lives entirely in the SIEM layer
— see [`splunk_detection.spl`](splunk_detection.spl). This keeps
collection (Sysmon: log everything) cleanly separated from detection
(Splunk: decide what matters), which is generally the safer pattern
for production environments.

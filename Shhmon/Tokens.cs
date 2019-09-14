using System;
using System.Runtime.InteropServices;

namespace Shhmon
{
    class Tokens
    {
        public static void SetTokenPrivilege(ref IntPtr hToken)
        {
            Console.WriteLine("[*] Adding SeLoadDriverPrivilege to token");
            Win32.LUID luid = new Win32.LUID();
            if (!Win32.LookupPrivilegeValue(null, "SeLoadDriverPrivilege", ref luid))
            {
                Console.WriteLine("[-] LookupPrivilegeValue failed!");
                return;
            }
            Console.WriteLine("[+] Received LUID");

            Win32.LUID_AND_ATTRIBUTES luidAndAttributes = new Win32.LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = 0x2; //SE_PRIVILEGE_ENABLED

            Win32.TOKEN_PRIVILEGES newState = new Win32.TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;

            Win32.TOKEN_PRIVILEGES previousState = new Win32.TOKEN_PRIVILEGES();
            uint retLen = 0;
            Console.WriteLine("[*] Adjusting token");
            if (!Win32.AdjustTokenPrivileges(hToken, false, ref newState, (uint)Marshal.SizeOf(newState), ref previousState, out retLen))
            {
                Console.WriteLine("[-] AdjustTokenPrivileges failed!");
                return;
            }

            Console.WriteLine("[+] SeLoadDriverPrivilege added!");
            return;
        }

        public static bool CheckTokenPrivs()
        {
            return false;
        }
    }
}

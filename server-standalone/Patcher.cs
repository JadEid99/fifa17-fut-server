using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class Patcher {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, int size, out int written);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtectEx(IntPtr proc, IntPtr addr, int size, int newProt, out int oldProt);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    const int PROCESS_ALL_ACCESS = 0x1F0FFF;
    const int PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args) {
        var procs = Process.GetProcessesByName("FIFA17");
        if (procs.Length == 0) { Console.WriteLine("FIFA17 not running!"); return; }
        var proc = procs[0];
        Console.WriteLine("Found FIFA17 PID: " + proc.Id);
        
        IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
        if (hProc == IntPtr.Zero) { Console.WriteLine("Failed to open process. Run as Administrator!"); return; }
        
        byte[] searchBytes = Encoding.ASCII.GetBytes("bad certificate\0");
        
        IntPtr baseAddr = proc.MainModule.BaseAddress;
        int moduleSize = proc.MainModule.ModuleMemorySize;
        Console.WriteLine("Module base: 0x" + baseAddr.ToString("X") + " size: 0x" + moduleSize.ToString("X"));
        
        // Read in chunks since module can be very large
        int chunkSize = 64 * 1024 * 1024; // 64MB chunks
        int strOffset = -1;
        
        for (int chunkStart = 0; chunkStart < moduleSize && strOffset < 0; chunkStart += chunkSize) {
            int readSize = Math.Min(chunkSize + searchBytes.Length, moduleSize - chunkStart);
            byte[] chunk = new byte[readSize];
            int bytesRead;
            ReadProcessMemory(hProc, IntPtr.Add(baseAddr, chunkStart), chunk, readSize, out bytesRead);
            
            for (int i = 0; i < bytesRead - searchBytes.Length; i++) {
                bool match = true;
                for (int j = 0; j < searchBytes.Length; j++) {
                    if (chunk[i + j] != searchBytes[j]) { match = false; break; }
                }
                if (match) { strOffset = chunkStart + i; break; }
            }
        }
        
        if (strOffset < 0) { Console.WriteLine("String not found!"); CloseHandle(hProc); return; }
        
        long strVA = baseAddr.ToInt64() + strOffset;
        Console.WriteLine("Found 'bad certificate' at RVA=0x" + strOffset.ToString("X") + " VA=0x" + strVA.ToString("X"));
        
        // Search for LEA instructions referencing this string
        Console.WriteLine("Searching for code references...");
        int refsFound = 0;
        
        for (int chunkStart = 0; chunkStart < moduleSize; chunkStart += chunkSize) {
            int readSize = Math.Min(chunkSize, moduleSize - chunkStart);
            byte[] chunk = new byte[readSize];
            int bytesRead;
            ReadProcessMemory(hProc, IntPtr.Add(baseAddr, chunkStart), chunk, readSize, out bytesRead);
            
            for (int i = 0; i < bytesRead - 7; i++) {
                // LEA reg, [rip+offset]: 48 8D xx yy yy yy yy  or  4C 8D xx yy yy yy yy
                if ((chunk[i] == 0x48 || chunk[i] == 0x4C) && chunk[i+1] == 0x8D) {
                    byte modrm = chunk[i+2];
                    if ((modrm & 0xC7) == 0x05) {
                        int offset = BitConverter.ToInt32(chunk, i + 3);
                        long targetRVA = (long)(chunkStart + i + 7) + offset;
                        if (targetRVA == strOffset) {
                            long refVA = baseAddr.ToInt64() + chunkStart + i;
                            Console.WriteLine("  REF at VA=0x" + refVA.ToString("X") + " RVA=0x" + (chunkStart + i).ToString("X"));
                            
                            // Read surrounding bytes
                            int ctxStart = Math.Max(0, i - 128);
                            int ctxEnd = Math.Min(bytesRead, i + 64);
                            byte[] ctx = new byte[ctxEnd - ctxStart];
                            Array.Copy(chunk, ctxStart, ctx, 0, ctx.Length);
                            
                            // Print hex dump of surrounding code
                            for (int row = 0; row < ctx.Length; row += 16) {
                                long rowVA = baseAddr.ToInt64() + chunkStart + ctxStart + row;
                                string hex = "";
                                for (int col = 0; col < 16 && row + col < ctx.Length; col++) {
                                    hex += ctx[row + col].ToString("X2") + " ";
                                }
                                string marker = "";
                                if (chunkStart + ctxStart + row <= chunkStart + i && chunkStart + i < chunkStart + ctxStart + row + 16)
                                    marker = " <-- LEA here";
                                Console.WriteLine("    0x" + rowVA.ToString("X") + ": " + hex + marker);
                            }
                            refsFound++;
                        }
                    }
                }
            }
        }
        
        Console.WriteLine("Total references: " + refsFound);
        CloseHandle(hProc);
    }
}

using System;
using System.IO;
using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.ComponentModel;
using System.Threading;
using System.Security.Principal;
using System.Security.Cryptography;

namespace Anti_Miner
{
    class Program {

        public static string api = "API_KEY";

        #region "Protect"

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);

        public static RawSecurityDescriptor GetProcessSecurityDescriptor(IntPtr processHandle)
        {
            const int DACL_SECURITY_INFORMATION = 0x00000004;
            byte[] psd = new byte[0];
            uint bufSizeNeeded;
            GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, 0, out bufSizeNeeded);
            if (bufSizeNeeded < 0 || bufSizeNeeded > short.MaxValue)
                throw new Win32Exception();
            if (!GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION,
            psd = new byte[bufSizeNeeded], bufSizeNeeded, out bufSizeNeeded))
                throw new Win32Exception();
            return new RawSecurityDescriptor(psd, 0);
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        public static void SetProcessSecurityDescriptor(IntPtr processHandle, RawSecurityDescriptor dacl)
        {
            const int DACL_SECURITY_INFORMATION = 0x00000004;
            byte[] rawsd = new byte[dacl.BinaryLength];
            dacl.GetBinaryForm(rawsd, 0);
            if (!SetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, rawsd))
                throw new Win32Exception();
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [Flags]
        public enum ProcessAccessRights
        {
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            SYNCHRONIZE = 0x00100000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            STANDARD_RIGHTS_REQUIRED = 0x000f0000,
            PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF),
        }

        static void SetProtect()
        {
            IntPtr hProcess = GetCurrentProcess();
            var dacl = GetProcessSecurityDescriptor(hProcess);
            dacl.DiscretionaryAcl.InsertAce( 0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, (int)ProcessAccessRights.PROCESS_ALL_ACCESS, new SecurityIdentifier(WellKnownSidType.WorldSid, null), false, null));
            SetProcessSecurityDescriptor(hProcess, dacl);
        }

        #endregion

        static string SHA256(string path)
        {
            string temp = null;
            try
            {
                using (FileStream stream = File.OpenRead(path))
                {
                    var sha = new SHA256Managed();
                    byte[] checksum = sha.ComputeHash(stream);
                    temp = BitConverter.ToString(checksum).Replace("-", String.Empty);
                }
            }
            catch { }

            return temp;
        }

        static bool VTrez(string sha256)
        {
            bool miner = false;
            string rez = new System.Net.WebClient().DownloadString("https://www.virustotal.com/vtapi/v2/file/report?apikey=" + api + "&resource=" + sha256);
            if (rez.Contains("Miner") || rez.Contains("miner") || rez.Contains("BtcMine") || rez.Contains("mine"))
                miner = true;

            rez = null;

            return miner;
        }

        static string NetStat()
        {
            Process p = new Process();

            ProcessStartInfo ps = new ProcessStartInfo();
            ps.Arguments = "-a -n -o -p TCP";
            ps.FileName = "netstat.exe";
            ps.UseShellExecute = false;
            ps.CreateNoWindow = true;
            ps.WindowStyle = ProcessWindowStyle.Hidden;
            ps.RedirectStandardInput = true;
            ps.RedirectStandardOutput = true;
            ps.RedirectStandardError = false;

            p.StartInfo = ps;
            p.Start();

            StreamReader output = p.StandardOutput;
            string netstat_out = output.ReadToEnd();

            return netstat_out;
        }

        static string TaskList()
        {
            Process p = new Process();

            ProcessStartInfo ps = new ProcessStartInfo();
            ps.Arguments = "";
            ps.FileName = "tasklist.exe";
            ps.UseShellExecute = false;
            ps.CreateNoWindow = true;
            ps.WindowStyle = ProcessWindowStyle.Hidden;
            ps.RedirectStandardInput = true;
            ps.RedirectStandardOutput = true;
            ps.RedirectStandardError = false;

            p.StartInfo = ps;
            p.Start();

            StreamReader output = p.StandardOutput;
            string tasklist_out = output.ReadToEnd();

            return tasklist_out;
        }

        static string Miner_Path(string PID)
        {
            string run_path = null;
            var regexItem = new Regex("^[0-9]*$");

            if (regexItem.IsMatch(PID)) { }
            else { return ""; }

            using (var searcher = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + PID))
            {
                var matchEnum = searcher.Get().GetEnumerator();
                if (matchEnum.MoveNext())
                {
                    run_path = matchEnum.Current["ExecutablePath"]?.ToString();
                }
            }

            return run_path;
        }

        static string Miner_AGR(string PID) {
            string run_agr = null;
            var regexItem = new Regex("^[0-9]*$");

            if (regexItem.IsMatch(PID)) {}
            else { return ""; }

            using (var searcher = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + PID)) {
                var matchEnum = searcher.Get().GetEnumerator();
                if (matchEnum.MoveNext()) {
                    run_agr = matchEnum.Current["CommandLine"]?.ToString();
                }
            }

            return run_agr;
        }

        static void KillMiner(int pids_int, string[] PIDS, string[] path)
        {
			try {
				for (int c = 0; c != pids_int; c++)
				{
					Process p = Process.GetProcessById(Convert.ToInt32(PIDS[c]));
					p.Kill();
				}
				Thread.Sleep(1500);

				for (int c = 0; c != pids_int; c++)
				{
					File.Delete(path[c]);
				}
			} catch {}

            pids_int = 0;
            PIDS = null;
            path = null;

        }


        // Template to download list of ports/agrs from web. Split ports or ags ","
        static string[] PortFromUrl()
        {
            System.Net.WebClient client = new System.Net.WebClient();
            string rez = client.DownloadString("link");
            string[] ports = rez.Split(',');

            return ports;
        }

        static void FindVirus()
        {
            string[] PIDS = new string[1000];
            string[] path = new string[1000];
            int pids_int = 0;

            string[] line = Regex.Split(TaskList(), "\r\n");

            for (int i = 4; i != line.Length - 2; i++)
            {
                string[] agr = Regex.Split(line[i], "\\s+");
                string prog_path = Miner_Path(agr[1]);
                
                if (VTrez(SHA256(prog_path))) {
                    PIDS[pids_int] = agr[1];
                    path[pids_int] = prog_path;
                    pids_int += 1;
                }
            }

            KillMiner(pids_int, PIDS, path);
        }

        static void FindUnSafeAgr()
        {
            string[] PIDS = new string[1000];
            string[] path = new string[1000];
            int pids_int = 0;

            string[] line = Regex.Split(TaskList(), "\r\n");
            string[] agrs = { "pool", "xmr", "monero", "eth", "minergate", "nicehash", "mine", "mining", "money"};

            for (int i = 4; i != line.Length - 2; i++)
            {
                string[] agr = Regex.Split(line[i], "\\s+");

                string pid_agr = Miner_AGR(agr[1]);

                for (int a = 0; a != agrs.Length; a++)
                {
                    try { 
                        if (pid_agr.Contains(agrs[a]))
                        {
                            path[pids_int] = Miner_Path(agr[1]);
                            PIDS[pids_int] = agr[1];
                            pids_int++;
                            break;
                        }
                    } catch { }
                }
            }

            KillMiner(pids_int, PIDS, path);
        }

        static void FindUnSafePort()
        {
            string[] PIDS = new string[1000];
            string[] path = new string[1000];
            int pids_int = 0;

            string[] line = Regex.Split(NetStat(), "\r\n");
            string[] ports = { "3333", "4444", "5555", "6666", "7777", "8888", "9999" };

            for (int i = 4; i != line.Length - 2; i++)
            {
                string[] port = Regex.Split(line[i], "\\s+");

                for (int a = 0; a != ports.Length; a++)
                {
                    if (port[3].Contains(ports[a]))
                    {
                        PIDS[pids_int] = port[5];
                        path[pids_int] = Miner_Path(port[5]);
                        pids_int++;
                    }
                }
            }

            KillMiner(pids_int, PIDS, path);
        }

        static void Main(string[] args)
        {
            SetProtect();

            while (true) {
                FindUnSafePort();
                FindUnSafeAgr();
                FindVirus();
                GC.Collect();
                Thread.Sleep(20000);
            }
        }
    }
}

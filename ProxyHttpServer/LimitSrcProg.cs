using System;
using System.Collections.Generic;
using System.Data;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.Diagnostics;
using Bjd.log;
using Bjd.option;
using Bjd.sock;
using System.Net;

namespace ProxyHttpServer {
    //アクセス元プログラム制限
    internal class LimitSrcProg {
        //https://code.msdn.microsoft.com/windowsdesktop/C-Sample-to-list-all-the-4817b58f
        private const int AF_INET = 2; //IPv4
        private const int AF_INET6 = 23; //IPv6
        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

        readonly Logger _logger;
        readonly List<string> _allowList = new List<string>();
        readonly List<string> _denyList = new List<string>();
        IPAddress[] localIPs;

        public LimitSrcProg(Logger logger, IEnumerable<OneDat> allow, IEnumerable<OneDat> deny) {
            localIPs = Dns.GetHostAddresses(Dns.GetHostName());
            _logger = logger;
            foreach (var o in allow) {
                if (o.Enable) { //有効なデータだけを対象にする
                    _allowList.Add(o.StrList[0]);
                }
            }
            foreach (var o in deny) {
                if (o.Enable) { //有効なデータだけを対象にする
                    _denyList.Add(o.StrList[0]);
                }
            }
        }

        public bool IsAllow(SockObj sockObj, ref string error) {
            if (!IsLocalIpAddress(sockObj.LocalAddress.Address)) {
                //localhost上でない場合、アクセス元プログラム名取得は未対応
                return true;
            }
            string progname = GetSrcProg(sockObj);
            _logger.Set(LogKind.Debug, null, 999, string.Format("limitSrcProg:{0}", progname));
            if (_allowList.Contains(progname)) {
                //allowでヒットした場合は、常にALLOW
                error = string.Format("AllowProg={0}", progname);
                return true;
            }
            if (_denyList.Contains(progname)) {
                //denyでヒットした場合は、常にDENY
                error = string.Format("DenyProg={0}", progname);
                return false;
            }
            if (_denyList.Count == 0 && _allowList.Count > 0) {
                //Allowだけ設定されている場合
                error = string.Format("don't agree in an ALLOW Prog list {0}", progname);
                return false;//DENY
            }
            //Denyだけ設定されている場合
            //両方設定されている場合
            return true;//ALLOW
        }

        // http://www.csharp-examples.net/local-ip/
        private bool IsLocalIpAddress(IPAddress ip) {
            try {
                if (IPAddress.IsLoopback(ip)) {
                    return true;
                }
                foreach (IPAddress localIP in localIPs) {
                    if (ip.Equals(localIP)) {
                        return true;
                    }
                }
                //(BJD.net.LocalAddress でやる方がいいかも)
            }
            catch { }
            return false;
        }

        // acquire progname from source port of sockObj
        private string GetSrcProg(SockObj sockObj) {
            int port = sockObj.RemoteAddress.Port;
            int af = AF_INET;
            if (sockObj.LocalAddress.AddressFamily == AddressFamily.InterNetworkV6) {
                af = AF_INET6;
            }

            int bufferSize = 0;
            // Getting the size of TCP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, af,
                TcpTableClass.TCP_TABLE_OWNER_PID_CONNECTIONS);

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr tcpTableRecordsPtr = Marshal.AllocHGlobal(bufferSize);

            try {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedTcpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedTcpTable(tcpTableRecordsPtr, ref bufferSize, false,
                    af, TcpTableClass.TCP_TABLE_OWNER_PID_CONNECTIONS);

                // Non-zero value represent the function 'GetExtendedTcpTable' failed
                if (result != 0)
                    return "";

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'tcpRecordsTable' of type 'MIB_TCPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                if (af == AF_INET6) {
                    MIB_TCP6TABLE_OWNER_PID tcpRecordsTable = (MIB_TCP6TABLE_OWNER_PID)
                                            Marshal.PtrToStructure(tcpTableRecordsPtr,
                                            typeof(MIB_TCP6TABLE_OWNER_PID));
                    IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                            Marshal.SizeOf(tcpRecordsTable.dwNumEntries));
                    for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++) {
                        MIB_TCP6ROW_OWNER_PID tcpRow = (MIB_TCP6ROW_OWNER_PID)Marshal.
                            PtrToStructure(tableRowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                        ushort p = BitConverter.ToUInt16(new byte[2] {
                                    tcpRow.localPort[1],
                                    tcpRow.localPort[0] }, 0);
                        if (p == port) {
                            return GetMainModuleFilepath(tcpRow.owningPid);
                        }
                        tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                    }
                } else {
                    MIB_TCPTABLE_OWNER_PID tcpRecordsTable = (MIB_TCPTABLE_OWNER_PID)
                                            Marshal.PtrToStructure(tcpTableRecordsPtr,
                                            typeof(MIB_TCPTABLE_OWNER_PID));
                    IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                            Marshal.SizeOf(tcpRecordsTable.dwNumEntries));
                    // Reading and parsing the TCP records one by one from the table
                    for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++) {
                        MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.
                            PtrToStructure(tableRowPtr, typeof(MIB_TCPROW_OWNER_PID));
                        ushort p = BitConverter.ToUInt16(new byte[2] {
                                    // remotePort==portのエントリはBJD自身
                                    tcpRow.localPort[1],
                                    tcpRow.localPort[0] }, 0);
                        if (p == port) {
                            return GetMainModuleFilepath(tcpRow.owningPid);
                        }
                        tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                    }
                }
            } catch (OutOfMemoryException outOfMemoryException) {
                _logger.Set(LogKind.Error, null, 9000038, outOfMemoryException.Message);
            } catch (Exception exception) {
                _logger.Set(LogKind.Error, null, 9000038, exception.Message);
            } finally {
                Marshal.FreeHGlobal(tcpTableRecordsPtr);
            }
            return "";
        }

        private string GetMainModuleFilepath(int pid) {
            Process proc = Process.GetProcessById(pid);
            try {
                return proc.MainModule.FileName;
            } catch (Exception exception) {
                _logger.Set(LogKind.Error, null, 9000038, exception.Message);
                // WSL内プロセスの場合、MainModule参照時に
                // "アクセスが拒否されました"例外

                // XXX: ProcessNameは実行ファイル名を変更すれば
                // 容易に変更可能なので、制限を簡単に抜けられる
                return proc.ProcessName;
            }
        }
    }

    // Enum to define the set of values used to indicate the type of table returned by
    // calls made to the function 'GetExtendedTcpTable'.
    public enum TcpTableClass
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    /// <summary>
    /// The structure contains information that describes an IPv4 TCP connection with
    /// IPv4 addresses, ports used by the TCP connection, and the specific process ID
    /// (PID) associated with connection.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public int owningPid;
    }

    /// <summary>
    /// The structure contains a table of process IDs (PIDs) and the IPv4 TCP links that
    /// are context bound to these PIDs.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public uint state;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
            SizeConst = 1)]
        public MIB_TCP6ROW_OWNER_PID[] table;
    }
}

using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace amWatcher
{
    class Program
    {
        [DllImport("user32.dll")]
        static extern int GetForegroundWindow();

        [DllImport("user32")]
        private static extern UInt32 GetWindowThreadProcessId(Int32 hWnd, out Int32 lpdwProcessId);

        //private int teller = 0;

        private static void Main(string[] args)
        {
            while (true)
            {
                SetWatchWindow();
                System.Threading.Thread.Sleep(10000);
            }
        }

        private static Int32 GetWindowProcessID(Int32 hwnd)
        {
            Int32 pid = 1;
            GetWindowThreadProcessId(hwnd, out pid);
            return pid;
        }

        private static void SetWatchWindow()
        {
            Int32 hwnd = 0;
            hwnd = GetForegroundWindow();
            string appProcessName = Process.GetProcessById(GetWindowProcessID(hwnd)).ProcessName;
            string appExePath = Process.GetProcessById(GetWindowProcessID(hwnd)).MainModule.FileName;
            string appExeName = appExePath.Substring(appExePath.LastIndexOf(@"\") + 1);
        }

        static void AddressChangedCallback(object sender, EventArgs e)
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface n in adapters)
            {
                Console.WriteLine("   {0} is {1}", n.Name, n.OperationalStatus);
            }
        }

        private static void GetOutGoingNetwork()
        {
            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName())
                   .AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork)
                 .AsEnumerable();

            // echo out a header line
            Console.WriteLine("Protocol\tSourceIP:Port\t===>\tDestinationIP:Port");

            // start a sniffer for each interface
            foreach (IPAddress ip in IPv4Addresses)
                Sniff(ip);

            // wait until a key is pressed
            Console.Read();

        }

        private static void Sniff(IPAddress ip)
        {
            // setup the socket to listen on, we are listening just to IPv4 IPAddresses
            Socket sck = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            sck.Bind(new IPEndPoint(ip, 0));
            sck.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            sck.IOControl(IOControlCode.ReceiveAll, new byte[4] { 1, 0, 0, 0 }, null);

            //byte array to hold the packet data we want to examine.
            //  we are assuming default (20byte) IP header size + 4 bytes for TCP header to get ports
            byte[] buffer = new byte[24];

            // Async methods for recieving and processing data
            Action<IAsyncResult> OnReceive = null;
            OnReceive = (ar) =>
            {
                Console.WriteLine( //echo the data. details at http://en.wikipedia.org/wiki/IPv4_packet#Packet_structure
                    "{0}\t{1}:{2}\t===>\t{3}:{4}"
                    , ToProtocolString(buffer.Skip(9).First())//todo: gotta be a cleaner way to do this one...
                     , new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString()
                      , ((ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 20))).ToString()
                      , new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString()
                     , ((ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 22))).ToString());
                buffer = new byte[24]; //clean out our buffer
                sck.BeginReceive(buffer, 0, 24, SocketFlags.None,
                     new AsyncCallback(OnReceive), null); //listen some more
            };

            // begin listening to the socket
            sck.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None,
                    new AsyncCallback(OnReceive), null);
        }

        // details at http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        private static string ToProtocolString(this byte b)
        {
            switch (b)
            {
                case 1: return "ICMP";
                case 6: return "TCP";
                case 17: return "UDP";
                default: return "#" + b.ToString();
            }
        }
    }
}

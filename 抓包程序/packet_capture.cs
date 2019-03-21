using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;

namespace 抓包程序
{
    class packet_capture
    {
        const int PACKET_ERRBUF_SIZE = 256;
        const string PCAP_SRC_FILE_STRING = "file://";
        const string PCAP_SRC_IF_STRING = "rpcap://";
        const int SOCK_ADDR_LEN = 16;
        const int SOCK_ADDR_IN6_LEN = 28;
        const int S_FAMILY_LEN = 2;
        const int PCAP_OPENFLAG_PROMISCUOUS = 1;//混杂模式

        const int PCAP_PKTHDR_LEN = 16; //struct pcap_pkthdr结构的长度

        [DllImport("Wpcap.dll")]
        static extern int pcap_findalldevs_ex(string source, IntPtr auth,ref IntPtr alldevs, StringBuilder errbuf);
        [DllImport("Wpcap.dll")]
        static extern void pcap_freealldevs(IntPtr alldevsp);

        [DllImport("Wpcap.dll")]
        static extern StringBuilder pcap_geterr(IntPtr p);
        [DllImport("Wpcap.dll")]
        static extern IntPtr pcap_open(string source, int snaplen, int falgs, int read_timeout, IntPtr auth, StringBuilder errbuf);
        /// <summary>
        /// 捕获数据包
        /// </summary>
        /// <param name="p"></param>
        /// <param name="pkt_header"></param>
        /// <param name="pkt_data"></param>
        /// <returns>1 成功返回；0 超时；-1 发生错误；-2 EOF</returns>
        [DllImport("Wpcap.dll")]
        static extern int pcap_next_ex(IntPtr p,ref IntPtr pkt_header,ref IntPtr pkt_data);

        public static List<InterfaceInfo> GetAllDevs()
        {
            List<InterfaceInfo> lsdevs = new List<InterfaceInfo>();

            IntPtr alldevs = new IntPtr();
            StringBuilder errbuf = new StringBuilder(PACKET_ERRBUF_SIZE);

            if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, IntPtr.Zero,ref alldevs, errbuf) == -1)
            {
                throw new InvalidOperationException(errbuf.ToString());
            }

            pcap_if p = Marshal.PtrToStructure<pcap_if>(alldevs);
            while(true)
            {
                InterfaceInfo temp = new InterfaceInfo(p.name, p.description);
                pcap_addr pa = Marshal.PtrToStructure<pcap_addr>(p.addresses);
                while(true)
                {
                    byte[] addr = new byte[S_FAMILY_LEN];
                    Marshal.Copy(pa.addr, addr, 0, S_FAMILY_LEN);
                    short sin_family = BitConverter.ToInt16(addr, 0);
                    if(sin_family == 23)
                    {
                        addr = new byte[SOCK_ADDR_IN6_LEN];
                        Marshal.Copy(pa.addr, addr, 0, SOCK_ADDR_IN6_LEN);
                        byte[] addrv6 = new byte[16];
                        Array.Copy(addr, 8, addrv6, 0, 16);
                        IPAddress ipv6 = new IPAddress(addrv6);
                        temp.IpList.Add(ipv6.ToString());
                    }
                    else
                    {
                        addr = new byte[SOCK_ADDR_LEN];
                        Marshal.Copy(pa.addr, addr, 0, SOCK_ADDR_LEN);
                        temp.IpList.Add(IntToIp(IPAddress.NetworkToHostOrder(BitConverter.ToInt32(addr, 4))));
                    }
                    if (pa.next == IntPtr.Zero)
                    {
                        break;
                    }
                    pa = Marshal.PtrToStructure<pcap_addr>(pa.next);
                }
                lsdevs.Add(temp);
                if (p.next == IntPtr.Zero)
                {
                    break;
                }
                p = Marshal.PtrToStructure<pcap_if>(p.next);
            }
            pcap_freealldevs(alldevs);
            return lsdevs;
        }

        public static IntPtr InitCapture()
        {
            IntPtr adhandle;
            StringBuilder errbuf = new StringBuilder(PACKET_ERRBUF_SIZE);

            if((adhandle = pcap_open(App.Interface_name,65535,PCAP_OPENFLAG_PROMISCUOUS,1000,IntPtr.Zero,errbuf)) == IntPtr.Zero)
            {
                throw new InvalidOperationException("打开接口失败!");
            }
            return adhandle;
        }
        public static Packet_Info CapturePacket(IntPtr adhandle)
        {
            int res;
            IntPtr pkt_data = new IntPtr();
            IntPtr header = new IntPtr();

            res = pcap_next_ex(adhandle,ref header,ref pkt_data);
            if(res == 0)
            {
                return null;
            }
            if(res == -1 || res == -2)
            {
                StringBuilder errbuf = pcap_geterr(adhandle);
                throw new InvalidOperationException(errbuf.ToString());
            }

            pcap_pkthdr header_s = Marshal.PtrToStructure<pcap_pkthdr>(header);

            byte[] packet = new byte[header_s.len];

            Marshal.Copy(pkt_data, packet, 0, header_s.len);

            Packet_Info temp = new Packet_Info(packet, header_s.tv_sec, header_s.tv_usec);

            return temp;
        }

        static string IntToIp(int ip)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append((ip >> 24) & 0xFF).Append(".");
            sb.Append((ip >> 16) & 0xFF).Append(".");
            sb.Append((ip >> 8) & 0xFF).Append(".");
            sb.Append(ip & 0xFF);
            return sb.ToString();
        }
    }
    struct pcap_if
    {
        public IntPtr next;
        public string name;
        public string description;
        public IntPtr addresses;
        public UInt32 falgs;
    }
    struct pcap_addr
    {
        public IntPtr next;
        public IntPtr addr;
        public IntPtr netmask;
        public IntPtr broadaddr;
        public IntPtr dstaddr;
    }
    struct pcap_pkthdr
    {
        public int tv_sec;
        public int tv_usec;
        public int caplen;
        public int len;
    }
    public class InterfaceInfo
    {
        public string Name
        {
            set;
            get;
        }
        public string Description
        {
            set;
            get;
        }
        public string StrIpList
        {
            get
            {
                string temp = "";
                foreach(var str in IpList)
                {
                    temp += str + "\n";
                }
                return temp;
            }
        }
        public List<string> IpList { set; get; } = new List<string>();

        public InterfaceInfo(string name,string description)
        {
            this.Name = name;
            this.Description = description;
        }
    }
    public class Packet_Info
    {
        public byte[] Packet
        {
            set;
            get;
        }
        public int Number
        {
            set;
            get;
        }
        public float Time { get; set; }
        public string dst_mac { get; private set; }
        public string src_mac { get; private set; }

        public int tv_sec { set; get; }
        public int tv_usec { set; get; }
        public Packet_Info(byte[] packet,int sec,int usec)
        {
            this.Packet = packet;
            tv_sec = sec;
            tv_usec = usec;

            byte[] mac = new byte[6];
            Array.Copy(packet, 6, mac, 0, 6);
            this.src_mac = BitConverter.ToString(mac);
            Array.Copy(packet, 0, mac, 0, 6);
            this.dst_mac = BitConverter.ToString(mac);
        }
    }
}
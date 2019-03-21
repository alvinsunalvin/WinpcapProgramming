using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;

namespace Winpcap编程
{
    class Program
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
        static extern int pcap_findalldevs_ex(string source,IntPtr auth,ref IntPtr alldevs,StringBuilder errbuf );
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
        static string IntToIp(int ip)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append((ip >> 24) & 0xFF).Append(".");
            sb.Append((ip >> 16) & 0xFF).Append(".");
            sb.Append((ip >> 8) & 0xFF).Append(".");
            sb.Append(ip & 0xFF);
            return sb.ToString();
        }
        static void Main(string[] args)
        {
            IntPtr alldevs = new IntPtr();
            StringBuilder errbuf = new StringBuilder(PACKET_ERRBUF_SIZE);
            string[] name = new string[5];

            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, IntPtr.Zero,ref alldevs, errbuf) == -1)
            {
                Console.WriteLine(errbuf);
                return;
            }


            pcap_if p = Marshal.PtrToStructure<pcap_if>(alldevs);

            int i = 1;

            while(true)
            {
                Console.WriteLine(i.ToString()+". " +p.name);
                name[i - 1] = p.name;
                Console.WriteLine(p.description);
                pcap_addr pa = Marshal.PtrToStructure<pcap_addr>(p.addresses);
                Console.WriteLine("IP地址:");
                while (true)
                {
                    byte[] addr = new byte[S_FAMILY_LEN];
                    Marshal.Copy(pa.addr, addr, 0, S_FAMILY_LEN);
                    short sin_family = BitConverter.ToInt16(addr, 0);
                    if(sin_family == 23)
                    {
                        //ipv6
                        addr = new byte[SOCK_ADDR_IN6_LEN];
                        Marshal.Copy(pa.addr, addr, 0, SOCK_ADDR_IN6_LEN);
                        byte[] addrv6 = new byte[16];
                        Array.Copy(addr, 8, addrv6, 0, 16);
                        IPAddress ipv6 = new IPAddress(addrv6);
                        Console.WriteLine(ipv6.ToString());
                    }
                    else
                    {
                        //ipv4
                        addr = new byte[SOCK_ADDR_LEN];
                        Marshal.Copy(pa.addr, addr, 0, SOCK_ADDR_LEN);
                        
                        Console.WriteLine(IntToIp(IPAddress.NetworkToHostOrder(BitConverter.ToInt32(addr,4))));
                    }

                    if (pa.next == IntPtr.Zero)
                    {
                        break;
                    }
                    pa = Marshal.PtrToStructure<pcap_addr>(pa.next);
                }
                if(p.next == IntPtr.Zero)
                {
                    break;
                }
                p = Marshal.PtrToStructure<pcap_if>(p.next);
                i++;
            }

            IntPtr adhandle;

            Console.WriteLine("请选择接口号:");
            i = int.Parse(Console.ReadLine());
            
            if((adhandle = pcap_open(name[i-1],65535,PCAP_OPENFLAG_PROMISCUOUS,1000,IntPtr.Zero,errbuf)) == IntPtr.Zero)
            {
                Console.WriteLine(errbuf);
                pcap_freealldevs(alldevs);
                return;
            }

            Console.WriteLine("在{0}端口号上监听...", i);
            pcap_freealldevs(alldevs);

            int res;
            IntPtr pkt_data = new IntPtr(); 
            IntPtr header = new IntPtr();

            int count = 0;
            int init_tv_sec = 0;
            int init_tv_usec = 0;

            while((res = pcap_next_ex(adhandle,ref header,ref pkt_data))>=0)  //抓包函数
            {
                if(res == 0)
                {
                    continue;
                }

                pcap_pkthdr header_s = Marshal.PtrToStructure<pcap_pkthdr>(header);
                if(count == 0)
                {
                    init_tv_sec = header_s.tv_sec;
                    init_tv_usec = header_s.tv_usec;
                }

                Console.WriteLine((++count).ToString() + " "+(header_s.tv_sec - init_tv_sec + (float)(header_s.tv_usec - init_tv_usec)/1000000).ToString() +" LEN:" + header_s.len.ToString());
                byte[] packet = new byte[header_s.len];

                Marshal.Copy(pkt_data, packet, 0, header_s.len);
                byte[] src_mac = new byte[6];
                byte[] dst_mac = new byte[6];
                Array.Copy(packet, 6, src_mac, 0, 6);
                Array.Copy(packet, 0, dst_mac, 0, 6);
                Console.WriteLine("dst_mac: " + BitConverter.ToString(dst_mac) + " " + "src_mac: " + BitConverter.ToString(src_mac));
            }
            if(res == -1)
            {
                errbuf = pcap_geterr(adhandle);
                Console.WriteLine("接受数据包发生错误:" + errbuf.ToString());
                return;
            }
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
}

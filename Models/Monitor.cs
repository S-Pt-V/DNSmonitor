using DNSmonitor.Controllers;
using Microsoft.AspNetCore.DataProtection;
using System.Net;
using System.Net.Sockets;
using static DNSmonitor.Models.Headers;

namespace DNSmonitor.Models
{
    /// <summary>
    /// 监视器类
    /// </summary>
    public class Monitor
    {
        private readonly ILogger<MonitorController> _logger;

        // 监听用的IP
        const string IP = "10.200.1.233";

        // 接收缓冲区长度
        private int recv_buffer_length;
        // 接收缓冲区
        private byte[] recv_buffer;

        // 接收到的数据包列表
        private List<byte[]> packets;

        // 原始套接字，用于监听TCP、UDP数据包
        private Socket? rawsocket;
        // 普通套接字用于绑定UDPsocket，用于发送syslog数据
        private Socket? udpsocket;
        // 原始套接字设置参数
        const int SIO_R = unchecked((int)0x98000001);
        const int SIO_1 = unchecked((int)0x98000002);
        const int SIO_2 = unchecked((int)0x98000003);

        /// <summary>
        /// rawsocket监听线程
        /// </summary>
        private Thread Listener;
        private bool keeplistening;

        /// <summary>
        /// 构造函数
        /// </summary>
        public Monitor(ILogger<MonitorController> logger)
        {
            _logger = logger;

            // IP数据包虽大长度为65536
            recv_buffer_length = 65536;
            recv_buffer = new byte[recv_buffer_length];

            // 数据包缓存列表
            packets = new List<byte[]>();

            // 监听线程设置
            keeplistening = true;
            ParameterizedThreadStart? ListenerStart = new((obj) =>
            {
                if (!RawsocketSetup())
                {
                    Console.WriteLine("rawsocket setup failed.");
                    return;
                }
                RawsocketListen();
            });
            Listener = new Thread(ListenerStart);
        }

        /// <summary>
        /// 
        /// </summary>
        public void Run()
        {
            Listener.Start();
            Console.WriteLine("Thread Listener started: " + Listener.ManagedThreadId.ToString());
        }

        /// <summary>
        /// 原始套接字设置
        /// </summary>
        public bool RawsocketSetup()
        {
            try
            {
                // 创建rawsocket
                rawsocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                // rawsocket.Blocking = false;
                Console.WriteLine("Rawsocket created.");
                
                // socket绑定到IP终结点
                rawsocket.Bind(new IPEndPoint(IPAddress.Parse(IP), 0));
                Console.WriteLine("Rawsocket binded on " + IP);

                // 设置Rawsocket功能
                Console.WriteLine("Set socket Option.");
                rawsocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];

                int ret_code = rawsocket.IOControl(SIO_R, IN, OUT);
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];
                if (ret_code != 0)
                {
                    Console.WriteLine("ret_code not 0 --SetSocketOption");
                    return false;
                }
                Console.WriteLine("Socket option set.");
                
                return true;
            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
                return false;
            }
        }

        /// <summary>
        /// 原始套接字监听
        /// </summary>
        unsafe private void RawsocketListen()
        {
            while (keeplistening)
            {
                if (rawsocket != null)
                {
                    int recved = rawsocket.Receive(recv_buffer);
                    Console.WriteLine("recved " + recved.ToString() + " bytes");
                    byte[] packet = new byte[recved];
                    Array.Copy(recv_buffer, 0, packet, 0, recved);
                    ResloveIPPacket(packet);
                    // packets.Add(packet);
                    // Console.WriteLine(packets.Count.ToString());
                }
            }
        }

        /// <summary>
        /// 解析IP数据包
        /// </summary>
        /// <param name="packet"></param>
        unsafe private void ResloveIPPacket(byte[] packet)
        {
            fixed (byte* fixed_buf = packet)
            {
                IPHeader* header = (IPHeader*)fixed_buf;
                uint version = (uint)(header->ip_verlen & 0xF0) >> 4;
                uint length = (uint)(header->ip_verlen & 0x0F) << 2;
                byte tos = (byte)header->ip_tos;
                ushort totallength = (ushort)(fixed_buf[2] * 256 + fixed_buf[3]);
                ushort identification = (ushort)header->ip_id;
                ushort offset = (ushort)header->ip_offset;
                byte ttl = (byte)header->ip_ttl;
                byte protocol_byte = (byte)header->ip_protocol;
                ushort checksum = (ushort)header->ip_checksum;
                string src_addr = new IPAddress(header->ip_srcaddr).ToString();
                string dst_addr = new IPAddress(header->ip_dstaddr).ToString();

                string protocol = "";
                switch (protocol_byte)
                {
                    case 1:
                        protocol = "ICMP";
                        break;
                    case 2:
                        protocol = "IGMP";
                        break;
                    case 6:
                        protocol = "TCP";
                        break;
                    case 17:
                        protocol = "UDP";
                        break;
                    default:
                        protocol = "UNKONOWN";
                        break;
                }

                // uint src_addr = header->ip_srcaddr;
                // uint dst_addr = header->ip_dstaddr;
                // Console.WriteLine(src_addr + " to " + dst_addr + " " + protocol + " " + totallength.ToString());
                _logger.LogInformation(src_addr + " to " + dst_addr + " " + protocol + " " + totallength.ToString());
            }
        }
    }
}

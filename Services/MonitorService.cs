using System.Net;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using static DNSmonitor.Headers;

namespace DNSmonitor
{
    /// <summary>
    /// 监听器的服务
    /// </summary>
    public class MonitorService
    {
        // 本机IP
        const string loacl_ip = "10.200.1.97";
        // 监听用的原始套接字
        private static readonly Socket rawsocket;
        // 接收缓冲区长度
        private const int recv_buffer_length = 65536;
        // 接收缓冲区
        private static byte[] recv_buffer;
        // 原始套接字设置参数
        const int SIO_R = unchecked((int)0x98000001);
        const int SIO_1 = unchecked((int)0x98000002);
        const int SIO_2 = unchecked((int)0x98000003);
        // 监听线程
        private static Thread Listener;
        // 持续监听
        private static bool keeplistening;

        // IP数据包中的信息
        private static Packet? ip_packet;

        // 临时字节数组
        private static byte[]? temp;


        static MonitorService()
        {
            rawsocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            recv_buffer= new byte[recv_buffer_length];
            keeplistening = true;

            ParameterizedThreadStart? ListenerStart = new((obj) =>
            {
                if (!SocketSetup())
                {
                    // _logger.LogError("rawsocket setup failed.");
                    Console.WriteLine("rawsocket setup failed.");
                    return;
                }
                RawsocketListen();
            });
            Listener = new Thread(ListenerStart);
            // Listener.Start();
        }

        private static bool SocketSetup()
        {
            try
            {
                //**************************************************************************************
                // socket绑定到IP终结点
                rawsocket.Bind(new IPEndPoint(IPAddress.Parse(loacl_ip), 0));
                Console.WriteLine("Rawsocket binded on " + loacl_ip);

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
                //**************************************************************************************
                // udpsocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                // _logger.LogInformation("Udpsocket created");
                // udpsocket.Bind(new IPEndPoint(IPAddress.Any, 55144));
                // _logger.LogInformation("Udpsocket binded");
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return false;
            }
        }

        /// <summary>
        /// 开始监听
        /// </summary>
        public static void StratListen()
        {
            try
            {
                Listener.Start();
            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
                keeplistening = false;
            }
        }

        /// <summary>
        /// 监听线程函数
        /// </summary>
        private static void RawsocketListen()
        {
            while (keeplistening)
            {
                try
                {
                    // 接收数据
                    int recved = rawsocket.Receive(recv_buffer);
                    byte[] databytes = new byte[recved];
                    Array.Copy(recv_buffer, 0, databytes, 0, recved);
                    // Console.WriteLine("{0} bytes data received", recved.ToString());
                    // Console.WriteLine(BitConverter.ToString(databytes));
                    // 解析IP数据包中的数据
                    ResloveIPPacket(databytes, recved);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                    keeplistening = false;
                    return;
                }
            }
        }

        /// <summary>
        /// 解析IP数据包
        /// </summary>
        /// <param name="packet_bytes">原始信息的字节数组</param>
        /// <param name="packet_length">字节数组长度</param>
        //private unsafe static void ResloveIPPacket(byte[] packet_bytes, int packet_length)
        private static void ResloveIPPacket(byte[] packet_bytes, int packet_length)
        {
            try
            {
                ip_packet = new Packet();
                // 5?
                ip_packet.Version = Packet.Version_dict[((packet_bytes[0] & 0xF0) >> 4)];
                // IP数据包头部长度
                ip_packet.Header_length = (uint)((packet_bytes[0] & 0x0F) << 2);
                // IP服务类型
                ip_packet.TOS = packet_bytes[1];
                // 数据包总长度
                ip_packet.Total_length = (ushort)(packet_bytes[2] * 256 + packet_bytes[3]);
                // id
                temp = new byte[2];
                Array.Copy(packet_bytes, 4, temp, 0, 2);
                ip_packet.Id = BitConverter.ToString(temp);
                // 偏移
                ip_packet.Offset = (ushort)(packet_bytes[6] * 256 + packet_bytes[7]);
                // 生存周期
                ip_packet.TTL = (byte)packet_bytes[8];
                // 协议类型
                ip_packet.Protocol = Packet.Protocol_dict[packet_bytes[9]];
                // 校验和
                ip_packet.Checksum = (ushort)(packet_bytes[10] * 256 + packet_bytes[11]);
                // 源地址
                temp = new byte[4];
                Array.Copy(packet_bytes, 12, temp, 0, 4);
                ip_packet.Src_addr = new IPAddress(temp).ToString();
                // 目的地址
                Array.Copy(packet_bytes, 16, temp, 0, 4);
                ip_packet.Dst_addr = new IPAddress(temp).ToString();
                // 包头的选项部分
                if(ip_packet.Header_length > 20)
                {
                    uint option_length = ip_packet.Header_length - 20;
                    ip_packet.Header_option = new byte[option_length];
                    Array.Copy(packet_bytes, 20, ip_packet.Header_option, 0, option_length);
                }
                // 数据载荷
                var payload_length = packet_length - ip_packet.Header_length;
                ip_packet.Payload = new byte[payload_length];
                Array.Copy(packet_bytes, ip_packet.Header_length, ip_packet.Payload, 0, payload_length);
                // Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}\t{10}", ip_packet.Version, ip_packet.Header_length.ToString(), ip_packet.TOS.ToString(), ip_packet.Total_length.ToString(), ip_packet.Id.ToString(), ip_packet.Offset.ToString(), ip_packet.TTL.ToString(), ip_packet.Protocol, ip_packet.Src_addr, ip_packet.Dst_addr, ip_packet.Payload.Length.ToString());

                switch (packet_bytes[9])
                {
                    case 1:
                        // ICMP
                        break;
                    case 2:
                        // IGMP
                        break;
                    case 6:
                        // TCP
                        break;
                    case 17:
                        // UDP
                        ResolveUDPDatagram(ip_packet);
                        break;
                    default:
                        // UNKNOWN
                        Console.WriteLine("UNKNOWN protocol");
                        break;
                }

            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
                keeplistening = false;
            }
        }

        /// <summary>
        /// 解析UDP数据包
        /// </summary>
        /// <param name="packet">解析后的IP数据包对象，包含IP数据包头和UDP数据内容，UDP数据报为byte[] Payload</param>
        private static void ResolveUDPDatagram(Packet packet)
        {
            try
            {
                Console.WriteLine(BitConverter.ToString(packet.Payload));
            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
                keeplistening = false;
            }
        }
    }
}

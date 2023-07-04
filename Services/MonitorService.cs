using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DNSmonitor
{
    /// <summary>
    /// 监听器的服务
    /// </summary>
    public class MonitorService
    {
        // 本机IP
        const string loacl_ip = "192.168.51.214";
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
        private static readonly Thread Listener;
        // 持续监听
        private static bool keeplistening;

        // IP数据包中的信息
        private static Packet? ip_packet;
        // UDP数据报中的信息
        private static Datagram? udp_datagram;
        private static DNSdata? dnsdata;

        // 临时字节数组
        private static byte[]? temp;

        // 发送syslog用的udpsocket
        private static readonly Socket udpsocket;

        // Syslog相关参数
        private static string syslog_ip = "";
        private static int port = 514;

        static MonitorService()
        {
            // 原始套接字初始化
            rawsocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            recv_buffer = new byte[recv_buffer_length];
            keeplistening = true;

            // udp套接字初始化
            udpsocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

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
                Console.WriteLine("Udpsocket created");
                udpsocket.Bind(new IPEndPoint(IPAddress.Any, 55144));
                Console.WriteLine("Udpsocket binded");
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
            catch (Exception e)
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
                if (ip_packet.Header_length > 20)
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
            catch (Exception e)
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
                if (packet.Payload == null)
                {
                    Console.WriteLine("Payload is null");
                    return;
                }
                // Console.WriteLine(BitConverter.ToString(packet.Payload));
                udp_datagram = new Datagram();
                udp_datagram.Src_port = (ushort)(packet.Payload[0] * 256 + packet.Payload[1]);
                udp_datagram.Dst_port = (ushort)(packet.Payload[2] * 256 + packet.Payload[3]);
                udp_datagram.Length = (ushort)(packet.Payload[4] * 256 + packet.Payload[5]);
                udp_datagram.Checksum = (ushort)(packet.Payload[6] * 256 + packet.Payload[7]);
                int payload_length = packet.Payload.Length - 8;
                udp_datagram.Payload = new byte[payload_length];
                Array.Copy(packet.Payload, 8, udp_datagram.Payload, 0, payload_length);
                // Console.WriteLine("{0}:{1}\t->\t{2}:{3}\t{4}", packet.Src_addr, udp_datagram.Src_port.ToString(), packet.Dst_addr, udp_datagram.Dst_port.ToString(), udp_datagram.Payload.Length.ToString());
                if (udp_datagram.Src_port == 53 || udp_datagram.Dst_port == 53)
                {
                    ResolveDNS(packet, udp_datagram);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                keeplistening = false;
            }
        }

        /// <summary>
        /// 解析DNS数据包内容
        /// </summary>
        /// <param name="packet">IP层数据包</param>
        /// <param name="datagram">传输层数据包，DNS数据位于 datagram.Payload</param>
        private static void ResolveDNS(Packet packet, Datagram datagram)
        {
            try
            {
                if (datagram.Payload == null)
                {
                    Console.WriteLine("datagram.Payload is null");
                    return;
                }
                Console.WriteLine("\n\n*************************************************************************************************");
                Console.WriteLine(BitConverter.ToString(datagram.Payload));

                // 复制udp数据报中的数据部分
                byte[] dns_datagram = new byte[datagram.Payload.Length];
                Array.Copy(datagram.Payload, 0, dns_datagram, 0, datagram.Payload.Length);

                // 新创建DNSdata对象，并解析首部信息
                dnsdata = new DNSdata
                {
                    // 12字节首部
                    // 前两字节为标识
                    Transaction_id = (ushort)(dns_datagram[0] * 256 + dns_datagram[1]),
                    // 二、三字节为各个标志位
                    QR = (dns_datagram[2] & 0b10000000) >> 7,
                    Opcode = (dns_datagram[2] & 0b01111000) >> 3,
                    AA = (dns_datagram[2] & 0b00000100) >> 2,
                    TC = (dns_datagram[2] & 0b00000010) >> 1,
                    RD = (dns_datagram[2] & 0b00000001),
                    RA = (dns_datagram[3] & 0b10000000) >> 7,
                    Zeros = (dns_datagram[3] & 0b01110000) >> 4,
                    Rcode = (dns_datagram[3] & 0b00001111),
                    //问题数
                    Questions = dns_datagram[4] * 256 + dns_datagram[5],
                    //资源记录数
                    Answer_RRs = dns_datagram[6] * 256 + dns_datagram[7],
                    //授权资源记录数
                    Authority_RRs = dns_datagram[8] * 256 + dns_datagram[9],
                    //额外资源记录数
                    Additional_RRs = dns_datagram[10] * 256 + dns_datagram[11]
                };
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(
                    "Queries: {0}\tAnswer RRs: {1}\tAuthorities RRs: {2}\tAdditional RRs: {3}",
                    dnsdata.Questions.ToString(), dnsdata.Answer_RRs.ToString(), dnsdata.Authority_RRs.ToString(), dnsdata.Additional_RRs.ToString()
                    );

                // 解析请求部分
                // 第一个query从第13字节开始，在字节数组中的位置为12 (好像一般都只有一个query)
                dnsdata.Queries = new List<DNS_query>();
                int index = 12;
                // 遍历每一个query
                for (int count = 0; count < dnsdata.Questions; count++)
                {
                    // 一个query有多个标识符，每个标识符为一个字节数组
                    DNS_query query = new();
                    int length = 0;
                    // length + 1 为下一个标识符的长度的索引值
                    for (; index < dns_datagram.Length;)
                    {
                        // 长度值
                        length = dns_datagram[index];
                        temp = new byte[length];
                        Array.Copy(dns_datagram, index + 1, temp, 0, length);
                        query.Name += Encoding.ASCII.GetString(temp);
                        index += length + 1;
                        if (dns_datagram[index] != 0)
                        {
                            query.Name += ".";
                        }
                        else
                        {
                            index += 1;
                            break;
                        }
                    }
                    // 0x00 后的四个个字节为查询类型和查询类
                    int type_byte = (dns_datagram[index] * 256 + dns_datagram[index + 1]);
                    int class_byte = (dns_datagram[index + 2] * 256 + dns_datagram[index + 3]);
                    if (!Q_tpye_class.Type_dict.ContainsKey(type_byte))
                    {
                        query.Type = type_byte.ToString();
                    }
                    else
                    {
                        query.Type = type_byte.ToString();
                    }
                    if (!Q_tpye_class.Class_dict.ContainsKey(class_byte))
                    {
                        query.Class = class_byte.ToString();
                    }
                    else
                    {
                        query.Class = Q_tpye_class.Class_dict[(dns_datagram[index + 2] * 256 + dns_datagram[index + 3])];
                    }
                    dnsdata.Queries.Add(query);
                    // index直接指向下一个部分的开始
                    index += 4;
                }
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(dnsdata.Queries.Count.ToString() + " queries:");
                foreach (DNS_query query in dnsdata.Queries)
                {
                    Console.WriteLine("Name: " + query.Name + "\tType: " + query.Type + "\tClass: " + query.Class);
                }

                // 所有的响应记录数量
                int total_RRs = dnsdata.Answer_RRs + dnsdata.Authority_RRs + dnsdata.Additional_RRs;
                dnsdata.AnswerRRs = new List<DNS_RR>(dnsdata.Answer_RRs);
                dnsdata.AuthorityRRs = new List<DNS_RR>(dnsdata.Authority_RRs);
                dnsdata.AdditionalRRs = new List<DNS_RR>(dnsdata.Additional_RRs);
                for (int count = 0; count < total_RRs; count++)
                {
                    // Console.WriteLine("No.{0} RR", i.ToString());
                    DNS_RR RR = new();
                    for (; index < dns_datagram.Length;)
                    {
                        // Console.WriteLine("Index: {0}\tlength: {1}", index.ToString(), dns_datagram[index].ToString());
                        // 0x00表示结束
                        if (dns_datagram[index] == 0)
                        {
                            // Console.WriteLine("end");
                            index += 1;
                            break;
                        }
                        // 前两位表示为压缩算法的指针
                        else if ((dns_datagram[index] & 0xC0) == 0xC0)
                        {
                            // Console.WriteLine("ptr");
                            int location = (int)((dns_datagram[index] & 0x3F) * 256 + dns_datagram[index + 1]);
                            RR.Name += GetNameByPTR(dns_datagram, location);
                            index += 2;
                            break;
                        }
                        else
                        {
                            // Console.WriteLine(dns_datagram[index].ToString());
                            int length = dns_datagram[index];
                            temp = new byte[length];
                            Array.Copy(dns_datagram, index + 1, temp, 0, length);
                            RR.Name += Encoding.ASCII.GetString(temp);
                            index += length + 1;
                            if (dns_datagram[index] != 0)
                            {
                                RR.Name += ".";
                            }
                            else
                            {
                                index += 1;
                                break;
                            }
                        }
                    }
                    int typeindex = index;
                    int type_byte = dns_datagram[index] * 256 + dns_datagram[index + 1];
                    int class_byte = dns_datagram[index + 2] * 256 + dns_datagram[index + 3];

                    if (!Q_tpye_class.Type_dict.ContainsKey(type_byte))
                    {
                        RR.Type = type_byte.ToString();
                    }
                    else
                    {
                        RR.Type = Q_tpye_class.Type_dict[dns_datagram[index] * 256 + dns_datagram[index + 1]];
                    }

                    if (!Q_tpye_class.Class_dict.ContainsKey(class_byte))
                    {
                        RR.Class = class_byte.ToString();
                    }
                    else
                    {
                        RR.Class = Q_tpye_class.Type_dict[dns_datagram[index + 2] * 256 + dns_datagram[index + 3]];
                    }
                    
                    RR.TTL = (uint)(dns_datagram[index + 4] * 16777216 + dns_datagram[index + 5] * 65536 + dns_datagram[index + 6] * 256 + dns_datagram[index + 7]);
                    RR.Data_length = (ushort)(dns_datagram[index + 8] * 256 + dns_datagram[index + 9]);
                    index += 10;
                    // Console.WriteLine(RR.Type+"\t"+RR.Class);
                    RR.Data = new byte[RR.Data_length];
                    Array.Copy(dns_datagram, index, RR.Data, 0, RR.Data_length);
                    index += RR.Data_length;

                    if (count < dnsdata.Answer_RRs)
                    {
                        dnsdata.AnswerRRs.Add(RR);
                    }
                    else if (count >= dnsdata.Answer_RRs && (count - dnsdata.Answer_RRs) < dnsdata.Authority_RRs)
                    {
                        dnsdata.AuthorityRRs.Add(RR);
                    }
                    else
                    {
                        dnsdata.AdditionalRRs.Add(RR);
                    }

                }
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(dnsdata.AnswerRRs.Count.ToString() + " answers RRs:");
                foreach (DNS_RR RR in dnsdata.AnswerRRs)
                {
                    Console.WriteLine(
                        "Type: {0}\tClass: {1}\tTTL: {2}\tData length: {3}\tName: {4}",
                        RR.Type, RR.Class, RR.TTL.ToString(), RR.Data_length.ToString(), RR.Name
                        );
                }
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(dnsdata.AuthorityRRs.Count.ToString() + " authority RRs:");
                foreach (DNS_RR RR in dnsdata.AuthorityRRs)
                {
                    Console.WriteLine(
                        "Type: {0}\tClass: {1}\tTTL: {2}\tData length: {3}\tName: {4}",
                        RR.Type, RR.Class, RR.TTL.ToString(), RR.Data_length.ToString(), RR.Name
                        );
                }
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(dnsdata.AdditionalRRs.Count.ToString() + " additional RRs:");
                foreach (DNS_RR RR in dnsdata.AdditionalRRs)
                {
                    Console.WriteLine(
                        "Type: {0}\tClass: {1}\tTTL: {2}\tData length: {3}\tName: {4}",
                        RR.Type, RR.Class, RR.TTL.ToString(), RR.Data_length.ToString(), RR.Name
                        );
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                keeplistening = false;
            }
        }

        /// <summary>
        /// 从指定位置获取域名，在检测到0xC?的指针后调用
        /// </summary>
        /// <param name="databytes">含有域名的字节数组</param>
        /// <param name="index">域名记录的起始位置</param>
        /// <returns></returns>
        private static string GetNameByPTR(byte[] databytes, int index)
        {
            string result = "";

            for (; index < databytes.Length;)
            {
                if ((databytes[index] & 0xC0) == 0xC0)
                {
                    int location = (databytes[index] & 0x3F) * 256 + databytes[index + 1];
                    result += GetNameByPTR(databytes, location);
                    break;
                }
                else if (databytes[index] == 0)
                {
                    break;
                }
                else
                {
                    int length = databytes[index];
                    temp = new byte[length];
                    Array.Copy(databytes, index + 1, temp, 0, length);
                    result += Encoding.ASCII.GetString(temp);
                    index += length + 1;
                    if (databytes[index] != 0)
                    {
                        result += ".";
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return result;
        }
    }
}

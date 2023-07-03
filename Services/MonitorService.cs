using System.Net;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.Xml;
using System.Text;
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
        // UDP数据报中的信息
        private static Datagram? udp_datagram;
        private static DNSdata? dnsdata;

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
                if(udp_datagram.Src_port == 53 || udp_datagram.Dst_port == 53)
                {
                    ResolveDNS(packet, udp_datagram);
                }
            }
            catch(Exception e)
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
                Console.WriteLine("Queries: {0}\tAnswer RRs: {1}\tAuthorities RRs: {2}\tAdditional RRs: {3}", dnsdata.Questions.ToString(), dnsdata.Answer_RRs.ToString(), dnsdata.Authority_RRs.ToString(), dnsdata.Additional_RRs.ToString());

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
                            break;
                        }
                    }
                    // 0x00 后的四个个字节为查询类型和查询类
                    query.Type = DNS_query.Type_dict[(dns_datagram[index + 1] * 256 + dns_datagram[index + 2])];
                    query.Class = DNS_query.Class_dict[(dns_datagram[index + 3] * 256 + dns_datagram[index + 4])];
                    dnsdata.Queries.Add(query);
                    // index直接指向下一个部分的开始
                    index += 5;
                }
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(dnsdata.Queries.Count.ToString() + " queries:");
                foreach (DNS_query query in dnsdata.Queries)
                {
                    Console.WriteLine("Name: " + query.Name + "\tType: " + query.Type + "\tClass: " + query.Class);
                }

                // 解析应答部分
                /* if (dnsdata.Answer_RRs > 0)
                {
                    dnsdata.AnswerRRs = new List<DNS_answerRR>();
                    for (int count = 0; count < dnsdata.Answer_RRs; count++)
                    {
                        // Console.WriteLine("getting number {0} answer", count.ToString());
                        DNS_answerRR answer = new DNS_answerRR();
                        // 前两位为11，为压缩表示方法，使用后续的14位表示该字段相对于数据报的偏移
                        if ((dns_datagram[index] & 0b11000000) == 0xC0)
                        {
                            // 后14位为该字段相对于DNS头部的偏移
                            int offset = (dns_datagram[index] & 0b00111111) * 256 + dns_datagram[index + 1];
                            answer.Name = GetName(dns_datagram, offset);
                            // answer.Type = (ushort)(dns_datagram[index + 2] * 256 + dns_datagram[index + 3]);
                            // answer.Class = (ushort)(dns_datagram[index + 4] * 256 + dns_datagram[index + 5]);
                            answer.Type = DNS_answerRR.Type_dict[(ushort)(dns_datagram[index + 2] * 256 + dns_datagram[index + 3])];
                            answer.Class = DNS_answerRR.Class_dict[(ushort)(dns_datagram[index + 4] * 256 + dns_datagram[index + 5])];
                            answer.TTL = dns_datagram[index + 6] * 16777216 + dns_datagram[index + 7] * 65536 + dns_datagram[index + 8] * 256 + dns_datagram[index + 9];
                            answer.Data_length = (ushort)(dns_datagram[index + 10] * 256 + dns_datagram[index + 11]);
                            index += 12;
                            byte[] answerdata = new byte[answer.Data_length];
                            Array.Copy(dns_datagram, index, answerdata, 0, answer.Data_length);

                            answer.Data = GetAnswerData((ushort)(dns_datagram[index + 2] * 256 + dns_datagram[index + 3]), (ushort)(dns_datagram[index + 4] * 256 + dns_datagram[index + 5]), answerdata, dns_datagram);

                            index += answer.Data_length;
                            dnsdata.AnswerRRs.Add(answer);
                        }
                        else
                        {
                            Console.WriteLine("不对劲");
                        }
                    }
                    Console.WriteLine("-------------------------------------------------------------------------------------------------");
                    Console.WriteLine(dnsdata.AnswerRRs.Count.ToString() + " responses:");
                    foreach (DNS_answerRR answer in dnsdata.AnswerRRs)
                    {
                        Console.WriteLine("Type: {0}\tClass: {1}\t TTL:{2}\tLength: {3}\tname:{4}", answer.Type, answer.Class, answer.TTL.ToString(), answer.Data_length.ToString(), answer.Name);
                    }
                } */
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                keeplistening = false;
            }
        }

        /// <summary>
        /// 从DNS数据包中取出请求名字
        /// </summary>
        /// <param name="datagram">DNS报文的字节数据</param>
        /// <param name="index">名称字段位置</param>
        /// <returns></returns>
        private static string GetName(byte[] datagram, int index)
        {
            string name = "";
            for (; index < datagram.Length;)
            {
                if ((datagram[index] & 0b11000000) == 0xC0)
                {
                    int name_index = (datagram[index] & 0b00111111) * 256 + datagram[index + 1];
                    string tempstr = GetName(datagram, name_index);
                    name += tempstr;
                    index += 2;
                    return name;
                }
                // 长度为0表示名称的结束
                if (datagram[index] == 0)
                {
                    return name;
                }
                else
                {
                    byte[] temp = new byte[datagram[index]];
                    Array.Copy(datagram, index + 1, temp, 0, datagram[index]);
                    string str = Encoding.ASCII.GetString(temp);
                    name += str;
                    if (datagram[index + datagram[index] + 1] != 0)
                    {
                        name += ".";
                    }
                    index += datagram[index] + 1;
                }
            }
            return "???";
        }

        /// <summary>
        /// 解析响应中的数据部分
        /// </summary>
        /// <param name="atype">查询类型</param>
        /// <param name="aclass">查询类</param>
        /// <param name="adatabytes">数据部分的字节流</param>
        /// <param name="dnsdatagram">完整的dns字节流数据</param>
        /// <returns></returns>
        private static string GetAnswerData(ushort atype, ushort aclass, byte[] adatabytes, byte[] dnsdatagram)
        {
            // Console.WriteLine("GetAnswerData");
            string result = "";

            switch (atype)
            {
                // A
                case 1:
                    // Console.WriteLine("A");
                    // Console.WriteLine("A\t" + aclass.ToString() + adatabytes.Length.ToString());
                    if (adatabytes.Length == 4)
                    {
                        result = new IPAddress(adatabytes).ToString();
                    }
                    else
                    {
                        result = "UNKNOWN " + adatabytes.Length.ToString() + " bytes data: " + Encoding.ASCII.GetString(adatabytes);
                    }
                    break;
                // NS
                case 2:
                    Console.WriteLine("NS\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // CNAME
                case 5:
                    // Console.WriteLine("CNAME");
                    result = CNAMEresolve(adatabytes, dnsdatagram);
                    // Console.WriteLine("CNAME\t" + aclass.ToString() + "\t" + adatabytes.Length.ToString() + " bytes data: " + result);
                    break;
                // SOA
                case 6:
                    Console.WriteLine("SOA\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // WKS
                case 11:
                    Console.WriteLine("WKS\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // PTR
                case 12:
                    Console.WriteLine("PTR\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // HINFO
                case 13:
                    Console.WriteLine("HINFO\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // MX
                case 15:
                    Console.WriteLine("MX\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // AAAA
                case 28:
                    Console.WriteLine("AAAA\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // AXFR
                case 252:
                    Console.WriteLine("AXFR\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                // ANY
                case 255:
                    Console.WriteLine("ANY\t" + aclass.ToString() + " bytes data: " + adatabytes.Length.ToString());
                    break;
                default:
                    Console.WriteLine("UNKNOWN");
                    result = "UNKNOWN";
                    break;
            }
            return result;
        }

        /// <summary>
        /// 解析CNAME数据
        /// </summary>
        /// <param name="answerdata">DNS应答中的数据内容</param>
        /// <param name="dnsdatagram">完整的DNS数据包</param>
        /// <returns></returns>
        public static string CNAMEresolve(byte[] answerdata, byte[] dnsdatagram)
        {
            // Console.WriteLine("Resolve CNAME, TotalLength: {0}", answerdata.Length.ToString());
            string result = "";
            for (int i = 0; i < answerdata.Length;)
            {
                if ((answerdata[i] & 0b11000000) == 0xC0)
                {
                    int index = (answerdata[i] & 0b00111111) * 256 + answerdata[i + 1];
                    // Console.WriteLine("Compressed location : {0}", index.ToString());
                    string tempstr = GetName(dnsdatagram, index);
                    // Console.WriteLine(tempstr);
                    result += tempstr;
                    i += 2;
                }
                // 结束
                else if (answerdata[i] == 0)
                {
                    // Console.WriteLine("End, result: " + result);
                    break;
                }
                else
                {
                    byte[] temp = new byte[answerdata[i]];
                    Array.Copy(answerdata, i + 1, temp, 0, answerdata[i]);
                    string str = Encoding.ASCII.GetString(temp);
                    result += str;
                    // Console.WriteLine(str);
                    if (answerdata[i + answerdata[i] + 1] != 0)
                    {
                        result += ".";
                    }
                    i += answerdata[i] + 1;
                }
            }
            // Console.WriteLine(result);
            return result;
        }
    }
}

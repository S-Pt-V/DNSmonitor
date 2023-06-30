using System.Net;
using System.Net.Sockets;
using System.Text;
using static DNSmonitor.Models.Headers;

namespace DNSmonitor.Models
{
    /// <summary>
    /// 监视器类
    /// </summary>
    public class Monitor
    {
        // private readonly ILogger<MonitorController> _logger;

        // 监听用的IP
        // const string IP = "10.200.1.66";
        const string IP = "192.168.51.214";
        // const string IP = "59.220.240.1";
        // const string IP = "59.220.240.2";
        // 接收缓冲区长度
        private int recv_buffer_length;
        // 接收缓冲区
        private byte[] recv_buffer;
        // 原始套接字，用于监听TCP、UDP数据包
        private static Socket rawsocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        // 原始套接字设置参数
        const int SIO_R = unchecked((int)0x98000001);
        const int SIO_1 = unchecked((int)0x98000002);
        const int SIO_2 = unchecked((int)0x98000003);

        // UDP套接字
        private Socket udpsocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        // 服务器IP
        private const string syslog_ip ="59.220.216.129";
        private const int syslog_port = 51456;
        private IPEndPoint syslog_endpoint = new IPEndPoint(IPAddress.Parse(syslog_ip), syslog_port);

        /// <summary>
        /// rawsocket监听线程
        /// </summary>
        private Thread Listener;
        private bool keeplistening;

        /// <summary>
        /// 构造函数
        /// </summary>
        // public Monitor(ILogger<MonitorController> logger)
        public Monitor()
        {
            // _logger = logger;
            // IP数据包虽大长度为65536
            recv_buffer_length = 65536;
            recv_buffer = new byte[recv_buffer_length];

            // 监听线程设置
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
        }

        /// <summary>
        /// 启动监听器
        /// </summary>
        public void Run()
        {
            Listener.Start();
            // _logger.LogInformation("Thread Listener started: " + Listener.ManagedThreadId.ToString());
            Console.WriteLine("Thread Listener started: " + Listener.ManagedThreadId.ToString());
        }

        /// <summary>
        /// 停止监听器
        /// </summary>
        public void Stop()
        {
            if (rawsocket == null)
            {
                // _logger.LogInformation("rawsocket is null");
                Console.WriteLine("rawsocket is null");
                return;
            }
            keeplistening = false;
            rawsocket.Shutdown(SocketShutdown.Both);
            rawsocket.Close();
            rawsocket.Dispose();
            // _logger.LogInformation("rawsocket stopped");
            Console.WriteLine("rawsocket stopped");
        }

        /// <summary>
        /// 原始套接字设置
        /// </summary>
        public bool SocketSetup()
        {
            try
            {
                //**************************************************************************************
                // 创建rawsocket
                // rawsocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                // rawsocket.Blocking = false;
                // _logger.LogInformation("Rawsocket created.");

                // socket绑定到IP终结点
                rawsocket.Bind(new IPEndPoint(IPAddress.Parse(IP), 0));
                // rawsocket.Bind(new IPEndPoint(IPAddress.Any, 0));
                // _logger.LogInformation("Rawsocket binded on " + IP);
                Console.WriteLine("Rawsocket binded on " + IP);

                // 设置Rawsocket功能
                // _logger.LogInformation("Set socket Option.");
                Console.WriteLine("Set socket Option.");
                rawsocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];

                int ret_code = rawsocket.IOControl(SIO_R, IN, OUT);
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];
                if (ret_code != 0)
                {
                    // _logger.LogError("ret_code not 0 --SetSocketOption");
                    Console.WriteLine("ret_code not 0 --SetSocketOption");
                    return false;
                }
                // _logger.LogInformation("Socket option set.");
                Console.WriteLine("Socket option set.");
                //**************************************************************************************
                // udpsocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                // _logger.LogInformation("Udpsocket created");
                udpsocket.Bind(new IPEndPoint(IPAddress.Any, 55144));
                // _logger.LogInformation("Udpsocket binded");
                return true;
            }
            catch(Exception e)
            {
                // _logger.LogError(e.ToString());
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
                    // _logger.LogInformation(recved.ToString() + " bytes received");
                    byte[] packet = new byte[recved];
                    Array.Copy(recv_buffer, 0, packet, 0, recved);
                    ResloveIPPacket(packet, recved);
                    // _logger.LogInformation(BitConverter.ToString(packet));
                }
            }
        }

        /// <summary>
        /// 解析IP数据包
        /// </summary>
        /// <param name="packet">IP数据包的字节数组</param>
        /// <param name="recved">数据包长度</param>
        unsafe private void ResloveIPPacket(byte[] packet, int recved)
        {
            IPPacket ip_packet = new IPPacket();
            fixed (byte* fixed_buf = packet)
            {
                IPHeader* header = (IPHeader*)fixed_buf;
                // IP协议版本
                ip_packet.version = (uint)(header->ip_verlen & 0xF0) >> 4;
                // IP数据包头部长度
                ip_packet.headerlength = (uint)(header->ip_verlen & 0x0F) << 2;
                // IP服务类型
                ip_packet.tos = (byte)header->ip_tos;
                // 数据包总长度
                ip_packet.totallength = (ushort)(fixed_buf[2] * 256 + fixed_buf[3]);
                // id
                ip_packet.identification = (ushort)header->ip_id;
                // 偏移
                ip_packet.offset = (ushort)header->ip_offset;
                // 生存周期
                ip_packet.ttl = (byte)header->ip_ttl;
                // 协议类型的字节数据
                byte protocol_byte = (byte)header->ip_protocol;
                // 校验和
                ip_packet.checksum = (ushort)header->ip_checksum;
                // 源地址
                ip_packet.src_addr = new IPAddress(header->ip_srcaddr).ToString();
                // 目的地址
                ip_packet.dst_addr = new IPAddress(header->ip_dstaddr).ToString();
                // 获取数据内容
                ip_packet.data = new byte[recved - ip_packet.headerlength];
                Array.Copy(packet, ip_packet.headerlength, ip_packet.data, 0, recved - ip_packet.headerlength);
                // 协议类型
                switch (protocol_byte)
                {
                    case 1:
                        ip_packet.protocol = "ICMP";
                        break;
                    case 2:
                        ip_packet.protocol = "IGMP";
                        break;
                    case 6:
                        ip_packet.protocol = "TCP";
                        break;
                    case 17:
                        ip_packet.protocol = "UDP";
                        UDPresolve(ip_packet, packet);
                        break;
                    default:
                        ip_packet.protocol = "UNKONOWN";
                        break;
                }
            }
        }

        /// <summary>
        /// UDP数据包解析
        /// </summary>
        /// <param name="packet">packet对象</param>
        /// <param name="origionalpacket">原始的packet</param>
        unsafe private void UDPresolve(IPPacket packet, byte[] origionalpacket)
        {
            UDPdatagram udpdatagram = new UDPdatagram();
            fixed (byte* fixed_buf = packet.data)
            {
                UDPHeader* udpheader = (UDPHeader*)fixed_buf;
                udpdatagram.srcport = (ushort)(fixed_buf[0] * 256 + fixed_buf[1]);
                udpdatagram.dstport = (ushort)(fixed_buf[2] * 256 + fixed_buf[3]);
                udpdatagram.length = (ushort)(fixed_buf[4] * 256 + fixed_buf[5]);
                udpdatagram.checksum = (ushort)(fixed_buf[6] * 256 + fixed_buf[7]);
                udpdatagram.datagram = new byte[packet.data.Length - 8];
                Array.Copy(packet.data, 8, udpdatagram.datagram, 0, packet.data.Length - 8);
            }
            if(udpdatagram.srcport == 53 || udpdatagram.dstport == 53)
            {
                DNSfilter(packet, udpdatagram);
            }
        }

        /// <summary>
        /// 过滤DNS相关数据
        /// </summary>
        unsafe private void DNSfilter(IPPacket packet, UDPdatagram udpdatagram)
        {
            try
            {
                Console.WriteLine("\n\n*************************************************************************************************");
                Console.WriteLine(BitConverter.ToString(udpdatagram.datagram));
                
                // 复制udp数据报中的数据部分
                byte[] datagram = new byte[udpdatagram.datagram.Length];
                Array.Copy(udpdatagram.datagram, 0, datagram, 0, udpdatagram.datagram.Length);

                // 存放解析后的dns数据报信息
                DNSdatagram dns = new DNSdatagram();

                // 12字节首部
                // 前两字节为标识
                dns.Transaction_id = (ushort)(datagram[0] * 256 + datagram[1]);
                // 二、三字节为各个标志位
                // QR 0：请求 1：响应
                dns.QR = (datagram[2] & 0b10000000) >> 7;
                dns.Opcode = (datagram[2] & 0b01111000) >> 3;
                dns.AA = (datagram[2] & 0b00000100) >> 2;
                dns.TC = (datagram[2] & 0b00000010) >> 1;
                dns.RD = (datagram[2] & 0b00000001);
                dns.RA = (datagram[3] & 0b10000000) >> 7;
                dns.Zeros = (datagram[3] & 0b01110000) >> 4;
                dns.Rcode = (datagram[3] & 0b00001111);
                //问题数
                dns.Questions = datagram[4] * 256 + datagram[5];
                //资源记录数
                dns.Answer_RRs = datagram[6] * 256 + datagram[7];
                //授权资源记录数
                dns.Authority_RRs = datagram[8] * 256 + datagram[9];
                //额外资源记录数
                dns.Additional_RRs = datagram[10] * 256 + datagram[11];
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine("Queries: {0}\tAnswer RRs: {1}\tAuthorities RRs: {2}\tAdditional RRs: {3}", dns.Questions.ToString(), dns.Answer_RRs.ToString(), dns.Authority_RRs.ToString(), dns.Additional_RRs.ToString());

                /*
                 * 问题部分
                 * 初始第一个（可能有多个query）query位于DNS首部之后，即第13个字节开始
                 * 
                 * 每个query结构为：
                 * [一个字节表示的长度][标识符名称][一字节长度][标识符名称].....[0x00]
                 * [两字节查询类型][两字节查询名称]
                 */

                // 第一个query从第13字节开始，在字节数组中的位置为12
                dns.Queries = new List<Dns_query>();
                int index = 12;
                // 遍历每一个query
                for(int count = 0; count < dns.Questions; count++)
                {
                    // 一个query有多个标识符，每个标识符为一个字节数组
                    Dns_query query = new Dns_query();
                    int length = 0;
                    // length + 1 为下一个标识符的长度的索引值
                    for (; index < datagram.Length; index += length + 1)
                    {
                        // 长度值
                        length = datagram[index];
                        // 长度值为0，读取到根标识符，当前查询问题结束
                        if (length == 0)
                        {
                            // Console.WriteLine("Current question resolved");
                            break;
                        }
                        // 临时字节数组存储当前标识符字节数据
                        byte[] temp = new byte[length];
                        Array.Copy(datagram, index + 1, temp, 0, length);
                        query.Query_name += Encoding.ASCII.GetString(temp);
                        if (datagram[index + length + 1] != 0)
                        {
                            query.Query_name += ".";
                        }
                    }
                    // 0x00 后的四个个字节为查询类型和查询类
                    query.Query_type = datagram[index + 1] * 256 + datagram[index + 2];
                    query.Query_class = datagram[index + 3] * 256 + datagram[index + 4];
                    dns.Queries.Add(query);
                    // index直接指向下一个部分的开始
                    index += 5;
                }
                Console.WriteLine("-------------------------------------------------------------------------------------------------");
                Console.WriteLine(dns.Queries.Count.ToString() + " queries:");
                foreach(Dns_query query in dns.Queries)
                {
                    Console.WriteLine("Name: " + query.Query_name + "\tType: " + query.Query_type.ToString() + "\tClass: " + query.Query_class.ToString());
                }

                /*
                 * 应答部分
                 * 
                 * 应答部分结构如下：
                 * 
                 * 两个字节为该应答对应的名字，通常为两个字节。前两位为11表示为压缩表示方法，后续的14位表示该名字相对于包头的偏移位置
                 * 两个字节的type
                 * 两个字节的class
                 * 四个字节的生存周期
                 * 两个字节的数据长度
                 * 之后就是数据
                 * 
                 */
                // 遍历每个响应，在遍历完查询问题后，index的位置位于第一个响应的第一个字节，不出意外的话应该是一个 0xC0

                if (dns.Answer_RRs > 0)
                {
                    dns.AnswerRRs = new List<Dns_answer>();
                    for(int count = 0; count < dns.Answer_RRs; count++)
                    {
                        Dns_answer answer = new Dns_answer();
                        // 前两位为11，为压缩表示方法，使用后续的14位表示该字段相对于数据报的偏移
                        if ((datagram[index] & 0b11000000) == 0xC0)
                        {
                            // 后14位为该字段相对于DNS头部的偏移
                            int offset = (datagram[index] & 0b00111111) * 256 + datagram[index + 1];
                            answer.Answer_name = GetName(datagram, offset);
                            answer.Answer_type = (ushort)(datagram[index + 2] * 256 + datagram[index + 3]);
                            answer.Answer_class = (ushort)(datagram[index + 4] * 256 + datagram[index + 5]);
                            answer.Answer_ttl = datagram[index + 6] * 16777216 + datagram[index + 7] * 65536 + datagram[index + 8] * 256 + datagram[index + 9];
                            answer.Answer_datalength = (ushort)(datagram[index + 10] * 256 + datagram[index + 11]);
                            index += 12;
                            byte[] answerdata = new byte[answer.Answer_datalength];
                            Array.Copy(datagram, index, answerdata, 0, answer.Answer_datalength);
                            answer.Answer_data = GetAnswerData(answer.Answer_type, answer.Answer_class, answerdata, datagram);
                            index += answer.Answer_datalength;
                            dns.AnswerRRs.Add(answer);
                        }
                        else if (datagram[index] <= 0xFF)
                        {
                            Console.WriteLine("好像不该这样datagram[" + index.ToString() + "] <= 0xFF");
                        }
                        else
                        {
                            Console.WriteLine("不对劲");
                        }
                    }
                    Console.WriteLine("-------------------------------------------------------------------------------------------------");
                    Console.WriteLine(dns.AnswerRRs.Count.ToString() + " responses:");
                    foreach (Dns_answer answer in dns.AnswerRRs)
                    {
                        Console.WriteLine("Type: {0}\tClass: {1}\t TTL:{2}\tLength: {3}\tname:{4}\tdata: {5}", answer.Answer_type.ToString(), answer.Answer_class.ToString(), answer.Answer_ttl.ToString(), answer.Answer_datalength.ToString(), answer.Answer_name, answer.Answer_data);
                    }
                }
            }
            catch (Exception e)
            {
                // _logger.LogError(e.ToString());
                Console.WriteLine(e.ToString());
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
            // int length;
            for (;index < datagram.Length; index += datagram[index] + 1)
            {
                // length = datagram[index];
                // Console.WriteLine("index:{0} length:{1}", index.ToString(), datagram[index].ToString());
                if((datagram[index] & 0b11000000) == 0xC0)
                {
                    int name_index = (datagram[index] & 0b00111111) * 256 + datagram[index + 1];
                    Console.WriteLine("index: {0}   location:{1}", index.ToString(), name_index.ToString());
                    name += GetName(datagram, name_index);
                    index += 2;
                }
                // 长度为0表示名称的结束
                if(datagram[index] == 0)
                {
                    Console.WriteLine("zero index: {0}", index.ToString());
                    return name;
                }
                byte[] temp = new byte[datagram[index]];
                Array.Copy(datagram, index + 1, temp, 0, datagram[index]);
                name += Encoding.ASCII.GetString(temp);
                if (datagram[index + datagram[index] + 1] != 0)
                {
                    name += ".";
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
        private string GetAnswerData(ushort atype, ushort aclass, byte[] adatabytes, byte[] dnsdatagram)
        {
            string result = "";

            switch (atype)
            {
                // A
                case 1:
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
                    result = CNAMEresolve(adatabytes, dnsdatagram);
                    Console.WriteLine("CNAME\t" + aclass.ToString() + "\t" + adatabytes.Length.ToString() + " bytes data: " + result);
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
        public string CNAMEresolve(byte[] answerdata, byte[] dnsdatagram)
        {
            string result = "";
            for(int i = 0; i < answerdata.Length;)
            {
                // 需要在原始的DNS数据包中寻找指向的域名
                if((answerdata[i] & 0b11000000) == 0xC0)
                {
                    int index = (answerdata[i] & 0b00111111) * 256 + answerdata[i + 1];
                    Console.WriteLine("压缩显示 index {0}", index.ToString());
                    result += GetName(dnsdatagram, index);
                    i += 2;
                }
                // 结束
                else if (answerdata[i] == 0)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("index {0} length {1}", i.ToString(), answerdata[i].ToString());
                    byte[] temp = new byte[answerdata[i]];
                    Array.Copy(answerdata, i + 1, temp, 0, answerdata[i]);
                    result += Encoding.ASCII.GetString(temp);
                    if (answerdata[i + answerdata[i] + 1] != 0)
                    {
                        result += ".";
                    }
                    i += answerdata[i] + 1;
                }

            }
            return result;
        }
    }
}

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
                    byte[] packet = new byte[recved];
                    Array.Copy(recv_buffer, 0, packet, 0, recved);
                    ResloveIPPacket(packet, recved);
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
                ip_packet.Version = (uint)(header->ip_verlen & 0xF0) >> 4;
                // IP数据包头部长度
                ip_packet.Headerlength = (uint)(header->ip_verlen & 0x0F) << 2;
                // IP服务类型
                ip_packet.Tos = (byte)header->ip_tos;
                // 数据包总长度
                ip_packet.Totallength = (ushort)(fixed_buf[2] * 256 + fixed_buf[3]);
                // id
                ip_packet.Identification = (ushort)header->ip_id;
                // 偏移
                ip_packet.Offset = (ushort)header->ip_offset;
                // 生存周期
                ip_packet.Ttl = (byte)header->ip_ttl;
                // 协议类型的字节数据
                byte protocol_byte = (byte)header->ip_protocol;
                // 校验和
                ip_packet.Checksum = (ushort)header->ip_checksum;
                // 源地址
                ip_packet.Src_addr = new IPAddress(header->ip_srcaddr).ToString();
                // 目的地址
                ip_packet.Dst_addr = new IPAddress(header->ip_dstaddr).ToString();
                // 获取数据内容
                ip_packet.Data = new byte[recved - ip_packet.Headerlength];
                Array.Copy(packet, ip_packet.Headerlength, ip_packet.Data, 0, recved - ip_packet.Headerlength);
                // 协议类型
                switch (protocol_byte)
                {
                    case 1:
                        ip_packet.Protocol = "ICMP";
                        break;
                    case 2:
                        ip_packet.Protocol = "IGMP";
                        break;
                    case 6:
                        ip_packet.Protocol = "TCP";
                        break;
                    case 17:
                        ip_packet.Protocol = "UDP";
                        UDPresolve(ip_packet, packet);
                        break;
                    default:
                        ip_packet.Protocol = "UNKONOWN";
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
            fixed (byte* fixed_buf = packet.Data)
            {
                UDPHeader* udpheader = (UDPHeader*)fixed_buf;
                udpdatagram.srcport = (ushort)(fixed_buf[0] * 256 + fixed_buf[1]);
                udpdatagram.dstport = (ushort)(fixed_buf[2] * 256 + fixed_buf[3]);
                udpdatagram.length = (ushort)(fixed_buf[4] * 256 + fixed_buf[5]);
                udpdatagram.checksum = (ushort)(fixed_buf[6] * 256 + fixed_buf[7]);
                if(packet.Data == null)
                {
                    Console.WriteLine("packet.Data is null, operation break;");
                    return;
                }
                udpdatagram.datagram = new byte[packet.Data.Length - 8];
                Array.Copy(packet.Data, 8, udpdatagram.datagram, 0, packet.Data.Length - 8);
            }
            if(udpdatagram.srcport == 53 || udpdatagram.dstport == 53)
            {
                DNSfilter(udpdatagram, packet);
            }
        }

        /// <summary>
        /// 过滤并解析DNS数据报
        /// </summary>
        /// <param name="udpdatagram"></param>
        /// <param name="packet"></param>
        unsafe private void DNSfilter(UDPdatagram udpdatagram, IPPacket packet)
        {
            try
            {
                Console.WriteLine("\n\n*************************************************************************************************");
                Console.WriteLine(BitConverter.ToString(udpdatagram.datagram));
                
                // 复制udp数据报中的数据部分
                byte[] dns_datagram = new byte[udpdatagram.datagram.Length];
                Array.Copy(udpdatagram.datagram, 0, dns_datagram, 0, udpdatagram.datagram.Length);

                // 存放解析后的dns数据报信息
                DNSdatagram dns = new DNSdatagram();

                // 12字节首部
                // 前两字节为标识
                dns.Transaction_id = (ushort)(dns_datagram[0] * 256 + dns_datagram[1]);
                // 二、三字节为各个标志位
                // QR 0：请求 1：响应
                dns.QR = (dns_datagram[2] & 0b10000000) >> 7;
                dns.Opcode = (dns_datagram[2] & 0b01111000) >> 3;
                dns.AA = (dns_datagram[2] & 0b00000100) >> 2;
                dns.TC = (dns_datagram[2] & 0b00000010) >> 1;
                dns.RD = (dns_datagram[2] & 0b00000001);
                dns.RA = (dns_datagram[3] & 0b10000000) >> 7;
                dns.Zeros = (dns_datagram[3] & 0b01110000) >> 4;
                dns.Rcode = (dns_datagram[3] & 0b00001111);
                //问题数
                dns.Questions = dns_datagram[4] * 256 + dns_datagram[5];
                //资源记录数
                dns.Answer_RRs = dns_datagram[6] * 256 + dns_datagram[7];
                //授权资源记录数
                dns.Authority_RRs = dns_datagram[8] * 256 + dns_datagram[9];
                //额外资源记录数
                dns.Additional_RRs = dns_datagram[10] * 256 + dns_datagram[11];
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
                    for (; index < dns_datagram.Length; index += length + 1)
                    {
                        // 长度值
                        length = dns_datagram[index];
                        // 长度值为0，读取到根标识符，当前查询问题结束
                        if (length == 0)
                        {
                            // Console.WriteLine("Current question resolved");
                            break;
                        }
                        // 临时字节数组存储当前标识符字节数据
                        byte[] temp = new byte[length];
                        Array.Copy(dns_datagram, index + 1, temp, 0, length);
                        query.Query_name += Encoding.ASCII.GetString(temp);
                        if (dns_datagram[index + length + 1] != 0)
                        {
                            query.Query_name += ".";
                        }
                    }
                    // 0x00 后的四个个字节为查询类型和查询类
                    query.Query_type = dns_datagram[index + 1] * 256 + dns_datagram[index + 2];
                    query.Query_class = dns_datagram[index + 3] * 256 + dns_datagram[index + 4];
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
                 * 两字节名称
                 * 两字节 type
                 * 两字节 class
                 * 两字节 ttl
                 * 两字节 数据长度
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
                        // Console.WriteLine("getting number {0} answer", count.ToString());
                        Dns_answer answer = new Dns_answer();
                        // 前两位为11，为压缩表示方法，使用后续的14位表示该字段相对于数据报的偏移
                        if ((dns_datagram[index] & 0b11000000) == 0xC0)
                        {
                            // 后14位为该字段相对于DNS头部的偏移
                            int offset = (dns_datagram[index] & 0b00111111) * 256 + dns_datagram[index + 1];
                            answer.Answer_name = GetName(dns_datagram, offset);
                            answer.Answer_type = (ushort)(dns_datagram[index + 2] * 256 + dns_datagram[index + 3]);
                            answer.Answer_class = (ushort)(dns_datagram[index + 4] * 256 + dns_datagram[index + 5]);
                            answer.Answer_ttl = dns_datagram[index + 6] * 16777216 + dns_datagram[index + 7] * 65536 + dns_datagram[index + 8] * 256 + dns_datagram[index + 9];
                            answer.Answer_datalength = (ushort)(dns_datagram[index + 10] * 256 + dns_datagram[index + 11]);
                            index += 12;
                            byte[] answerdata = new byte[answer.Answer_datalength];
                            Array.Copy(dns_datagram, index, answerdata, 0, answer.Answer_datalength);

                            answer.Answer_data = GetAnswerData(answer.Answer_type, answer.Answer_class, answerdata, dns_datagram);
                            
                            index += answer.Answer_datalength;
                            dns.AnswerRRs.Add(answer);
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

                /*
                 * 
                 * 权威应答部分
                 * 
                 * 两字节 name
                 * 两字节 type
                 * 两字节 class
                 * 四字节 ttl
                 * 两字节 data length
                 * 
                 * Primary name Server                  跟名称一样
                 * Responsible authority's mail box     跟名称一样
                 * Serial Number                        四字节
                 * Refersh Interval                     四字节
                 * Retry Interval                       四字节
                 * Expire limit                         四字节
                 * Minimum ttl                          四字节
                 * 
                 */
                if (dns.Authority_RRs > 0)
                {
                    dns.AuthorityRRs = new List<Dns_authorityRR>();
                    for(int count = 0; count < dns.Authority_RRs;  count++)
                    {
                        Dns_authorityRR authorityRR = new Dns_authorityRR();
                        // 解析数据包头部，名称应该是一个压缩格式指向的位置
                        if ((dns_datagram[index] & 0b11000000) == 0xC0)
                        {
                            int offset = (dns_datagram[index] & 0b00111111) * 256 + dns_datagram[index + 1];
                            authorityRR.Name = GetName(dns_datagram, offset);
                            authorityRR.Type = (ushort)(dns_datagram[index + 2] * 256 + dns_datagram[index + 3]);
                            authorityRR.Class = (ushort)(dns_datagram[index + 4] * 256 + dns_datagram[index + 5]);
                            authorityRR.TTL = dns_datagram[index + 6] * 16777216 + dns_datagram[index + 7] * 65536 + dns_datagram[index + 8] * 256 + dns_datagram[index + 9];
                            authorityRR.Datalength = (ushort)(dns_datagram[index + 10] * 256 + dns_datagram[index + 11]);
                            index += 12;
                            byte[] databytes = new byte[authorityRR.Datalength];
                            Array.Copy(dns_datagram, index, databytes, 0, authorityRR.Datalength);
                            // Console.WriteLine("权威应答： {0} {1} {2} {3} {4}", authorityRR.Name, authorityRR.Type, authorityRR.Class, authorityRR.TTL, authorityRR.Datalength);
                            // Console.WriteLine(BitConverter.ToString(databytes));
                            
                            // authorityRR.Primary_Name_Server
                            authorityRR.Primary_Name_Server = "";
                            int i = 0;
                            for(; i < databytes.Length;)
                            {
                                if ((databytes[i] & 0xC0) == 0xC0)
                                {
                                    int location = (databytes[i] & 0b00111111) * 256 + databytes[i + 1];
                                    // 获取在该位置的名称
                                    authorityRR.Primary_Name_Server += GetName(dns_datagram, location);
                                    i += 2;
                                    break;
                                }
                                else
                                {
                                    int length = databytes[i];
                                    byte[] temp = new byte[length];
                                    Array.Copy(databytes, i+1, temp, 0, length);
                                    authorityRR.Primary_Name_Server += Encoding.ASCII.GetString(temp);
                                    i += length + 1;
                                    if (databytes[i] != 0)
                                    {
                                        authorityRR.Primary_Name_Server += ".";
                                    }
                                    else
                                    {
                                        i += 1;
                                        break;
                                    }
                                }
                            }
                            // Console.WriteLine("Primary_Name_Server: " + authorityRR.Primary_Name_Server);

                            // authorityRR.Responsible_Authority_Mailbox
                            authorityRR.Responsible_Authority_Mailbox = "";
                            for (; i < databytes.Length;)
                            {
                                if ((databytes[i] & 0xC0) == 0xC0)
                                {
                                    int location = (databytes[i] & 0b00111111) * 256 + databytes[i + 1];
                                    // 获取在该位置的名称
                                    authorityRR.Responsible_Authority_Mailbox += GetName(dns_datagram, location);
                                    i += 2;
                                    break;
                                }
                                else
                                {
                                    int length = databytes[i];
                                    byte[] temp = new byte[length];
                                    Array.Copy(databytes, i + 1, temp, 0, length);
                                    authorityRR.Responsible_Authority_Mailbox += Encoding.ASCII.GetString(temp);
                                    i += length + 1;
                                    if (databytes[i] != 0)
                                    {
                                        authorityRR.Responsible_Authority_Mailbox += ".";
                                    }
                                    else
                                    {
                                        i += 1;
                                        break;
                                    }
                                }
                            }
                            // Console.WriteLine("Responsible_Authority_Mailbox: " + authorityRR.Responsible_Authority_Mailbox);

                            // authorityRR.Serial_Number
                            byte[] tempstr = new byte[4];
                            Array.Copy(databytes, i, tempstr, 0, 4);
                            authorityRR.Serial_Number = BitConverter.ToString(tempstr);
                            i += 4;
                            // authorityRR.Refersh_Interval
                            authorityRR.Refresh_Interval = databytes[i] * 16777216 + databytes[i + 1] * 65536 + databytes[i + 2] * 256 + databytes[i + 3];
                            i += 4;
                            // authorityRR.Retry_Interval
                            authorityRR.Expire_Interval = databytes[i] * 16777216 + databytes[i + 1] * 65536 + databytes[i + 2] * 256 + databytes[i + 3];
                            i += 4;
                            // authorityRR.Expire_Interval
                            authorityRR.Retry_Interval = databytes[i] * 16777216 + databytes[i + 1] * 65536 + databytes[i + 2] * 256 + databytes[i + 3];
                            i += 4;
                            // authorityRR.Minimum_Interval
                            authorityRR.Minimum_Interval = databytes[i] * 16777216 + databytes[i + 1] * 65536 + databytes[i + 2] * 256 + databytes[i + 3];
                            i += 4;
                        }
                        else
                        {
                            Console.WriteLine("不对劲          -AuthorityRR");
                        }
                        dns.AuthorityRRs.Add(authorityRR);
                    }
                    Console.WriteLine("-------------------------------------------------------------------------------------------------");
                    Console.WriteLine(dns.AuthorityRRs.Count.ToString() + " auth RRs:");
                    foreach (Dns_authorityRR authorityRR in dns.AuthorityRRs)
                    {
                        Console.WriteLine("Name: {0} Type: {1} Class: {2} Primary_Name_Server: {3} Responsible_Authority_Mailbox: {4} Serial_Number: {5} Refresh_Interval:{6} Retry_Interval: {7} Expire_Interval: {8} Minimum_Interval: {9}",
                            authorityRR.Name,
                            authorityRR.Type.ToString(),
                            authorityRR.Class.ToString(),
                            authorityRR.Primary_Name_Server,
                            authorityRR.Responsible_Authority_Mailbox,
                            authorityRR.Serial_Number,
                            authorityRR.Refresh_Interval.ToString(),
                            authorityRR.Retry_Interval.ToString(),
                            authorityRR.Expire_Interval.ToString(),
                            authorityRR.Minimum_Interval.ToString()
                            );
                    }
                }

                /*
                 * 
                 * 额外记录部分
                 * 
                 */

                if(dns.Additional_RRs  > 0)
                {
                    Console.WriteLine("额外记录");
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
            // Console.WriteLine("GetName at {0}, datagram length is {1}", index.ToString(), datagram.Length.ToString());
            string name = "";
            // int length;
            //  index < datagram.Length是不是不太合适，得要找个方法得到这个字段的长度
            for (;index < datagram.Length;)
            {
                // Console.WriteLine("current index: {0}  length under this index:{1}", index.ToString(), datagram[index].ToString());
                // length = datagram[index];
                // Console.WriteLine("index:{0} length:{1}", index.ToString(), datagram[index].ToString());
                if ((datagram[index] & 0b11000000) == 0xC0)
                {
                    int name_index = (datagram[index] & 0b00111111) * 256 + datagram[index + 1];
                    // Console.WriteLine("Compressed format, location is {0}", name_index.ToString());
                    string tempstr = GetName(datagram, name_index);
                    // Console.WriteLine(tempstr);
                    name += tempstr;
                    //Console.WriteLine("index: {0}   location:{1}  {2}", index.ToString(), name_index.ToString(), tempstr);
                    index += 2;
                    //Console.WriteLine("supposed to end");
                    /*
                     * 就是这个位置，如果不直接return会出问题
                     */
                    return name;
                }
                // 长度为0表示名称的结束
                if (datagram[index] == 0)
                {
                    // Console.WriteLine("Zero detected, end. Result: " + name);
                    return name;
                }
                else
                {
                    byte[] temp = new byte[datagram[index]];
                    // Console.WriteLine("Before copy. index: {0} length: {1}", index.ToString(), datagram[index].ToString());
                    Array.Copy(datagram, index + 1, temp, 0, datagram[index]);
                    string str = Encoding.ASCII.GetString(temp);
                    // Console.WriteLine(str);
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
        private string GetAnswerData(ushort atype, ushort aclass, byte[] adatabytes, byte[] dnsdatagram)
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
        public string CNAMEresolve(byte[] answerdata, byte[] dnsdatagram)
        {
            // Console.WriteLine("Resolve CNAME, TotalLength: {0}", answerdata.Length.ToString());
            string result = "";
            for(int i = 0; i < answerdata.Length;)
            {
                // Console.WriteLine("Current index: {0}, Current length: {1}", i.ToString(), answerdata[i].ToString());
                // 需要在原始的DNS数据包中寻找指向的域名
                if((answerdata[i] & 0b11000000) == 0xC0)
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

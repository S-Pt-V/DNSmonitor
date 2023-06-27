using DNSmonitor.Controllers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
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
        private readonly ILogger<MonitorController> _logger;

        // 监听用的IP
        const string IP = "10.200.1.66";
        // const string IP = "59.220.240.2";

        // 接收缓冲区长度
        private int recv_buffer_length;
        // 接收缓冲区
        private byte[] recv_buffer;

        // 原始套接字，用于监听TCP、UDP数据包
        private Socket? rawsocket;
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

            // 监听线程设置
            keeplistening = true;
            ParameterizedThreadStart? ListenerStart = new((obj) =>
            {
                if (!RawsocketSetup())
                {
                    _logger.LogError("rawsocket setup failed.");
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
            _logger.LogInformation("Thread Listener started: " + Listener.ManagedThreadId.ToString());
        }

        /// <summary>
        /// 停止监听器
        /// </summary>
        public void Stop()
        {
            if (rawsocket == null)
            {
                _logger.LogInformation("rawsocket is null");
                return;
            }
            keeplistening = false;
            rawsocket.Shutdown(SocketShutdown.Both);
            rawsocket.Close();
            rawsocket.Dispose();
            _logger.LogInformation("rawsocket stopped");
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
                _logger.LogInformation("Rawsocket created.");

                // socket绑定到IP终结点
                rawsocket.Bind(new IPEndPoint(IPAddress.Parse(IP), 0));
                // rawsocket.Bind(new IPEndPoint(IPAddress.Any, 0));
                _logger.LogInformation("Rawsocket binded on " + IP);

                // 设置Rawsocket功能
                _logger.LogInformation("Set socket Option.");
                rawsocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];

                int ret_code = rawsocket.IOControl(SIO_R, IN, OUT);
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];
                if (ret_code != 0)
                {
                    _logger.LogError("ret_code not 0 --SetSocketOption");
                    return false;
                }
                _logger.LogInformation("Socket option set.");
                
                return true;
            }
            catch(Exception e)
            {
                _logger.LogError(e.ToString());
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
                try
                {
                    ip_packet.data = new byte[recved - ip_packet.headerlength];
                    Array.Copy(packet, ip_packet.headerlength, ip_packet.data, 0, recved - ip_packet.headerlength);
                }
                catch(Exception e)
                {
                    _logger.LogError(e.ToString());
                    string packetstring = BitConverter.ToString(packet);
                    _logger.LogError(packetstring);
                    return;
                }
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
                        // TCPresolve(ip_packet);
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
        /// TCP数据包解析
        /// </summary>
        /// <param name="packet"></param>
        unsafe private void TCPresolve(IPPacket packet)
        {
            fixed(byte* fixed_buf = packet.data)
            {
                TCPHeader* tcpheader = (TCPHeader*)fixed_buf;
                ushort srcport = (ushort)(fixed_buf[0] * 256 + fixed_buf[1]);
                ushort dstport = (ushort)(fixed_buf[2] * 256 + fixed_buf[3]);
                // _logger.LogInformation("TCP\t" + packet.src_addr + ":" + srcport.ToString() + "\t->\t" + packet.dst_addr + ":" + dstport.ToString());
            }
            // _logger.LogInformation("TCP\t" + packet.headerlength.ToString() + "\t" + packet.data.Length.ToString());
        }

        /// <summary>
        /// UDP数据包解析
        /// </summary>
        /// <param name="packet"></param>
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
                // _logger.LogInformation("UDP: " + packet.src_addr + ":" + udpdatagram.srcport.ToString() + "\t" + packet.dst_addr + ":" + udpdatagram.dstport.ToString() + "\t" + datagram.datagram.Length + "Bytes");
                
                DNSfilter(packet, udpdatagram, origionalpacket);
            }
        }

        /// <summary>
        /// 过滤DNS相关数据
        /// </summary>
        unsafe private void DNSfilter(IPPacket packet, UDPdatagram udpdatagram, byte[] origionalpacket)
        {
            try
            {
                // 筛选源或目的端口为53的数据，可能是DNS请求和响应
                if (udpdatagram.srcport == 53 || udpdatagram.dstport == 53)
                {
                    _logger.LogInformation(BitConverter.ToString(origionalpacket));

                    // 直接从UDP端口转发


                    /*
                    // 复制udp数据报中的数据部分
                    byte[] datagram = new byte[udpdatagram.datagram.Length];
                    Array.Copy(udpdatagram.datagram, 0, datagram, 0, udpdatagram.datagram.Length);
                    
                    _logger.LogInformation("数据包总长度： " + datagram.Length.ToString() + " Bytes");
                    _logger.LogInformation(BitConverter.ToString(datagram));

                    DNSdatagram dns = new DNSdatagram();

                    // 12字节首部
                    // 前两字节为标识
                    dns.identification = (ushort)(datagram[0] * 256 + datagram[1]);
                    // 二、三字节为各个标志位
                    dns.QR = (datagram[2] & 0b10000000) >> 7;
                    dns.opcode = (datagram[2] & 0b01111000) >> 3;
                    dns.AA = (datagram[2] & 0b00000100) >> 2;
                    dns.TC = (datagram[2] & 0b00000010) >> 1;
                    dns.RD = (datagram[2] & 0b00000001);
                    dns.RA = (datagram[3] & 0b10000000) >> 7;
                    dns.zeros = (datagram[3] & 0b01110000) >> 4;
                    dns.rcode = (datagram[3] & 0b00001111);
                    */
                    // _logger.LogInformation("原始数据: " + BitConverter.ToString(datagram, 2, 1) + "\t与运算: " + (datagram[2] & 0b10000000).ToString() + "\tQR: " + ((datagram[2] & 0b10000000) >> 7).ToString());
                    /*
                    switch (dns.QR)
                    {
                        case 0:
                            _logger.LogInformation("DNS请求\t" + packet.src_addr + "->" + packet.dst_addr);
                            break;
                        case 1:
                            _logger.LogInformation("DNS响应\t" + packet.src_addr + "->" + packet.dst_addr);
                            break;
                        default:
                            _logger.LogError("数据类型未知");
                            break;
                    }
                    */
                    /*
                    //问题数
                    dns.questionnum = datagram[4] * 256 + datagram[5];
                    //资源记录数
                    dns.resource_record_num = datagram[6] * 256 + datagram[7];
                    //授权资源记录数
                    dns.authresource_record_num = datagram[8] * 256 + datagram[9];
                    //额外资源记录数
                    dns.extraresource_record_num = datagram[10] * 256 + datagram[11];
                    // _logger.LogInformation("问题数：" + dns.questionnum.ToString() + "\t资源记录数：" + dns.resource_record_num.ToString() + "\t授权资源记录数：" + dns.authresource_record_num.ToString() + "\t额外资源记录数：" + dns.extraresource_record_num.ToString());

                    // 问题部分
                    List<byte[]> identificators = new List<byte[]>();
                    int length = 0;
                    int index = 0;
                    for (index = 12; index < datagram.Length; index += length + 1)
                    {
                        length = datagram[index];
                        // _logger.LogInformation("datagram index: " + index.ToString() + "\t" + "identificator length: " + length.ToString());
                        if (length == 0)
                        {
                            // _logger.LogInformation("Root identificator detected");
                            break;
                        }
                        byte[] temp = new byte[length];
                        Array.Copy(datagram, index + 1, temp, 0, length);
                        identificators.Add(temp);
                    }
                    /*
                    foreach (byte[] identificator in identificators)
                    {
                        _logger.LogInformation(Encoding.ASCII.GetString(identificator));
                    }
                    */
                    //_logger.LogInformation("请求类型：" + ((int)(datagram[index + 1] * 256 + datagram[index + 2])).ToString() + "\t查询类：" + ((int)(datagram[index + 3] * 256 + datagram[index + 4])).ToString());

                    // 回答
                    /*
                    if(dns.QR == 1)
                    {
                        List<byte[]> answers = new List<byte[]>();
                        index += 5;
                        length = 0;
                        for(; index < datagram.Length; index += length + 1)
                        {
                            length = datagram[index];
                            _logger.LogInformation("Index: " + index.ToString() + "\tlength: " + length.ToString());
                            if (length == 0)
                            {
                                _logger.LogInformation("Answer end");
                                break;
                            }
                            byte[] temp = new byte[length];
                            Array.Copy(datagram, index + 1, temp, 0, length);
                            answers.Add(temp);
                        }
                    }
                    // 授权
                    // 额外信息
                    */
                }
            }
            catch(Exception e)
            {
                _logger.LogError(e.ToString());
            }
        }
    }
}

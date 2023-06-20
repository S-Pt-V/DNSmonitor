using DNSmonitor.Controllers;
using System.Net;
using System.Net.Sockets;
using static DNSmonitor.Models.Headers;

/*
 * Run -> CallReceive -> Receive -> OnPacketArrival
*/

namespace DNSmonitor.Models
{
    /// <summary>
    /// Rawsocket类定义
    /// </summary>
    public class Rawsocket
    {
        /// <summary>
        /// 日志记录
        /// </summary>
        private readonly ILogger<RawsocketController> _logger;

        private bool error_occured;
        /// <summary>
        /// 是否有错误发生
        /// </summary>
        public bool ErrorOccured
        {
            get
            {
                return error_occured;
            }
        }
        
        // 持续运行
        private bool KeepRunning;
        // 接收缓冲区长度
        private static int len_receive_buf;
        // 接收缓冲区
        private byte[] receive_buf_bytes;

        
        // socket对象
        private Socket? socket;
        // socket option 设置参数
        const int SIO_R = unchecked((int)0x98000001);
        const int SIO_1 = unchecked((int)0x98000002);
        const int SIO_2 = unchecked((int)0x98000003);

        /// <summary>
        /// 使用Rawsocket的监听线程
        /// </summary>
        public Thread Listener;
        private ParameterizedThreadStart listener = new((obj) =>
        {
            while (true)
            {
                Console.WriteLine("This is listener thread");
                Thread.Sleep(1000);
            }
        });
        /// <summary>
        /// 使用Udpsocket 发送 syslog 的线程
        /// </summary>
        public Thread Syslog;
        private ParameterizedThreadStart syslog = new((obj) =>
        {
            while (true)
            {
                Console.WriteLine("This is syslog thread");
                Thread.Sleep(1500);
            }
        });

        /// <summary>
        /// 构造函数
        /// </summary>
        public Rawsocket(ILogger<RawsocketController> logger)
        {
            _logger = logger;
            KeepRunning = true;
            error_occured = false;
            len_receive_buf = 98304;
            receive_buf_bytes = new byte[len_receive_buf];

            Listener = new Thread(listener);
            _logger.LogInformation("监听线程ID：" + Listener.ManagedThreadId.ToString());
            Syslog = new Thread(syslog);
            _logger.LogInformation("发送线程ID：" + Syslog.ManagedThreadId.ToString());
        }

        /// <summary>
        /// 创建并绑定套接字至指定IP地址
        /// </summary>
        /// <param name="IP">绑定的IP地址</param>
        public void CreateAndBindSocket(string IP)
        {
            Listener.Start();
            Syslog.Start();
            
            try
            {
                _logger.LogInformation("Creating and binding rawsocket on: " + IP);

                // 创建RAWsocket
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP)
                {
                    //非阻塞式socket
                    Blocking = false
                };
                _logger.LogInformation("Rawsocket created.");
                // socket绑定到IP终结点
                socket.Bind(new IPEndPoint(IPAddress.Parse(IP), 0));
                _logger.LogInformation("Rawsocket binded on " + IP);

                // 设置Rawsocket功能
                if (SetSocketOption() == false)
                {
                    error_occured = true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
                error_occured = true;
            }
            
        }

        /// <summary>
        /// 设置具有IO控制功能的Socket
        /// </summary>
        /// <returns></returns>
        private bool SetSocketOption()
        {
            _logger.LogInformation("Set socket Option.");
            bool ret_value = true;
            try
            {
                if (socket == null)
                {
                    _logger.LogError("socket is null --SetSocketOption");
                    ret_value = false;
                    return ret_value;
                }
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];

                int ret_code = socket.IOControl(SIO_R, IN, OUT);
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];
                if (ret_code != 0)
                {
                    _logger.LogError("ret_code not 0 --SetSocketOption");
                    ret_value = false;
                    return ret_value;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
                ret_value = false;
                return ret_value;
            }
            _logger.LogInformation("Socket option set.");
            return ret_value;
        }

        /// <summary>
        /// 运行RawSocket
        /// </summary>
        public void Run()
        {
            if (socket == null)
            {
                _logger.LogError("socket is null --Run");
                return;
            }
            try
            {
                IAsyncResult ar = socket.BeginReceive(receive_buf_bytes, 0, len_receive_buf, SocketFlags.None, new AsyncCallback(CallReceive), this);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
                return;
            }
        }

        /// <summary>
        /// 接收数据回调函数
        /// </summary>
        /// <param name="ar"></param>
        private void CallReceive(IAsyncResult ar)
        {
            try
            {
                if (socket == null)
                {
                    _logger.LogError("socket is null --CallReceive");
                    return;
                }
                int received_bytes = 0;
                received_bytes = socket.EndReceive(ar);
                Receive(receive_buf_bytes, received_bytes);
                if (KeepRunning)
                {
                    Run();
                }
            }
            catch(Exception ex)
            {
                _logger.LogError(ex.ToString());
                KeepRunning = false;
                return;
            }
        }

        /// <summary>
        /// 接收数据包
        /// 形成PacketArrivedEventArgs时间数据类对象，并引发PacketArrival事件
        /// </summary>
        /// <param name="buf">接收缓冲区</param>
        /// <param name="len">接收数据长度</param>
        unsafe private void Receive(byte[] buf, int len)
        {
            byte temp_protocol = 0;
            uint temp_version = 0;
            uint temp_ip_srcaddr = 0;
            uint temp_ip_dstaddr = 0;
            ushort temp_srcport = 0;
            ushort temp_dstport = 0;
            IPAddress temp_ip;

            PacketArrivedEventArgs e = new PacketArrivedEventArgs(len_receive_buf);

            fixed (byte* fixed_buf = buf)
            {
                // head指针指向接收到的数据包
                IPHeader* head = (IPHeader*)fixed_buf;
                // 获取头部长度，为首部中首部长度值乘以4
                e.HeaderLength = (uint)(head->ip_verlen & 0x0F) << 2;
                // 获取协议类型
                temp_protocol = head->ip_protocol;
                switch (temp_protocol)
                {
                    case 1:
                        e.Protocol = "ICMP";
                        break;
                    case 2:
                        e.Protocol = "IGMP";
                        break;
                    case 6:
                        e.Protocol = "TCP";
                        break;
                    case 17:
                        e.Protocol = "UDP";
                        break;
                    default:
                        e.Protocol = "Unknown";
                        break;
                }

                // 获取ip协议版本，为verlen中的前4位
                temp_version = (uint)(head->ip_verlen & 0xF0) >> 4;
                e.IpVersion = temp_version.ToString();

                // 获取源目地址
                temp_ip_srcaddr = head->ip_srcaddr;
                temp_ip_dstaddr = head->ip_dstaddr;
                temp_ip = new IPAddress(temp_ip_srcaddr);
                e.OriginationAddress = temp_ip.ToString();
                temp_ip = new IPAddress(temp_ip_dstaddr);
                e.DestinationAddress = temp_ip.ToString();

                // 获取源目端口
                temp_srcport = (ushort)((byte)fixed_buf[e.HeaderLength] * 256 + (byte)fixed_buf[e.HeaderLength + 1]);
                temp_dstport = (ushort)((byte)fixed_buf[e.HeaderLength + 2] * 256 + (byte)fixed_buf[e.HeaderLength + 3]);
                e.OriginationPort = temp_srcport.ToString();
                e.DestinationPort = temp_dstport.ToString();

                e.TotalPacketlength = (uint)len;
                e.MessageLength = (uint)len - e.HeaderLength;
                
                _logger.LogInformation(e.OriginationAddress + ":" + e.OriginationPort + " -> " + e.DestinationAddress + ":" + e.DestinationPort + "\t" + e.Protocol + "\t" + len.ToString() + "Bytes"); 
                
                // 将首部数据和携带数据写入各自的缓存
                e.ReceiveBuffer = buf;
                Array.Copy(buf, 0, e.HeaderBuffer, 0, (int)e.HeaderLength);
                Array.Copy(buf, (int)e.HeaderLength, e.MessageBuffer, 0, (int)e.MessageLength);
            }
            OnPacketArrival(e);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        public delegate void PacketArrivedEventHandler(Object sender, PacketArrivedEventArgs args);

        /// <summary>
        /// PacketArrival事件
        /// </summary>
        public event PacketArrivedEventHandler? PacketArrival;

        /// <summary>
        /// PacketArrival事件的处理
        /// </summary>
        /// <param name="e"></param>
        protected virtual void OnPacketArrival(PacketArrivedEventArgs e)
        {
            try
            {
                // _logger.LogInformation("OnPacketArrival");
                if (PacketArrival != null)
                {
                    PacketArrival(this, e);
                }
                // SystemStackOverflowException Here
                // _logger.LogInformation(e.OriginationAddress + ":" + e.OriginationPort + " -> " + e.DestinationAddress + ":" + e.DestinationPort + "\t" + e.Protocol);
            }
            catch(Exception ex)
            {
                _logger.LogError(ex.ToString());
                KeepRunning = false;
                return;
            }
        }

        /// <summary>
        /// 关闭套接字
        /// </summary>
        public void Shutdown()
        {
            if (socket != null)
            {
                _logger.LogInformation("Shutting dwon socket.");
                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }
            else
            {
                _logger.LogError("socket is null --Shutdown");
            }
        }
    }
}

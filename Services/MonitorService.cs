using System.Net;
using System.Net.Sockets;
using DNSmonitor.Dataformat.NetworkLayer;
using DNSmonitor.Dataformat.TransportLayer;

namespace DNSmonitor.Services
{
    /// <summary>
    /// 监听服务类
    /// </summary>
    public class MonitorService
    {
        // 监听用的原始套接字
        private static Socket rawSocket;
        // 数据处理用的TaskFactory
        private static TaskFactory taskFactory;
        // 取消标记源
        private static CancellationTokenSource cts;

        // 本地IP地址
        private static string localip = "192.168.51.214";
        // private static IPAddress localIP;

        /// <summary>
        /// 类构造函数
        /// </summary>
        static MonitorService()
        {
            // 应该在此处自动获取监听ip地址？
            // localIP = Dns.GetHostEntry(Dns.GetHostName()).AddressList[0];
            
            // 原始套接字设置
            rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            rawSocket.Bind(new IPEndPoint(IPAddress.Parse(localip), 0));
            rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            // 设置网卡为混杂模式
            byte[] inBytes = new byte[] { 1, 0, 0, 0 };
            byte[] outBytes = new byte[] { 0, 0, 0, 0 };
            rawSocket.IOControl(IOControlCode.ReceiveAll, inBytes, outBytes);

            // 创建一个取消标记源
            cts = new CancellationTokenSource();

            // 创建TaskFactory
            //taskFactory = new TaskFactory();
            taskFactory = new TaskFactory(cts.Token);
        }

        /// <summary>
        /// 开始监听
        /// </summary>
        public static void CapturePacket()
        {
            // 接受缓冲区
            byte[] buffer = new byte[65536];
            // 异步回调方法
            AsyncCallback callback = new AsyncCallback(OnReceive);
            // 异步接收数据包
            rawSocket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, callback, buffer);
        }

        /// <summary>
        /// 停止监听
        /// </summary>
        public static void StopCapture()
        {
            cts.Cancel();
            rawSocket.Close();
            Console.WriteLine("Capture stopped...");
        }

        /// <summary>
        /// 接收数据包的回调方法
        /// </summary>
        static void OnReceive(IAsyncResult ar)
        {
            try
            {
                // 结束异步接收，并获取接收到的字节数
                int count = rawSocket.EndReceive(ar);
                // 获取传入的缓冲区
                byte[] buffer = (byte[])ar.AsyncState;
                // 继续接收
                if (!cts.IsCancellationRequested)
                {
                    CapturePacket();
                }
                if (count > 0)
                {
                    Task ProcessTask = taskFactory.StartNew(() => DataAnalyze(buffer, count));
                    ProcessTask.ContinueWith((t) => t.Dispose());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        /// <summary>
        /// 数据解析，在Task中执行
        /// </summary>
        /// <param name="buffer">由rawSocket直接抓取到的包含IP头部的原始数据包</param>
        /// <param name="count">字节数组长度</param>
        static void DataAnalyze(byte[] buffer, int count)
        {
            IPpacket packet = ResolveService.IPPacketResolve(buffer, count);
            if (packet == null)
            {
                Console.WriteLine("Packet is null");
                return;
            }
            // Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}\t{10} Bytes", packet.Version, packet.Header_length.ToString(), packet.Tos, packet.Total_length.ToString(), packet.Id.ToString(), packet.Offset.ToString(), packet.TTL.ToString(), packet.Protocol, packet.Src_addr, packet.Dst_addr, packet.Data.Length);
            switch(packet.Protocol)
            {
                case (ushort)IIIProtocol.ICMP:
                    Console.WriteLine("ICMP");
                    break;
                case (ushort)IIIProtocol.IGMP:
                    Console.WriteLine("IGMP");
                    break;
                case (ushort)IIIProtocol.TCP:
                    Console.WriteLine("TCP");
                    break;
                case (ushort)IIIProtocol.UDP:
                    UDPdatagram datagram = ResolveService.UDPdatagramResolve(packet.Data);
                    Console.WriteLine("{0}:{1}\t->\t{2}:{3}\t{4} Bytes", packet.Src_addr, datagram.Src_port, packet.Dst_addr, datagram.Dst_port, datagram.Data.Length);
                    break;
                default:
                    Console.WriteLine("UNKNOWN");
                    break;
            }
        }

    }
}

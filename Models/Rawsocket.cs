using System.Net.Sockets;

namespace DNSmonitor.Models
{
    /// <summary>
    /// 原始套接字
    /// </summary>
    public class Rawsocket
    {
        /// <summary>
        /// 监听IP
        /// </summary>
        public string listening_ip { get; set; }
        /// <summary>
        /// 套接字
        /// </summary>
        public Socket socket { get; set; }
        /// <summary>
        /// 接收数据计数
        /// </summary>
        public int recv_count { get; set; }
        /// <summary>
        /// 接收缓冲区长度
        /// </summary>
        public int recv_buffer_length { get; set; }
        /// <summary>
        /// 接收缓冲区
        /// </summary>
        public byte[] recv_buffer { get; set; }

        /// <summary>
        /// 构造函数
        /// </summary>
        public Rawsocket()
        {
            listening_ip = "10.200.1.66";
            recv_count = 0;
            recv_buffer_length = 65536;
            recv_buffer = new byte[recv_buffer_length];
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        }
    }
}

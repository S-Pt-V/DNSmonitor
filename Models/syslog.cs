namespace DNSmonitor.Models
{
    /// <summary>
    /// syslog 数据的对象内容
    /// </summary>
    public class Syslog
    {
        /// <summary>
        /// 源地址
        /// </summary>
        public string src_addr { get; set; }
        /// <summary>
        /// 源端口
        /// </summary>
        public ushort srt_port { get; set; }
        /// <summary>
        /// 目的地址
        /// </summary>
        public string dst_addr { get; set; }
        /// <summary>
        /// 目的端口
        /// </summary>
        public ushort dst_port { get; set; }
        /// <summary>
        /// 请求域名
        /// </summary>
        public string query { get; set; }
        /// <summary>
        /// 响应
        /// </summary>
        public string respond { get; set; }
    }
}

namespace DNSmonitor
{
    /// <summary>
    /// syslog记录的对象
    /// </summary>
    public class SyslogObj
    {
        /// <summary>
        /// 源主机地址
        /// </summary>
        public string? Source_ip { get; set; }
        /// <summary>
        /// 源主机地址
        /// </summary>
        public string? Destination_ip { get; set; }
        /// <summary>
        /// 0：请求    1：响应
        /// </summary>
        public byte QR { get; set; }
        /// <summary>
        /// 域名
        /// </summary>
        public string? Domain { get; set; }

    }
}

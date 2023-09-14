namespace DNSmonitor.Models
{
    /// <summary>
    /// 监听器的状态
    /// </summary>
    public class MonitorState
    {
        /// <summary>
        /// 监听的IP地址
        /// </summary>
        public string? Listen_ip { get; set; }
        /// <summary>
        /// Syslog服务器地址
        /// </summary>
        public string? Syslog_ip { get; set; }
        /// <summary>
        /// Syslog服务器端口
        /// </summary>
        public int Syslog_port { get; set; }
        /// <summary>
        /// 监听线程状态
        /// </summary>
        public string? ThreadState { get; set; }
        /// <summary>
        /// 是否持续监听
        /// </summary>
        public Boolean? Listening { get; set; }
    }
}

namespace DNSmonitor
{
    /// <summary>
    /// 网络层的IP数据包解析后的数据格式对象
    /// </summary>
    public class Packet
    {
        /// <summary>
        /// IP数据包版本号数据字典
        /// </summary>
        public static Dictionary<int, string> Version_dict = new Dictionary<int, string>()
        {
            { 4, "IPv4"},
            { 6, "IPv6"}
        };
        /// <summary>
        /// 数据部分协议数据字典
        /// </summary>
        public static Dictionary<int, string> Protocol_dict = new Dictionary<int, string>()
        {
            { 1, "TCMP"},
            { 2, "IGMP"},
            { 6, "TCP"},
            { 17, "UDP"}
        };

        /// <summary>
        /// 协议版本
        /// </summary>
        public uint Version { get; set; }
        /// <summary>
        /// 头部长度
        /// </summary>
        public uint Header_length { get; set; }
        /// <summary>
        /// 服务类型
        /// </summary>
        public byte TOS { get; set; }
        /// <summary>
        /// 数据包总长度
        /// </summary>
        public ushort Total_length { get; set; }
        /// <summary>
        /// id
        /// </summary>
        public ushort Id { get; set; }
        /// <summary>
        /// 片偏移
        /// </summary>
        public ushort Offset { get; set; }
        /// <summary>
        /// 生存周期
        /// </summary>
        public byte TTL { get; set; }
        /// <summary>
        /// 数据部分协议
        /// </summary>
        public string? Protocol { get; set; }
        /// <summary>
        /// 源地址
        /// </summary>
        public string? Src_addr { get; set; }
        /// <summary>
        /// 目的地址
        /// </summary>
        public string? Dst_addr { get; set; }
        /// <summary>
        /// 数据载荷
        /// </summary>
        public byte[]? Payload { get; set; }
    }
}

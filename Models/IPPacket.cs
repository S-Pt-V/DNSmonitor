namespace DNSmonitor.Models
{
    /// <summary>
    /// IP数据包
    /// </summary>
    public class IPPacket
    {
        /// <summary>
        /// IP协议版本号
        /// </summary>
        public uint Version { get; set; }
        /// <summary>
        /// 数据包头部长度
        /// </summary>
        public uint Headerlength { get; set; }
        /// <summary>
        /// 服务类型
        /// </summary>
        public byte Tos { get; set; }
        /// <summary>
        /// 数据包总长度，头部长度加数据部分长度
        /// </summary>
        public ushort Totallength { get; set; }
        /// <summary>
        /// id
        /// </summary>
        public ushort Identification { get; set; }
        /// <summary>
        /// 片偏移
        /// </summary>
        public ushort Offset { get; set; }
        /// <summary>
        /// 存活周期
        /// </summary>
        public byte Ttl { get; set; }
        /// <summary>
        /// 数据部分协议
        /// </summary>
        public string? Protocol { get; set; }
        /// <summary>
        /// 校验和
        /// </summary>
        public ushort? Checksum { get; set; }
        /// <summary>
        /// 源地址
        /// </summary>
        public string? Src_addr { get; set; }
        /// <summary>
        /// 目的地址
        /// </summary>
        public string? Dst_addr { get; set; }
        /// <summary>
        /// 数据部分缓存
        /// </summary>
        public byte[]? Data { get; set; }
    }

    /// <summary>
    /// UDP数据报
    /// </summary>
    public class UDPdatagram
    {
        /// <summary>
        /// 源端口
        /// </summary>
        public ushort srcport { get; set; }
        /// <summary>
        /// 目的端口
        /// </summary>
        public ushort dstport { get; set; }
        /// <summary>
        /// 总长度
        /// </summary>
        public ushort length { get; set; }
        /// <summary>
        /// 校验和
        /// </summary>
        public ushort checksum { get; set; }
        /// <summary>
        /// 数据部分
        /// </summary>
        public byte[] datagram { get; set; }
    }
}

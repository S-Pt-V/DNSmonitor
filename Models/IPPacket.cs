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
        public uint version { get; set; }
        /// <summary>
        /// 数据包头部长度
        /// </summary>
        public uint headerlength { get; set; }
        /// <summary>
        /// 服务类型
        /// </summary>
        public byte tos { get; set; }
        /// <summary>
        /// 数据包总长度，头部长度加数据部分长度
        /// </summary>
        public ushort totallength { get; set; }
        /// <summary>
        /// id
        /// </summary>
        public ushort identification { get; set; }
        /// <summary>
        /// 片偏移
        /// </summary>
        public ushort offset { get; set; }
        /// <summary>
        /// 存活周期
        /// </summary>
        public byte ttl { get; set; }
        /// <summary>
        /// 数据部分协议
        /// </summary>
        public string protocol { get; set; }
        /// <summary>
        /// 校验和
        /// </summary>
        public ushort checksum { get; set; }
        /// <summary>
        /// 源地址
        /// </summary>
        public string src_addr { get; set; }
        /// <summary>
        /// 目的地址
        /// </summary>
        public string dst_addr { get; set; }
        /// <summary>
        /// 数据部分缓存
        /// </summary>
        public byte[] data { get; set; }
    }
}

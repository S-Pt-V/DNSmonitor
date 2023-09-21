using System.Runtime.InteropServices;

namespace DNSmonitor
{
    /// <summary>
    /// 网络层的IP数据包解析后的数据格式对象
    /// </summary>
    public class IPPacket
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
        public string? Version { get; set; }
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
        public int Total_length { get; set; }
        /// <summary>
        /// id
        /// </summary>
        public string? Id { get; set; }
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
        /// 校验和
        /// </summary>
        public ushort Checksum { get; set; }
        /// <summary>
        /// 源地址
        /// </summary>
        public string? Src_addr { get; set; }
        /// <summary>
        /// 目的地址
        /// </summary>
        public string? Dst_addr { get; set; }
        /// <summary>
        /// 包头的选项
        /// </summary>
        public byte[]? Header_option { get; set; }
        /// <summary>
        /// 数据载荷
        /// </summary>
        public byte[]? Payload { get; set; }
    }

    /// <summary>
    /// 数据报头部定义
    /// </summary>
    public class Headers
    {
        /// <summary>
        /// IP协议头部
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IPHeader
        {
            /// <summary>
            /// 协议版本及首部长度。前4位为版本号，0100 IPv4，0110 IPv6。后4bit为首部长度，该值乘以4
            /// </summary>
            [FieldOffset(0)] public byte verlen;
            /// <summary>
            /// 服务类型
            /// </summary>
            [FieldOffset(1)] public byte tos;
            /// <summary>
            /// 总长度
            /// </summary>
            [FieldOffset(2)] public ushort total_length;
            /// <summary>
            /// ID
            /// </summary>
            [FieldOffset(4)] public ushort id;
            /// <summary>
            /// 分段偏移
            /// </summary>
            [FieldOffset(6)] public ushort offset;
            /// <summary>
            /// 生存周期
            /// </summary>
            [FieldOffset(8)] public byte ttl;
            /// <summary>
            /// 协议类型
            /// </summary>
            [FieldOffset(9)] public byte protocol;
            /// <summary>
            /// 校验和
            /// </summary>
            [FieldOffset(10)] public ushort checksum;
            /// <summary>
            /// 源地址
            /// </summary>
            [FieldOffset(12)] public uint srcaddr;
            /// <summary>
            /// 目的地址
            /// </summary>
            [FieldOffset(16)] public uint dstaddr;
        }
    }
}

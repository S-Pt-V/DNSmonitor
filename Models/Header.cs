using System.Runtime.InteropServices;

namespace DNSmonitor.Models
{
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
            /// 协议版本及首部长度。前4bit为版本号，0100 IPv4，0110 IPv6。后4bit为首部长度，该值乘以4
            /// </summary>
            [FieldOffset(0)] public byte ip_verlen;
            /// <summary>
            /// 服务类型
            /// </summary>
            [FieldOffset(1)] public byte ip_tos;
            /// <summary>
            /// 总长度
            /// </summary>
            [FieldOffset(2)] public ushort ip_totallength;
            /// <summary>
            /// ID
            /// </summary>
            [FieldOffset(4)] public ushort ip_id;
            /// <summary>
            /// 分段偏移
            /// </summary>
            [FieldOffset(6)] public ushort ip_offset;
            /// <summary>
            /// 生存周期
            /// </summary>
            [FieldOffset(8)] public byte ip_ttl;
            /// <summary>
            /// 协议类型
            /// </summary>
            [FieldOffset(9)] public byte ip_protocol;
            /// <summary>
            /// 校验和
            /// </summary>
            [FieldOffset(10)] public ushort ip_checksum;
            /// <summary>
            /// 源地址
            /// </summary>
            [FieldOffset(12)] public uint ip_srcaddr;
            /// <summary>
            /// 目的地址
            /// </summary>
            [FieldOffset(16)] public uint ip_dstaddr;
        }
    }
}

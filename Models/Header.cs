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

        /// <summary>
        /// TCP头部
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct TCP
        {
            /// <summary>
            /// 源端口
            /// </summary>
            [FieldOffset(0)] public ushort srcport;
            /// <summary>
            /// 目的端口
            /// </summary>
            [FieldOffset(2)] public ushort dstport;
            /// <summary>
            /// 32位序号
            /// </summary>
            [FieldOffset(4)] public int secquence;
            /// <summary>
            /// 32位确认号
            /// </summary>
            [FieldOffset(8)] public int ack;
            /// <summary>
            /// 前四位为头部长度，中间16位保留，后续依次为 URG，ACK，PSH，RST，SYN，FIN
            /// </summary>
            [FieldOffset(12)] public ushort len_bits;
            /// <summary>
            /// 窗口大小
            /// </summary>
            [FieldOffset(14)] public ushort windowsize;
            /// <summary>
            /// 校验和
            /// </summary>
            [FieldOffset(16)] public ushort checksum;
            /// <summary>
            /// 16位紧急指针
            /// </summary>
            [FieldOffset(18)] public ushort emergency_pointer;
        }

        /// <summary>
        /// UDP头部
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct UDP
        {
            /// <summary>
            /// 源端口号
            /// </summary>
            [FieldOffset(0)] public ushort srcport;
            /// <summary>
            /// 目的端口号
            /// </summary>
            [FieldOffset(2)] public ushort dstport;
            /// <summary>
            /// 长度，包含头部和数据部分
            /// </summary>
            [FieldOffset(4)] public ushort length;
            /// <summary>
            /// 校验和
            /// </summary>
            [FieldOffset(6)] public ushort checksum;
        }
    }
}

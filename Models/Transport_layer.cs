using System.Runtime.InteropServices;

namespace DNSmonitor
{
    /// <summary>
    /// UDP数据报
    /// </summary>
    public class Datagram
    {
        /// <summary>
        /// 源端口
        /// </summary>
        public ushort Src_port { get; set; }
        /// <summary>
        /// 目的端口
        /// </summary>
        public ushort Dst_port { get; set; }
        /// <summary>
        /// 总长度
        /// </summary>
        public ushort Length { get; set; }
        /// <summary>
        /// 校验和
        /// </summary>
        public ushort Checksum { get; set; }
        /// <summary>
        /// 数据部分
        /// </summary>
        public byte[]? Payload { get; set; }
    }

    /// <summary>
    /// UDP头部
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct UDPHeader
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

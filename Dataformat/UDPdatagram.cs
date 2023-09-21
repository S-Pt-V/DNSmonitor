using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;

namespace DNSmonitor.Dataformat.TransportLayer
{
    /// <summary>
    /// UDP 数据报定义
    /// </summary>
    public class UDPdatagram
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
        public byte[] Data { get; set; }
    }
}

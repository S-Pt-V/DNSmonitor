using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;

namespace DNSmonitor.Dataformat.NetworkLayer
{
    /// <summary>
    /// IP协议枚举
    /// </summary>
    public enum IPProtocol_Ver
    {
        /// <summary>
        /// IPv4版本号
        /// </summary>
        IPv4 = 4,
        /// <summary>
        /// IPv6版本号
        /// </summary>
        IPv6 = 6
    }

    /// <summary>
    /// 传输层协议版本号
    /// </summary>
    public enum IIIProtocol
    {
        /// <summary>
        /// ICMP
        /// </summary>
        ICMP = 1,
        /// <summary>
        /// IGMP
        /// </summary>
        IGMP = 2,
        /// <summary>
        /// TCP
        /// </summary>
        TCP = 6,
        /// <summary>
        /// UDP
        /// </summary>
        UDP = 17
    }

    /// <summary>
    /// IP数据包格式
    /// </summary>
    public class IPpacket
    {
        /// <summary>
        /// IP协议版本号
        /// </summary>
        public byte Version { get; set; }
        /// <summary>
        /// 协议头部长度
        /// </summary>
        public byte Header_length { get; set; }
        /// <summary>
        /// 服务类型
        /// </summary>
        public byte Tos { get; set; }
        /// <summary>
        /// 总长度
        /// </summary>
        public ushort Total_length { get; set; }
        /// <summary>
        /// 标识
        /// </summary>
        public ushort Id { get; set; }
        /// <summary>
        /// 标志位
        /// </summary>
        public byte Flags { get; set; }
        /// <summary>
        /// 偏移
        /// </summary>
        public ushort Offset { get; set; }
        /// <summary>
        /// 生存时间
        /// </summary>
        public ushort TTL { get; set; }
        /// <summary>
        /// 上层协议类型
        /// </summary>
        public ushort Protocol { get; set; }
        /// <summary>
        /// 校验和
        /// </summary>
        public ushort Checksum { get; set; }
        /// <summary>
        /// 源地址
        /// </summary>
        public string Src_addr { get; set; }
        /// <summary>
        /// 目的地址
        /// </summary>
        public string Dst_addr { get; set; }
        /// <summary>
        /// 选项部分
        /// </summary>
        public byte[] Options { get; set; }
        /// <summary>
        /// 数据部分
        /// </summary>
        public byte[] Data { get; set; }
    }

    /// <summary>
    /// 标志位
    /// </summary>
    public struct FLAGS
    {
        /// <summary>
        /// 值，方便判断分片情况
        /// </summary>
        public byte value { get; set; }
        /// <summary>
        /// 恒为0
        /// </summary>
        public bool Zero { get; set; }
        /// <summary>
        /// 0 需要分片，1 不需要分片
        /// </summary>
        public bool Segment { get; set; }
        /// <summary>
        /// 0 最后一个分片，1 后续有分片
        /// </summary>
        public bool LastSeg { get; set; }
    }

    /// <summary>
    /// 分片FLAGS枚举类型
    /// </summary>
    public enum Seg
    {
        /// <summary>
        /// 不需要分片
        /// </summary>
        NoSeg = 0b010,
        /// <summary>
        /// 需要分片且有后续分片
        /// </summary>
        Seg = 0b001,
        /// <summary>
        /// 需要分片且目前是最后一个分片
        /// </summary>
        LastSeg = 0b000
    }

    /// <summary>
    /// 服务类型
    /// </summary>
    public struct TOS
    {
        /// <summary>
        /// PPP 包优先级
        /// </summary>
        public byte PPP { get; set; }
        /// <summary>
        /// D 时延, 0 普通, 1 尽量小
        /// </summary>
        public bool D { get; set; }
        /// <summary>
        /// T 吞吐量, 0 普通, 1 尽量大
        /// </summary>
        public bool T { get; set; }
        /// <summary>
        /// R 可靠性, 0 普通, 1 尽量大
        /// </summary>
        public bool R { get; set; }
        /// <summary>
        /// M 传输成本, 0 普通, 1 尽量小
        /// </summary>
        public bool M { get; set; }
        /// <summary>
        /// 0 保留，恒为0
        /// </summary>
        public bool Zero { get; set; }
    }

    /// <summary>
    /// 优先级 枚举类型
    /// </summary>
    public enum PPP
    {
        /// <summary>
        /// 普通
        /// </summary>
        Routine = 0b000,
        /// <summary>
        /// 优先
        /// </summary>
        Priority = 0b001,
        /// <summary>
        /// 立即发送
        /// </summary>
        Immediate = 0b010,
        /// <summary>
        /// 闪电式
        /// </summary>
        Flash = 0b011,
        /// <summary>
        /// 比闪电还闪电式
        /// </summary>
        Flash_Override = 0b100,
        /// <summary>
        /// CRI/TIC/ECP暂无翻译
        /// </summary>
        CRI_TIC_ECP = 0b101,
        /// <summary>
        /// 网间控制
        /// </summary>
        Internetwork_control = 0b110,
        /// <summary>
        /// 网络控制
        /// </summary>
        Network_control = 0b111,
    }


}

using System.Net;

namespace DNSmonitor.Services
{
    /// <summary>
    /// 数据包解析
    /// </summary>
    public class ResolveService
    {
        // 临时字节数组
        private static byte[]? temp;

        /// <summary>
        /// IP数据包解析
        /// </summary>
        /// <param name="buffer">由rawSocket直接抓取到的包含IP头部的原始数据包</param>
        /// <param name="count">字节数组长度</param>
        public static IPPacket PacketResolve(byte[] buffer, int count)
        {
            try
            {
                // Console.WriteLine("Received {0} bytes", count);
                // 开始解析IP数据包
                IPPacket packet = new IPPacket();
                // 版本号
                packet.Version = IPPacket.Version_dict[((buffer[0] & 0b11110000) >> 4)];
                // 头部长度
                packet.Header_length = (uint)((buffer[0] & 0b00001111) << 2);
                // 服务类型
                packet.TOS = buffer[1];
                // 数据包总长度
                packet.Total_length = (ushort)(buffer[2] * 256 + buffer[3]);
                // ID
                temp = new byte[4];
                Array.Copy(buffer, 4, temp, 0, 2);
                packet.Id = BitConverter.ToString(temp);
                // 偏移
                packet.Offset = (ushort)(buffer[6] * 256 + buffer[7]);
                // 生存周期
                packet.TTL = buffer[8];
                // 协议类型
                packet.Protocol = IPPacket.Protocol_dict[buffer[9]];
                // 校验和
                packet.Checksum = (ushort)(buffer[10] * 256 + buffer[11]);
                // 源地址
                temp = new byte[4];
                Array.Copy(buffer, 12, temp, 0, 4);
                packet.Src_addr = new IPAddress(temp).ToString();
                // 目的地址
                Array.Copy(buffer, 16, temp, 0, 4);
                packet.Dst_addr = new IPAddress(temp).ToString();
                // 报头的选项部分
                if (packet.Header_length > 20)
                {
                    uint optionlength = packet.Header_length - 20;
                    packet.Header_option = new byte[optionlength];
                    Array.Copy(buffer, 20, packet.Header_option, 0, optionlength);
                }
                // 数据部分
                long payloadlength = count - packet.Header_length;
                packet.Payload = new byte[payloadlength];
                Array.Copy(buffer, packet.Header_length, packet.Payload, 0, payloadlength);
                return packet;
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }

    }
}

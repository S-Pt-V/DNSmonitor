namespace DNSmonitor.Services
{
    /// <summary>
    /// 数据包解析
    /// </summary>
    public class ResolveService
    {
        /// <summary>
        /// IP数据包解析
        /// </summary>
        /// <param name="buffer">由rawSocket直接抓取到的包含IP头部的原始数据包</param>
        /// <param name="count">字节数组长度</param>
        public static void PacketResolve(byte[] buffer, int count)
        {
            Console.WriteLine("Received {0} bytes", count);
        }
    }
}

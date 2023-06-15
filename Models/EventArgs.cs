namespace DNSmonitor.Models
{
    /// <summary>
    /// 数据包到达事件
    /// </summary>
    public class PacketArrivedEventArgs : EventArgs
    {
        /// <summary>
        /// 
        /// </summary>
        public PacketArrivedEventArgs(int len_receive_buf)
        {
            this.protocol = "";
            this.destination_port = "";
            this.origination_port = "";
            this.destination_address = "";
            this.origination_address = "";
            this.ip_version = "";

            this.total_packetlength = 0;
            this.message_length = 0;
            this.header_length = 0;

            this.receive_buf_bytes = new byte[len_receive_buf];
            this.ip_header_bytes = new byte[len_receive_buf];
            this.message_bytes = new byte[len_receive_buf];
        }

        private string protocol;
        /// <summary>
        /// 协议
        /// </summary>
        public string Protocol
        {
            get { return protocol; }
            set { protocol = value; }
        }

        private string destination_port;
        /// <summary>
        /// 目的端口
        /// </summary>
        public string DestinationPort
        {
            get { return destination_port; }
            set { destination_port = value; }
        }

        private string origination_port;
        /// <summary>
        /// 源端口
        /// </summary>
        public string OriginationPort
        {
            get { return origination_port; }
            set { origination_port = value; }
        }

        private string destination_address;
        /// <summary>
        /// 目的地址
        /// </summary>
        public string DestinationAddress
        {
            get { return destination_address; }
            set { destination_address = value; }
        }

        private string origination_address;
        /// <summary>
        /// 源地址
        /// </summary>
        public string OriginationAddress
        {
            get { return origination_address; }
            set { origination_address = value; }
        }

        private string ip_version;
        /// <summary>
        /// IP协议版本
        /// </summary>
        public string IpVersion
        {
            get { return ip_version; }
            set { ip_version = value; }
        }

        private uint total_packetlength;
        /// <summary>
        /// 数据包总长度
        /// </summary>
        public uint TotalPacketlength
        {
            get { return total_packetlength; }
            set { total_packetlength = value; }
        }

        private uint message_length = 0;
        /// <summary>
        /// 消息长度
        /// </summary>
        public uint MessageLength
        {
            get { return message_length; }
            set { message_length = value; }
        }

        private uint header_length = 0;
        /// <summary>
        /// 头部长度
        /// </summary>
        public uint HeaderLength
        {
            get { return header_length; }
            set { header_length = value; }
        }

        private byte[] receive_buf_bytes;
        /// <summary>
        /// 接收缓冲区字节数组
        /// </summary>
        public byte[] ReceiveBuffer
        {
            get { return receive_buf_bytes; }
            set { receive_buf_bytes = value; }
        }

        private byte[] ip_header_bytes;
        /// <summary>
        /// IP头部数据缓冲区
        /// </summary>
        public byte[] HeaderBuffer
        {
            get { return ip_header_bytes; }
            set { ip_header_bytes = value; }
        }

        private byte[] message_bytes;
        /// <summary>
        /// 消息缓冲区
        /// </summary>
        public byte[] MessageBuffer
        {
            get { return message_bytes; }
            set { message_bytes = value; }
        }
    }
}

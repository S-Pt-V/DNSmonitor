namespace DNSmonitor.Models
{
    /// <summary>
    /// DNS数据包结构
    /// </summary>
    public class DNSdatagram
    {
        public enum Type
        {
            /// <summary>
            /// A记录，由域名获得IPV4地址
            /// </summary>
            A = 1,
            /// <summary>
            /// 查询域名服务器
            /// </summary>
            NS = 2,
            /// <summary>
            /// 查询规范名称
            /// </summary>
            CNAME = 5,
            /// <summary>
            /// 开始授权
            /// </summary>
            SOA = 6,
            /// <summary>
            /// 熟知服务
            /// </summary>
            WKS = 11,
            /// <summary>
            /// IP地址转换为域名
            /// </summary>
            PTR = 12,
            /// <summary>
            /// 主机信息
            /// </summary>
            HINFO = 13,
            /// <summary>
            /// 邮件交换
            /// </summary>
            MX = 15,
            /// <summary>
            /// 由域名获得IPv6地址
            /// </summary>
            AAAA = 28,
            /// <summary>
            /// 传送整个区的请求
            /// </summary>
            AXFR = 252,
            /// <summary>
            /// 对所有记录的请求
            /// </summary>
            ANY = 255
        }
        /// <summary>
        /// DNS请求和响应类型
        /// </summary>
        public Dictionary<ushort, string> Dns_Type = new()
        {
            { 1, "A" },
            { 2, "NS" },
            { 5, "CNAME" },
            { 6, "SOA" },
            { 11, "WKS" },
            { 12, "PTR" },
            { 13, "HINFO" },
            { 15, "MX" },
            { 28, "AAAA" },
            { 252, "AXFR" },
            { 255, "ANY" }
        };

        /// <summary>
        /// 事务id 两字节长度
        /// </summary>
        public ushort Transaction_id { get; set; }
        /// <summary>
        /// 0b1xxxxxxx xxxxxxxx 第一位为0:query或者1:response
        /// </summary>
        public int QR { get; set; }
        /// <summary>
        /// 0bx1111xxx xxxxxxxx 操作码，0:标准查询，1:反向查询，2:服务器状态请求
        /// </summary>
        public int Opcode { get; set; }
        /// <summary>
        /// 0bxxxxx1xx xxxxxxxx AA表示授权回答，默认为0
        /// </summary>
        public int AA { get; set; }
        /// <summary>
        /// 0bxxxxxx1x xxxxxxxx TC是否可截断，使用UDP时表示应答长度超过512字节只返回前512字节
        /// </summary>
        public int TC { get; set; }
        /// <summary>
        /// 0bxxxxxxx1 xxxxxxxx RD 期望递归请求。一般由请求端发送。若为1，服务器必须处理该请求。若为0，且请求的DNS没有一个授权回答，就返回一个能够解答这种查询的其他DNS列表，称为迭代查询
        /// </summary>
        public int RD { get; set; }
        /// <summary>
        /// 0bxxxxxxxx 1xxxxxxx RA 表示可用递归。是RD的响应。大部分DNS都可以响应RD，除了少部分根服务器。
        /// </summary>
        public int RA { get; set; }
        /// <summary>
        /// 0bxxxxxxxx x111xxxx zeros 这三位必须为0
        /// </summary>
        public int Zeros { get; set; }
        /// <summary>
        /// 0bxxxxxxxx xxxx1111 rcode 0:没有差错，3：名字有错，表示查询中指定的域名不存在
        /// </summary>
        public int Rcode { get; set; }
        /// <summary>
        /// 两字节问题数
        /// </summary>
        public int Questions { get; set; }
        /// <summary>
        /// 两字节资源记录数
        /// </summary>
        public int Answer_RRs { get; set; }
        /// <summary>
        /// 两字节授权资源记录数
        /// </summary>
        public int Authority_RRs { get; set; }
        /// <summary>
        /// 两字节额外资源记录数
        /// </summary>
        public int Additional_RRs { get;set; }
        /// <summary>
        /// 查询问题
        /// </summary>
        //public List<List<byte[]>>? queries { get; set; }
        public List<Dns_query>? Queries { get; set; }
        /// <summary>
        /// 资源记录
        /// </summary>
        public List<Dns_answer>? AnswerRRs { get; set; }
        /// <summary>
        /// 权威应答列表
        /// </summary>
        public List<Dns_authorityRR>? AuthorityRRs { get; set; }
    }

    /// <summary>
    /// 查询问题
    /// </summary>
    public struct Dns_query
    {
        /// <summary>
        /// 域名
        /// </summary>
        public string Query_name { get; set; }
        /// <summary>
        /// 查询类型
        /// </summary>
        public int Query_type { get; set; }
        /// <summary>
        /// 查询类
        /// </summary>
        public int Query_class { get; set; }
    }

    /// <summary>
    /// DNS响应的资源记录
    /// </summary>
    public struct Dns_answer
    {
        /// <summary>
        /// 名称
        /// </summary>
        public string Answer_name { get; set; }
        /// <summary>
        /// 响应类型
        /// </summary>
        public ushort Answer_type { get; set; }
        /// <summary>
        /// 响应类
        /// </summary>
        public ushort Answer_class { get; set; }
        /// <summary>
        /// 生存周期
        /// </summary>
        public int Answer_ttl { get; set; }
        /// <summary>
        /// 数据长度
        /// </summary>
        public ushort Answer_datalength { get; set; }
        /// <summary>
        /// 数据
        /// </summary>
        public string Answer_data { get; set; }
    }

    /// <summary>
    /// 权威应答
    /// </summary>
    public struct Dns_authorityRR
    {
        /// <summary>
        /// 名称
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// 响应类型
        /// </summary>
        public ushort Type { get; set; }
        /// <summary>
        /// 响应类
        /// </summary>
        public ushort Class { get; set; }
        /// <summary>
        /// 生存周期
        /// </summary>
        public int TTL { get; set; }
        /// <summary>
        /// 数据长度
        /// </summary>
        public ushort Datalength { get; set; }
        /// <summary>
        /// 域名服务器
        /// </summary>
        public string Primary_Name_Server { get; set; }
        /// <summary>
        /// 域名服务器邮箱
        /// </summary>
        public string Responsible_Authority_Mailbox { get; set; }
        /// <summary>
        /// 序列号
        /// </summary>
        public string Serial_Number { get; set; }
        /// <summary>
        /// 刷新周期
        /// </summary>
        public int Refresh_Interval { get; set; }
        /// <summary>
        /// 重试周期
        /// </summary>
        public int Retry_Interval { get; set; }
        /// <summary>
        /// 报废周期
        /// </summary>
        public int Expire_Interval { get; set; }
        /// <summary>
        /// 最小周期
        /// </summary>
        public int Minimum_Interval { get; set; }
    }
}

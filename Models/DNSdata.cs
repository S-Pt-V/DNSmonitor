namespace DNSmonitor
{
    /// <summary>
    /// DNS数据报内容
    /// </summary>
    public class DNSdata
    {
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
        public int Additional_RRs { get; set; }
        /// <summary>
        /// 查询问题
        /// </summary>
        //public List<List<byte[]>>? queries { get; set; }
        public List<DNS_query>? Queries { get; set; }
        /// <summary>
        /// 资源记录
        /// </summary>
        public List<DNS_answerRR>? AnswerRRs { get; set; }
        /// <summary>
        /// 权威应答列表
        /// </summary>
        // public List<Dns_authorityRR>? AuthorityRRs { get; set; }
    }

    /// <summary>
    /// DNS请求的结构
    /// </summary>
    public class DNS_query
    {
        /// <summary>
        /// 请求类型
        /// </summary>
        public static Dictionary<int, string> Type_dict = new Dictionary<int, string>()
        {
            {1, "A"},           // A记录，主机地址
            {2, "NS"},          // Name Server记录
            {3, "MD" },         // a mail destination (Obsolete - use MX)
            {5, "CNAME"},       // CNAME 记录
            {6, "SOA" },        // 起始授权
            {7, "MB" },         // a mailbox domain name (EXPERIMENTAL)
            {8, "MG" },         // a mail group member (EXPERIMENTAL)
            {9, "MR" },         // a mail rename domain name
            {10, "NULL" },      // a NULL RR (EXPERIMENTAL)
            {11, "WKS" },       // a well known service description      
            {12, "PTR"},        // 指针
            {13, "HINFO"},      // 主机信息
            {15, "MX"},         // 邮件交换
            {16, "TXT" },       // text strings
            {28, "AAAA"},       // AAAA记录
            {252, "AXFR"},      // A request for a transfer of an entire zone
            {253, "MAILB" },    // A request for mailbox-related records (MB, MG or MR)
            {254, "MAILA" },    // A request for mail agent RRs (Obsolete - see MX)
            {255, "ANY" }       // A request for all records
        };

        /// <summary>
        /// 请求类别
        /// </summary>
        public static Dictionary<int, string> Class_dict = new Dictionary<int, string>()
        {
            {1, "IN" },         // the Internet
            {2, "CS" },         // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
            {3, "CH" },         // the CHAOS class
            {4, "HS" }          // Hesiod [Dyer 87]
        };

        /// <summary>
        /// 请求域名
        /// </summary>
        public string? Name { get; set; }
        /// <summary>
        /// 请求类型
        /// </summary>
        public string? Type { get; set; }
        /// <summary>
        /// 请求类别
        /// </summary>
        public string? Class { get; set; }
    }

    /// <summary>
    /// DNS资源记录结构
    /// </summary>
    public class DNS_answerRR
    {
        /// <summary>
        /// 请求类型
        /// </summary>
        public static Dictionary<int, string> Type_dict = new Dictionary<int, string>()
        {
            {1, "A"},           // A记录
            {2, "NS"},          // Name Server记录
            {3, "MD" },         // a mail destination (Obsolete - use MX)
            {5, "CNAME"},       // CNAME 记录
            {6, "SOA" },        // 起始授权
            {7, "MB" },         // a mailbox domain name (EXPERIMENTAL)
            {8, "MG" },         // a mail group member (EXPERIMENTAL)
            {9, "MR" },         // a mail rename domain name
            {10, "NULL" },      // a NULL RR (EXPERIMENTAL)
            {11, "WKS" },       // a well known service description      
            {12, "PTR"},        // 指针
            {13, "HINFO"},      // 主机信息
            {15, "MX"},         // 邮件交换
            {16, "TXT" },       // text strings
            {28, "AAAA"},       // AAAA记录
            {252, "AXFR"},      // A request for a transfer of an entire zone
            {253, "MAILB" },    // A request for mailbox-related records (MB, MG or MR)
            {254, "MAILA" },    // A request for mail agent RRs (Obsolete - see MX)
            {255, "ANY" }       // A request for all records
        };

        /// <summary>
        /// 请求类别
        /// </summary>
        public static Dictionary<int, string> Class_dict = new Dictionary<int, string>()
        {
            {1, "IN" },         // the Internet
            {2, "CS" },         // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
            {3, "CH" },         // the CHAOS class
            {4, "HS" }          // Hesiod [Dyer 87]
        };

        /// <summary>
        /// 域名
        /// </summary>
        public string? Name { get; set; }
        /// <summary>
        /// 类型
        /// </summary>
        public string? Type { get; set; }
        /// <summary>
        /// 类别
        /// </summary>
        public string? Class { get; set; }
        /// <summary>
        /// 生存周期
        /// </summary>
        public int TTL { get; set; }
        /// <summary>
        /// 数据长度
        /// </summary>
        public ushort Data_length { get; set; }
        /// <summary>
        /// 数据
        /// </summary>
        public string? Data { get; set; } 
    }
}

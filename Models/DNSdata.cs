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
        public List<DNS_AnswerRR>? AnswerRRs { get; set; }
        /// <summary>
        /// 权威应答列表
        /// </summary>
        public List<DNS_AuthorityRR>? AuthorityRRs { get; set; }
        /// <summary>
        /// 额外记录
        /// </summary>
        public List<DNS_AdditionalRR>? AdditionalRRs { get; set; }
    }

    /// <summary>
    /// DNS请求的结构
    /// </summary>
    public class DNS_query
    {
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
    /// DNS资源记录类型
    /// </summary>
    public class DNS_RR
    {
        /// <summary>
        /// 域名
        /// </summary>
        public string? Name { get; set; }
        /// <summary>
        /// 记录类型
        /// </summary>
        public string? Type { get; set; }
        /// <summary>
        /// 数据类型
        /// </summary>
        public string? Class { get; set; }
        /// <summary>
        /// 生存周期
        /// </summary>
        public uint TTL { get; set; }
        /// <summary>
        /// 数据长度
        /// </summary>
        public ushort Rdata_length { get; set; }
        /// <summary>
        /// 数据的字节数据
        /// </summary>
        public byte[]? Rdata { get; set; }
    }

    /// <summary>
    /// 回答资源记录
    /// </summary>
    public class DNS_AnswerRR : DNS_RR
    {
        /// <summary>
        /// 指向下一部分的开头
        /// </summary>
        public int Next { get; set; }
    }

    /// <summary>
    /// 权威应答资源记录
    /// </summary>
    public class DNS_AuthorityRR : DNS_RR
    {
        /// <summary>
        /// 指向下一部分的开头
        /// </summary>
        public int Next { get; set; }
    }

    /// <summary>
    /// 附加记录
    /// </summary>
    public class DNS_AdditionalRR : DNS_RR
    {
        /// <summary>
        /// 指向下一部分的开头
        /// </summary>
        public int Next { get; set; }
        /// <summary>
        /// UDP payload size
        /// </summary>
        public ushort UDP_ps { get; set; }
        /// <summary>
        /// Higher bits in extedned RCODE
        /// </summary>
        public byte Higher_bits_in_rcode { get; set; }
        /// <summary>
        /// EDNS0 version
        /// </summary>
        public byte EDNS0_version { get; set; }
        /// <summary>
        /// Z
        /// </summary>
        public ushort Z { get; set; }
        /// <summary>
        /// Data length
        /// </summary>
        public ushort Data_length { get; set; }
    }

    /// <summary>
    /// dns请求类型和类别
    /// </summary>
    public class Q_tpye_class
    {
        /// <summary>
        /// 请求类型
        /// </summary>
        public static Dictionary<int, string> Type_dict = new Dictionary<int, string>()
        {
            {1, "A"},
            {2, "NS" },
            {3, "MD" },
            {4, "MF" },
            {5, "CNAME" },
            {6, "SOA" },
            {7, "MB" },
            {8, "MG" },
            {9, "MR" },
            {10, "NULL" },

            {11, "WKS" },
            {12, "PTR"},
            {13, "HINFO" },
            {14, "MINFO" },
            {15, "MX" },
            {16, "TXT" },
            {17, "RP" },
            {18, "AFSDB" },
            {19, "X25" },

            {20, "ISDN" },
            {21, "RT" },
            {22, "NSAP" },
            {23, "NSAP-PTR" },
            {24, "SIG" },
            {25, "KEY" },
            {26, "PX" },
            {27, "GPOS" },
            {28, "AAAA" },
            {29, "LOC" },

            {30, "NXT" },
            {31, "EID" },
            {32, "NIMLOC/NB" },
            {33, "SRV/NBSTAT" },
            {34, "ATMA" },
            {35, "NAPTR" },
            {36, "KX" },
            {37, "CERT" },
            {38, "A6" },
            {39, "DNAME" },

            {40, "SINK" },
            {41, "OPT" },
            {42, "APL" },
            {43, "DS" },
            {44, "SSHFP" },
            {45, "IPSECKEY" },
            {46, "PRSIG" },
            {47, "NSEC" },
            {48, "DNSKEY" },
            {49, "DHCID" },

            {50, "NSEC3" },
            {51, "NSEC3PARAM" },
            {52, "TLSA" },
            {53, "SMIMEA" },
            {55, "HIP" },
            {56, "NINFO" },
            {57, "PKEY" },
            {58, "TALINK" },
            {59, "CDS" },

            {60, "CDNSKEY" },
            {61, "OPENPGPKEY" },
            {62, "CSYNC" },
            {63, "ZONEMD" },
            {64, "SVCB" },
            {65, "HTTPS" },

            {99, "SPF"},
            {100, "UINFO" },
            {101, "UID" },
            {102, "GID" },
            {103, "UNSPEC" },
            {104, "NID" },
            {105, "L32" },
            {106, "L64" },
            {107, "LP" },
            {108, "EUI48" },
            {109, "EUI64" },

            {249, "TKEY" },
            {250, "TSIG" },
            {251, "IXFR" },
            {252, "AXFR" },
            {253, "MAILB" },
            {254, "MAILA" },
            {255, "ANY" },
            {256, "URI" },
            {257, "CAA" },
            {259, "DOA" },

            {32768, "TA" },
            {32769, "DLV" },
        };

        /// <summary>
        /// 请求类别
        /// </summary>
        public static Dictionary<int, string> Class_dict = new Dictionary<int, string>()
        {
            {0, "Reserved" },
            {1, "Internet" },
            {2, "Unassigned" },
            {3, "Chaos" },
            {4, "Hesiod" },
            {254, "QCLASS NONE" },
            {255, "QCLASS * (ANY)" },
        };
    }
}

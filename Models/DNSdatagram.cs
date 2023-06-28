namespace DNSmonitor.Models
{
    /// <summary>
    /// DNS数据包结构
    /// </summary>
    public class DNSdatagram
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
        public int Additional_RRs { get;set; }
        /// <summary>
        /// 查询问题
        /// </summary>
        //public List<List<byte[]>>? queries { get; set; }
        public List<dns_query>? Queries { get; set; }
    }

    /// <summary>
    /// 查询问题
    /// </summary>
    public struct dns_query
    {
        /// <summary>
        /// 域名
        /// </summary>
        public string query_name { get; set; }
        /// <summary>
        /// 查询类型
        /// </summary>
        public int query_type { get; set; }
        /// <summary>
        /// 查询类
        /// </summary>
        public int query_class { get; set; }
    }
}

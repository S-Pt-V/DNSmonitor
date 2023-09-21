using ARSoft.Tools.Net.Dns;

namespace DNSmonitor.Services
{
    /// <summary>
    /// DNS解析
    /// </summary>
    public class DNSAnalyze
    {
        /// <summary>
        /// 从字节数组中解析DNS数据
        /// </summary>
        /// <param name="buffer"></param>
        public static DnsMessage BytesToDNSMsg(byte[] buffer)
        {
            DnsMessage message = DnsMessage.Parse(buffer);

            /*
            // 输出 DnsMessage 对象的属性和方法
            Console.WriteLine("Transaction ID: {0}", message.TransactionID);
            Console.WriteLine("Is Query: {0}", message.IsQuery);
            Console.WriteLine("Operation Code: {0}", message.OperationCode);
            Console.WriteLine("Is Authoritive Answer: {0}", message.IsAuthoritiveAnswer);
            Console.WriteLine("Is Truncated: {0}", message.IsTruncated);
            Console.WriteLine("Is Recursion Desired: {0}", message.IsRecursionDesired);
            Console.WriteLine("Is Recursion Allowed: {0}", message.IsRecursionAllowed);
            //Console.WriteLine("Response Code: {0}", message.ResponseCode);
            //Console.WriteLine("Response Code: {0}", message.ResponseCode);
            Console.WriteLine("Questions: {0}", message.Questions.Count);
            Console.WriteLine("Answers: {0}", message.AnswerRecords.Count);
            Console.WriteLine("Authorities: {0}", message.AuthorityRecords.Count);
            Console.WriteLine("Additionals: {0}", message.AdditionalRecords.Count);

            // 遍历 Questions 集合，输出每个问题的属性
            foreach (DnsQuestion question in message.Questions)
            {
                Console.WriteLine("Question Name: {0}", question.Name);
                Console.WriteLine("Question Type: {0}", question.RecordType);
                Console.WriteLine("Question Class: {0}", question.RecordClass);
            }
            */

            return message;
        }
    }
}

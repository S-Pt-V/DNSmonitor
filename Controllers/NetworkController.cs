using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace DNSmonitor.Controllers
{
    /// <summary>
    /// 网络行为控制器
    /// </summary>
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class NetworkController : ControllerBase
    {

        struct Address {
            public string Addr { get; set; }
            public string Addrfamily { get; set; }
        }
        /// <summary>
        /// 获取所有网卡地址
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult GetAllAddress()
        {
            List<Address> addrlist = new();
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            foreach(IPAddress entry in host.AddressList)
            {
                Console.WriteLine("{0}\t{1}", entry.AddressFamily.ToString(), entry.ToString());
                Address addr = new()
                {
                    Addr = entry.ToString(),
                    Addrfamily = entry.AddressFamily.ToString()
                };
                addrlist.Add(addr);
            }
            return Ok(addrlist);
        }
    }
}

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
        /// <summary>
        /// 获取所有网卡地址
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult GetAllAddress()
        {
            List<string> addrlist = new();
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            foreach(IPAddress entry in host.AddressList)
            {
                Console.WriteLine("{0}\t{1}", entry.AddressFamily.ToString(), entry.ToString());
                if (entry.AddressFamily.ToString() == "InterNetwork")
                {
                    Console.WriteLine("Add {0}", entry.ToString());
                    addrlist.Add(entry.ToString());
                }
            }
            return Ok(addrlist);
        }

        /// <summary>
        /// 获取当前配置
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult GetCurrentConf()
        {
            return Ok();
        }
    }
}

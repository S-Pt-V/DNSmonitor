using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using DNSmonitor.Models;
using System.Net;

namespace DNSmonitor.Controllers
{
    /// <summary>
    /// API控制器
    /// </summary>
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class MonitorController : ControllerBase
    {
        // 日志记录组件
        // private readonly ILogger<MonitorController> _logger;

        private Models.Monitor monitor;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="logger"></param>
        //public MonitorController(ILogger<MonitorController> logger)
        public MonitorController()
        {
            // _logger = logger;
            // monitor = new Models.Monitor(_logger);
            monitor = new Models.Monitor();
        }

        /// <summary>
        /// 获取本机所有网卡地址
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult GetAllAddr()
        {
            List<string> iplist = new List<string>();
            // 获取本机所有IP地址
            IPHostEntry ipEntry = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in ipEntry.AddressList)
            {
                Console.WriteLine(ip.AddressFamily.ToString() + ": " + ip.ToString());
                iplist.Add(ip.ToString());
            }
            return Ok(iplist);
        }

        /// <summary>
        /// 启动
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Start()
        {
            // _logger.LogInformation("Start");
            Console.WriteLine("Start");
            monitor.Run();
            return Ok();
        }

        /// <summary>
        /// 停止监听
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Stop()
        {
            // _logger.LogInformation("Stop");
            Console.WriteLine("Stop");
            monitor.Stop();
            return Ok();
        }

        /// <summary>
        /// 获取状态
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult State()
        {
            return Ok();
        }


        [HttpGet]
        public ActionResult DNSTypeTset(ushort i)
        {
            return Ok(new DNSdatagram().Dns_Type[i]);
        }
    }
}

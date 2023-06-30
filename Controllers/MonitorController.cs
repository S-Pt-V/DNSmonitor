using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using DNSmonitor.Models;
using System.Net;
using System.Text;

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

        [HttpGet]
        public ActionResult Falsepacket()
        {
            byte[] falsepacket = new byte[]
            {
                0xDF, 0xB3, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x67, 0x07, 0x63, 0x73, 0x64, 0x6E, 0x69,
                0x6D, 0x67, 0x02, 0x63, 0x6E, 0x00, 0x00, 0x01, 0x00, 0x01,
                0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7E,
                0x00, 0x27, 0x01, 0x67, 0x07, 0x63, 0x73, 0x64, 0x6E, 0x69,
                0x6D, 0x67, 0x02, 0x63, 0x6E, 0x08, 0x38, 0x39, 0x66, 0x65,
                0x61, 0x30, 0x64, 0x36, 0x0B, 0x63, 0x64, 0x6E, 0x68, 0x77,
                0x63, 0x76, 0x69, 0x78, 0x31, 0x36, 0x03, 0x63, 0x6F, 0x6D,
                0x00, 0xC0, 0x2A, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x7E, 0x00, 0x1C, 0x08, 0x68, 0x63, 0x64, 0x6E, 0x77, 0x31,
                0x32, 0x30, 0x06, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x01,
                0x63, 0x07, 0x63, 0x64, 0x6E, 0x68, 0x77, 0x63, 0x36, 0xC0,
                0x4C, 0xC0, 0x5D, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x7E, 0x00, 0x04, 0x6E, 0xA7, 0xA3, 0x31, 0xC0, 0x5D, 0x00,
                0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x04, 0x6E,
                0xA7, 0xA3, 0x33
            };

            Console.WriteLine(Encoding.ASCII.GetString(falsepacket));

            return Ok();
        }
    }
}

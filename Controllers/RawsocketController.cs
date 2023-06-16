using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using DNSmonitor.Models;
using System.Net;
using Microsoft.VisualBasic;
using System.Net.Sockets;

namespace DNSmonitor.Controllers
{
    /// <summary>
    /// Rawsocket 控制器
    /// </summary>
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class RawsocketController : ControllerBase
    {
        private readonly ILogger<RawsocketController> _logger;
        private readonly IConfiguration _configuration;

        /// <summary>
        /// Rawsocket 对象
        /// </summary>
        public Rawsocket rs;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public RawsocketController(ILogger<RawsocketController> logger, IConfiguration configuration)
        //public RawsocketController(ILogger<RawsocketController> logger)
        {
            _logger = logger;
            _configuration = configuration;
            rs = new Rawsocket(_logger);
        }

        /// <summary>
        /// 获取本机所有网卡地址
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult GetNICAddr()
        {
            List<string> iplist = new List<string>();
            // 获取本机所有IP地址
            IPHostEntry ipEntry = Dns.GetHostEntry(Dns.GetHostName());
            foreach( var ip in ipEntry.AddressList)
            {
                Console.WriteLine(ip.AddressFamily.ToString() + ": " + ip.ToString());
                iplist.Add(ip.ToString());
            }
            return Ok(iplist);
        }

        /// <summary>
        /// 开始监听
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        //public ActionResult StartListen(string ip)
        public ActionResult StartListen()
        {
            // rs.CreateAndBindSocket(ip);
            rs.CreateAndBindSocket("10.200.1.158");
            if (rs.ErrorOccured)
            {
                return BadRequest("ErrorOccured");
            }
            rs.Run();
            return Ok();
        }
    }
}

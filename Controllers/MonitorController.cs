using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using DNSmonitor.Models;

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
        private readonly ILogger<MonitorController> _logger;

        private Models.Monitor monitor;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="logger"></param>
        public MonitorController(ILogger<MonitorController> logger)
        {
            _logger = logger;
            monitor = new Models.Monitor();
        }

        /// <summary>
        /// 启动
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Start()
        {
            _logger.LogInformation("Start");
            monitor.Run();
            return Ok();
        }
    }
}

using Microsoft.AspNetCore.Mvc;

namespace DNSmonitor.Controllers
{
    /// <summary>
    /// 监听器的控制API
    /// </summary>
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class MonitorController : ControllerBase
    {
        /// <summary>
        /// 构造函数
        /// </summary>
        public MonitorController() { }
    }
}

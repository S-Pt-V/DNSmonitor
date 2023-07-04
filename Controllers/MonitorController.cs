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
        /*
        /// <summary>
        /// 开始监听
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult Start()
        {
            MonitorService.StratListen();
            return Ok();
        }
        */
    }
}

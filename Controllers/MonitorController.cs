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
        /// 开始监听
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult Start()
        {
            MonitorService.StratListen();
            return Ok();
        }

        /// <summary>
        /// 停止监听
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult Stop()
        {
            return Ok();
        }

        /// <summary>
        /// 获取监听器运行状态
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult State()
        {
            return Ok(MonitorService.GetState());
        }

        /// <summary>
        /// 监听器配置
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Config()
        {
            return Ok();
        }
    }
}

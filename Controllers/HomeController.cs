using BlogAspNet_Improvement.Attributes;
using Microsoft.AspNetCore.Mvc;

namespace BlogAspNet.Controllers
{
    [ApiController]
    [Route("")]
    public class HomeController : ControllerBase
    {
        // Método comum apenas para testar se a API está online.
        [HttpGet("")]
        [ApiKey]
        public IActionResult Get()
        {
            return Ok();
        }
    }
}

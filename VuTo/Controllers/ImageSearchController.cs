using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VuTo.Services.Interface;

namespace VuTo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImageSearchController : ControllerBase
    {
        private readonly IGoogleImageSearcher _googleImageSearcher;

        public ImageSearchController(IGoogleImageSearcher googleImageSearcher)
        {
            _googleImageSearcher = googleImageSearcher;
        }
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> SearchImages([FromQuery] string keyword, [FromQuery] int count = 10)
        {
            if (string.IsNullOrWhiteSpace(keyword))
            {
                return BadRequest("Keyword is required.");
            }
            var userName = User.FindFirstValue(ClaimTypes.Name);

            var images = await _googleImageSearcher.SearchImagesAsync(userName, keyword, count);

            return Ok(images);
        }
    }
}

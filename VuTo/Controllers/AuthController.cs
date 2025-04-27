using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using VuTo.Model;
using VuTo.Services.Interface;

namespace VuTo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthController(IConfiguration configuration, IUserService userService, IHttpContextAccessor httpContextAccessor) 
        {
            _configuration = configuration;
            _userService = userService;
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        }
        [HttpPost("login")] 
        public IActionResult Login([FromBody] LoginModel loginModel)
        {
            if (loginModel == null || string.IsNullOrEmpty(loginModel.Username) || string.IsNullOrEmpty(loginModel.Password))
            {
                return BadRequest("Username and Password are required.");
            }

            var user = _userService.GetUserByUsername(loginModel.Username);

            if (user == null || user.Password != loginModel.Password)
            {
                return Unauthorized("Invalid credentials.");
            }

            var jwtSettings = _configuration.GetSection("Jwt");
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // Subject 
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), // Issued At

                new Claim(ClaimTypes.Name, user.Username!),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),

            };

            if (user.Roles != null && user.Roles.Any())
            {
                foreach (var role in user.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }



            var expirationMinutes = Convert.ToDouble(jwtSettings["ExpirationMinutes"]);
            var expires = DateTime.UtcNow.AddMinutes(expirationMinutes);

            var token = new JwtSecurityToken(
                claims: claims, 
                expires: expires,
                signingCredentials: credentials);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new TokenResponse
            {
                Token = tokenString,
                Expiration = expires.ToLocalTime(),
                Username = user.Username
            });
        }
        [Authorize]
        [HttpGet("currentUser")]
        public IActionResult GetCurrentUser()
        {

            if (User.Identity == null || !User.Identity.IsAuthenticated)
            {
                return Unauthorized();
            }

            // Lấy thông tin từ Claims
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier); 
            var userName = User.FindFirstValue(ClaimTypes.Name); 
            var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value); 

            var userDetails = new UserDetailViewModel
            {
                Id = userId,
                Username = userName,
                Roles = roles
            };

            return Ok(userDetails);
        }
        [Authorize]
        [HttpGet("gethttpcontext")]
        public IActionResult GetHttpRequest()
        {
 

            var httpContext = _httpContextAccessor.HttpContext;

            if (httpContext == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "HttpContext is not available.");
            }
            var authorizationHeader = httpContext.Request.Headers[HeaderNames.Authorization].FirstOrDefault();

            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Unauthorized("Authorization header is missing or invalid.");
            }

            var tokenString = authorizationHeader.Substring("Bearer ".Length).Trim();

            if (string.IsNullOrEmpty(tokenString))
            {
                return Unauthorized("Token is missing.");
            }

            try
            {

                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(tokenString); 

                var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
                var userName = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                var roles = jwtToken.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);

                if (userId == null || userName == null)
                {
                    return BadRequest("Token is valid but missing required claims (UserId or Username).");
                }


                var userDetails = new UserDetailViewModel
                {
                    Id = userId,
                    Username = userName,
                    Roles = roles ?? Enumerable.Empty<string>() 
                };

                return Ok(userDetails);
            }
            catch (Exception ex) 
            { 
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred processing the token.");
            }
        }
    }

}

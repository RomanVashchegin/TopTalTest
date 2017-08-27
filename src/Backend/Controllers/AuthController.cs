using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Backend.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Net;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Backend.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<Role> _roleManager;
        private IPasswordHasher<User> _passwordHasher;
        private IConfigurationRoot _configurationRoot;
        private ILogger<AuthController> _logger;


        public AuthController(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<Role> roleManager,
                              IPasswordHasher<User> passwordHasher, IConfigurationRoot configurationRoot, ILogger<AuthController> logger)
        {
            this._userManager = userManager;
            this._signInManager = signInManager;
            this._roleManager = roleManager;
            this._passwordHasher = passwordHasher;
            this._configurationRoot = configurationRoot;
            this._logger = logger;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var user = new User()
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(result);
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("error", error.Description);
            }
            return BadRequest(result.Errors);
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("token")]
        public async Task<IActionResult> CreateToken([FromBody] LoginViewModel model)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(model.Email);
                if (user == null)
                {
                    return Unauthorized();
                }

                if (_passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password) == PasswordVerificationResult.Success)
                {
                    var userClaims = await _userManager.GetClaimsAsync(user);

                    var claims = new[]
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email)
                    }.Union(userClaims);

                    var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this._configurationRoot["JwtSecurityToken:Key"]));

                    var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

                    var jwtSecurityToken = new JwtSecurityToken(
                        issuer: _configurationRoot["JwtSecurityToken:Issuer"],
                        audience: _configurationRoot["JwtSecurityToken:Audience"],
                        claims: claims,
                        expires: DateTime.UtcNow.AddMinutes(60),
                        signingCredentials: signingCredentials
                        );

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                        expiration = jwtSecurityToken.ValidTo
                    });

                }

                return Unauthorized();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error while creating token: {ex}");
                return StatusCode((int)HttpStatusCode.InternalServerError, "Error while creating token");
            }
        }

    }
}

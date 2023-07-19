using Azure;
using Azure.Core;
using Fitness.Buss.Interface;
using Fitness.DataAccess.ModelDbContext;
using Fitness.Mail.Model;
using Fitness.Mail.Service;
using Fitness.Model.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Fitness.Buss.Repo
{
    public class Authenticate: IAuthenticate
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public readonly SignInManager<ApplicationUser> _signInManager;
        public Authenticate(
           UserManager<ApplicationUser> userManager,
           RoleManager<IdentityRole> roleManager,
           IConfiguration configuration, IEmailService emailService, SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
              _emailService = emailService;
        }

        //public async Task<ServiceResponse<string>> Login(LoginModel loginModel)
        //{
        //    ServiceResponse<string> serviceResponse = new ServiceResponse<string>();
        //    serviceResponse.Message = "Success";
        //    serviceResponse.Success = true;
        //    try
        //    {

        //        var user = await _userManager.FindByNameAsync(loginModel.Username);
        //        if (user.TwoFactorEnabled)
        //        {
        //            await _signInManager.SignOutAsync();
        //            var userRoles = await _userManager.GetRolesAsync(user);
        //            await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
        //            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

        //            var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
        //            _emailService.SendEmail(message);
        //            var authClaims = new List<Claim> {
        //            new Claim(ClaimTypes.Name,user.UserName),
        //            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
        //            };
        //            foreach (var role in userRoles)
        //            {
        //                authClaims.Add(new Claim(ClaimTypes.Role, role));
        //            }
        //            var token = GetToken(authClaims);
        //            serviceResponse.Data = new JwtSecurityTokenHandler().WriteToken(token);
        //        }

        //    }
        //    catch (Exception ex)
        //    {
        //        serviceResponse.Message = ex.ToString();
        //        serviceResponse.Success = false;
        //    }
        //    return serviceResponse;
        //}
        public async Task<ServiceResponse<string>> Login(LoginModel loginModel)
        {
            ServiceResponse<string> serviceResponse = new ServiceResponse<string>();
            serviceResponse.Message = "Success";
            serviceResponse.Success = true;
            try
            {
               
                var user = await _userManager.FindByNameAsync(loginModel.Username);
                var result = await _userManager.IsEmailConfirmedAsync(user);
                if (!result)
                {
                    serviceResponse.Message = "Please verified your Email";
                    serviceResponse.Success = false;
                }
                else
                {
                    if (!user.TwoFactorEnabled)
                    {
                        if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                        {
                            var userRoles = await _userManager.GetRolesAsync(user);
                            var authClaims = new List<Claim> {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                    };
                            foreach (var role in userRoles)
                            {
                                authClaims.Add(new Claim(ClaimTypes.Role, role));
                            }
                            var token = GetToken(authClaims);
                            serviceResponse.Data = new JwtSecurityTokenHandler().WriteToken(token);
                        }

                    }
                    else
                    {
                        await _signInManager.SignOutAsync();
                        var userRoles = await _userManager.GetRolesAsync(user);
                        await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                        var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                        var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
                        _emailService.SendEmail(message);
                        serviceResponse.Data = "OTP Sended Successfully";
                    }
                }
                
               
            }
            catch (Exception ex)
            {
                serviceResponse.Message = ex.ToString();
                serviceResponse.Success = false;
            }
            return serviceResponse;
        }
        public async Task<ServiceResponse<string>> LoginWithOTP(string code, string username)
        {
            ServiceResponse<string> serviceResponse = new ServiceResponse<string>();
            serviceResponse.Message = "Success";
            serviceResponse.Success = true;
            try
            {
                var user = await _userManager.FindByNameAsync(username);
                var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
                if (signIn.Succeeded)
                {
                    if (user != null)
                    {

                        var userRoles = await _userManager.GetRolesAsync(user);

                        var authClaims = new List<Claim> {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                    };
                        foreach (var role in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, role));
                        }
                        var token = GetToken(authClaims);
                        serviceResponse.Data = new JwtSecurityTokenHandler().WriteToken(token);

                    }
                }
            }
            catch (Exception ex)
            {
                serviceResponse.Message = ex.ToString();
                serviceResponse.Success = false;
            }
           
            return serviceResponse;
        }

        public async Task<ServiceResponse<ApplicationUser>> SignIn(RegisterModel registerModel)
        {
            ServiceResponse<ApplicationUser> serviceResponse = new ServiceResponse<ApplicationUser>();
            serviceResponse.Message = "Success";
            serviceResponse.Success = true;
            ApplicationUser user = new()
            {
                Email = registerModel.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.Username,
                FirstName = registerModel.FirstName,
                Last_name = registerModel.Last_name,
                Age = registerModel.Age,
                TwoFactorEnabled = true,
            };
            try
            {

                var userexists = await _userManager.FindByNameAsync(registerModel.Username);
                var usermail = await _userManager.FindByEmailAsync(registerModel.Email);
                if (userexists != null && usermail!=null)
                {
                    serviceResponse.Data = user;
                    serviceResponse.Message = "User Already Exists";
                    serviceResponse.Success = false;
                    return serviceResponse;
                }
                else
                {
                    
                    var result = await _userManager.CreateAsync(user,registerModel.Password);
                    if (result.Succeeded)
                    {
                        if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                            await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
                        if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                            await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

                        if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                        {
                            await _userManager.AddToRoleAsync(user, UserRoles.Admin);
                        }
                        else
                        {
                            await _userManager.AddToRoleAsync(user, UserRoles.User);
                        }

                        serviceResponse.Data = user;
                    }

                }

            }
            catch (Exception ex)
            {
                serviceResponse.Message = ex.ToString();
                serviceResponse.Success = false;
            }
            return serviceResponse;
        }
        public async Task<ServiceResponse<string>> ConfirmEmail(string token, string email) 
        {
            ServiceResponse<string> serviceResponse = new ServiceResponse<string>();
            serviceResponse.Message = "success";
            serviceResponse.Success = true;
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    var result = await _userManager.ConfirmEmailAsync(user, token);
                    if (result.Succeeded)
                    {
                        return serviceResponse;
                    }
                }
               
            }
            catch(Exception ex)
            {
                serviceResponse.Message = ex.ToString();
                serviceResponse.Success = false;
            }
            return serviceResponse;
           
        }

        private JwtSecurityToken GetToken(List<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
               issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: claims,
                                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }

    }
}

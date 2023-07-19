using Azure;
using Fitness.Buss.Interface;
using Fitness.DataAccess.ModelDbContext;
using Fitness.Mail.Model;
using Fitness.Mail.Service;
using Fitness.Model.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FitnesApp.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IAuthenticate _authenticate;
        private readonly IEmailService _emailService;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthenticateController(IAuthenticate authenticate, IEmailService emailService, UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
            _authenticate = authenticate;
            _emailService = emailService;
        }
      [Route("Login")]
      [HttpPost]
      
        public async Task<ServiceResponse<string>> Login(LoginModel loginModel)
        {
            var result = await _authenticate.Login(loginModel);
            return result;
        }
        [Route("SignIn")]
        [HttpPost]
        public async Task<ServiceResponse<string>> SignIn(RegisterModel registerModel)
        {
            ServiceResponse<string> serviceResponse = new ServiceResponse<string>();
            var result = await _authenticate.SignIn(registerModel);
            if (result.Success)
            {
               
                //Add Token to Verify the email....
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(result.Data);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authenticate", new { token, email = registerModel.Email }, Request.Scheme);
                var message = new Message(new string[] { registerModel.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);
                serviceResponse.Message = "Please verifiy email";
                serviceResponse.Success = true;
            }
            return serviceResponse;
        }
        [Route("SendEmail")]
        [HttpGet]
        public async Task SendMail()
        {
            var message = new Message(
                new string[] { "avinashsaroj7754@gmail.com"},"Test","<h1>subscribe to my channel</h1>"
                );
            _emailService.SendEmail(message);

        }
        [HttpGet("ConfirmEmail")]
        public async Task<ServiceResponse<string>> ConfirmEmail(string token, string email)
        {
            var result = await _authenticate.ConfirmEmail(token,email);
            return result;
        }
        [HttpPost]
        [Route("LoginWithOTP")]
        public async Task<ServiceResponse<string>> LoginWithOTP(string code, string username)
        {
            var result = await _authenticate.LoginWithOTP(code, username);
            return result;
        }
    }
}

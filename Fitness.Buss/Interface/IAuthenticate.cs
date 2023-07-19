using Fitness.DataAccess.ModelDbContext;
using Fitness.Model.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fitness.Buss.Interface
{
    public interface IAuthenticate
    {
        Task<ServiceResponse<string>> Login(LoginModel loginModel);
        Task<ServiceResponse<ApplicationUser>> SignIn(RegisterModel registerModel);
        Task<ServiceResponse<string>> ConfirmEmail(string token, string email);
        Task<ServiceResponse<string>> LoginWithOTP(string code, string username);
    }
}

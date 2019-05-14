using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using WebAdvert.Web.Models.Account;


namespace WebAdvert.Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<CognitoUser> signInManager;
        private readonly UserManager<CognitoUser> userManager;
        private readonly CognitoUserPool pool;
        private readonly IAmazonCognitoIdentityProvider identityProvider;
        private readonly IConfiguration configuration;

        public AccountController(SignInManager<CognitoUser> signInManager,
            UserManager<CognitoUser> userManager,
            CognitoUserPool pool,
            IAmazonCognitoIdentityProvider identityProvider,
            IConfiguration configuration)

        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.pool = pool;
            this.identityProvider = identityProvider;
            this.configuration = configuration;
        }
        public async Task<IActionResult> Signup()
        {
            return View(new SignupModel());
        }
        [HttpPost]
        public async Task<IActionResult> SignUp(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }
                user.Attributes.Add("name", model.Email);
                var createdUser = await userManager.CreateAsync(user, model.Password);
                if (createdUser.Succeeded)
                    return RedirectToAction("Confirm");

            }
            return View(model);
        }
        public async Task<IActionResult> Confirm()
        {
            return View(new ConfirmModel());
        }
        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError("UserNotFound", "User not found");
                    return View(model);
                }
                var result = await (userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if (result.Succeeded)
                    return RedirectToAction("Index", "Home");

                foreach (var item in result.Errors)
                    ModelState.AddModelError(item.Code, item.Description);
            }
            return View(model);
        }

        public async Task<IActionResult> ForgotPassword()
        {
            return View(new ForgotPasswordModel());
        }
        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            await identityProvider.ForgotPasswordAsync(new Amazon.CognitoIdentityProvider.Model.ForgotPasswordRequest
            {
                ClientId = configuration["AWS:UserPoolClientId"],
                Username = model.Email,
                SecretHash = GetSecretHash(model.Email, configuration["AWS:UserPoolClientId"], configuration["AWS:UserPoolClientSecret"]),

            });
            return View(model);
        }
        public async Task<IActionResult> ChangePassword()
        {
            return View(new ChangePasswordModel());
        }
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            var user = pool.GetUser(model.Email);
            await identityProvider.ConfirmForgotPasswordAsync(new Amazon.CognitoIdentityProvider.Model.ConfirmForgotPasswordRequest
            {
                ClientId = configuration["AWS:UserPoolClientId"],
                Username = model.Email,
                SecretHash = GetSecretHash(model.Email, configuration["AWS:UserPoolClientId"], configuration["AWS:UserPoolClientSecret"]),
                ConfirmationCode = model.Token,
                Password = model.Password
            });
            return View(model);
        }
        public async Task<IActionResult> SignIn()
        {
            return View(new SignInModel());
        }
        [HttpPost]
        public async Task<IActionResult> SignIn(SignInModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                    return RedirectToAction("Index", "Home");
                else
                    ModelState.AddModelError("LoginFailed", "Email / Password do not match");
            }
            return View(model);
        }
        private static string GetSecretHash(string username, string appClientId, string appSecretKey)
        {
            var dataString = username + appClientId;
            var data = Encoding.UTF8.GetBytes(dataString);
            var key = Encoding.UTF8.GetBytes(appSecretKey);
            return Convert.ToBase64String(HmacSHA256(data, key));
        }
        private static byte[] HmacSHA256(byte[] data, byte[] key)
        {
            using (var shaAlgorithm = new System.Security.Cryptography.HMACSHA256(key))
            {
                var result = shaAlgorithm.ComputeHash(data);
                return result;
            }
        }
        public async Task<IActionResult> SignOut()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("SignIn");
        }
    }
}
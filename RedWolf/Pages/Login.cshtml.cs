using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using RedWolf.Core;
using RedWolf.Models;
using RedWolf.Models.RedWolf;

namespace RedWolf.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<RedWolfUser> _signInManager;
        private readonly UserManager<RedWolfUser> _userManager;

        public LoginModel(SignInManager<RedWolfUser> signInManager, UserManager<RedWolfUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public RedWolfUserRegister RedWolfUserRegister { get; set; }
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                if (!_userManager.Users.ToList().Where(U => _userManager.IsInRoleAsync(U, "Administrator").WaitResult()).Any())
                {
                    if (RedWolfUserRegister.Password != RedWolfUserRegister.ConfirmPassword)
                    {
                        return BadRequest($"BadRequest - Password does not match ConfirmPassword.");
                    }

                    RedWolfUser user = new RedWolfUser { UserName = RedWolfUserRegister.UserName };
                    IdentityResult userResult = await _userManager.CreateAsync(user, RedWolfUserRegister.Password);
                    await _userManager.AddToRoleAsync(user, "User");
                    await _userManager.AddToRoleAsync(user, "Administrator");
                    await _signInManager.PasswordSignInAsync(RedWolfUserRegister.UserName, RedWolfUserRegister.Password, true, lockoutOnFailure: false);
                    // return RedirectToAction(nameof(Index));
                    return LocalRedirect("/home/index");
                }
                else
                {
                    var result = await _signInManager.PasswordSignInAsync(RedWolfUserRegister.UserName, RedWolfUserRegister.Password, true, lockoutOnFailure: false);
                    if (!result.Succeeded == true)
                    {
                        ModelState.AddModelError(string.Empty, "Incorrect username or password");
                        return Page();
                    }
                    // if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    // {
                    //     return LocalRedirect(returnUrl);
                    // }
                    // return RedirectToAction("Index", "Home");
                    return LocalRedirect("/home/index");
                }
            }
            catch (Exception e) when (e is ControllerNotFoundException || e is ControllerBadRequestException || e is ControllerUnauthorizedException)
            {
                ModelState.AddModelError(string.Empty, e.Message);
                return Page();
            }
        }
    }
}

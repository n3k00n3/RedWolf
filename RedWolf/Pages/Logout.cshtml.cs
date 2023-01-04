using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using RedWolf.Models.RedWolf;

namespace RedWolf.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<RedWolfUser> _signInManager;

        public LogoutModel(SignInManager<RedWolfUser> signInManager)
        {
            _signInManager = signInManager;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            await _signInManager.SignOutAsync();
            return LocalRedirect("/redwolfuser/login");
        }
    }
}

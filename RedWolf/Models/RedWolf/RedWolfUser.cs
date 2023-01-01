// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Identity;

namespace RedWolf.Models.RedWolf
{
    public class RedWolfUser : IdentityUser
    {
        public RedWolfUser() : base()
        {
            this.Email = "";
            this.NormalizedEmail = "";
            this.PhoneNumber = "";
            this.LockoutEnd = DateTime.UnixEpoch;
            this.ThemeId = 1;
        }

        public int ThemeId { get; set; }
        public Theme Theme { get; set; }
    }

    public class RedWolfUserLogin
    {
        public string Id { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }

    public class RedWolfUserRegister : RedWolfUserLogin
    {
        [Required]
        public string ConfirmPassword { get; set; }
    }

    public class RedWolfUserLoginResult
    {
        public bool Success { get; set; } = true;
        public string RedWolfToken { get; set; } = default;
    }
}

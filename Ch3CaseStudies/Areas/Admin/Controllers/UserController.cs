using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Ch3CaseStudies.Models.DomainModels.Identity;

namespace Ch3CaseStudies.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin")]
    public class UserController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> List()
        {
            var users = _userManager.Users.ToList();
            var userList = new List<UserWithRolesViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userList.Add(new UserWithRolesViewModel
                {
                    User = user,
                    Roles = roles.ToList(),
                    IsDefaultAdmin = user.UserName == "admin"
                });
            }

            return View(userList);
        }

        [HttpPost]
        public async Task<IActionResult> ToggleAdminRole(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                TempData["Message"] = "User not found.";
                return RedirectToAction("List");
            }

            // Protect the default admin account
            if (user.UserName == "admin")
            {
                TempData["Message"] = "Cannot modify the default admin account.";
                return RedirectToAction("List");
            }

            var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
            
            if (isAdmin)
            {
                await _userManager.RemoveFromRoleAsync(user, "Admin");
                TempData["Message"] = $"Removed admin privileges from {user.UserName}.";
            }
            else
            {
                await _userManager.AddToRoleAsync(user, "Admin");
                TempData["Message"] = $"Granted admin privileges to {user.UserName}.";
            }

            return RedirectToAction("List");
        }
    }

    public class UserWithRolesViewModel
    {
        public User User { get; set; }
        public List<string> Roles { get; set; }
        public bool IsDefaultAdmin { get; set; }
    }
}

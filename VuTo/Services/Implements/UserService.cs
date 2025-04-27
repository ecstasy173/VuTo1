using VuTo.Model;
using VuTo.Services.Interface;

namespace VuTo.Services.Implements
{
    public class UserService : IUserService
    {
        private readonly List<User> _users = new List<User>
        {
            new User {
                Id = 1,
                Username = "haloli",
                Password = "password", 
                Roles = new[] { "Loli" }
            },
            new User {
                Id = 2,
                Username = "admin",
                Password = "password",
                Roles = new[] { "WeRevert"}
            }
    
        };

        public User? GetUserByUsername(string username)
        {
            return _users.FirstOrDefault(u =>
                !string.IsNullOrEmpty(u.Username) &&
                u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        }
    }
}

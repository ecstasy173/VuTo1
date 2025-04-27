using VuTo.Model;

namespace VuTo.Services.Interface
{
    public interface IUserService
    {
        User? GetUserByUsername(string username);
    }
}

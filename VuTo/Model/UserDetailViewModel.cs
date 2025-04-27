namespace VuTo.Model
{
    public class UserDetailViewModel
    {
        public string? Id { get; set; } 
        public string? Username { get; set; }
        public IEnumerable<string>? Roles { get; set; }
    }
}

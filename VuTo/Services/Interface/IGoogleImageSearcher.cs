namespace VuTo.Services.Interface
{
    public interface IGoogleImageSearcher
    {
        Task<List<string>> SearchImagesAsync(string username, string query, int count = 10);
    }
}

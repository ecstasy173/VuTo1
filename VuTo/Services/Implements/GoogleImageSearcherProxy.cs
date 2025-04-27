using VuTo.Services.Interface;

namespace VuTo.Services.Implements
{
    public class GoogleImageSearcherProxy : IGoogleImageSearcher
    {
        private readonly GoogleImageSearcher _googleImageSearcher;
        private readonly GoogleImageSearcherHaloli _googleImageSearcherHaloli;

        public GoogleImageSearcherProxy(GoogleImageSearcher googleImageSearcher, GoogleImageSearcherHaloli googleImageSearcherHaloli)
        {
            _googleImageSearcher = googleImageSearcher;
            _googleImageSearcherHaloli = googleImageSearcherHaloli;
        }
        public Task<List<string>> SearchImagesAsync(string username, string query, int count = 10)
        {
            if (username == "haloli")
            {
               return _googleImageSearcherHaloli.SearchImagesAsync(username, query,count);
            }
            else
            {
               return _googleImageSearcher.SearchImagesAsync(username, query, count);
            }
        }
    }
}

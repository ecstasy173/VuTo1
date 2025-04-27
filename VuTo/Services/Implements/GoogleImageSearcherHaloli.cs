using System.Text.Json.Serialization;
using System.Text.Json;
using VuTo.Services.Interface;
using VuTo.Model;

namespace VuTo.Services.Implements
{
    public class GoogleImageSearcherHaloli : IGoogleImageSearcher
    {
        private readonly HttpClient _httpClient;
        private readonly GoogleSearchOptions _options;

        public GoogleImageSearcherHaloli(HttpClient httpClient, GoogleSearchOptions options)
        {
            _httpClient = httpClient;
            _options = options;
        }

        public async Task<List<string>> SearchImagesAsync(string username, string query, int count = 10)
        {
            var url = $"https://www.googleapis.com/customsearch/v1?q={Uri.EscapeDataString(query)}&cx={_options.SearchEngineId}&key={_options.ApiKey}&searchType=image&num={1}";

            var response = await _httpClient.GetAsync(url);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new Exception($"API call failed with status code {response.StatusCode}: {errorContent}");
            }
            response.EnsureSuccessStatusCode();

            using var responseStream = await response.Content.ReadAsStreamAsync();
            var result = await JsonSerializer.DeserializeAsync<GoogleSearchResponse>(responseStream);

            var imageUrls = result?.Items?.Select(item => item.Link).ToList() ?? new List<string>();

            return imageUrls;
        }

        private class GoogleSearchResponse
        {
            [JsonPropertyName("items")]
            public List<SearchItem> Items { get; set; }
        }

        private class SearchItem
        {
            [JsonPropertyName("link")]
            public string Link { get; set; }
        }
    }
}

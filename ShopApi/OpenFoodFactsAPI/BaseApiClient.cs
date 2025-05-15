using System.Text.Json;
using System.Text;
using System.Text.Json.Serialization;

namespace ShopApi.OpenFoodFactsAPI
{
	public abstract class BaseApiClient
	{
		protected readonly HttpClient _httpClient;
		protected readonly JsonSerializerOptions _jsonOptions;

		protected BaseApiClient(HttpClient httpClient)
		{
			_httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
			_jsonOptions = new JsonSerializerOptions
			{
				PropertyNameCaseInsensitive = true,
				PropertyNamingPolicy = JsonNamingPolicy.CamelCase
			};
			_httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ShopApi/1.0");
		}

		/// <summary>
		/// Makes a GET request to the specified endpoint
		/// </summary>
		protected async Task<T> GetAsync<T>(string endpoint)
		{
			try
			{
				// Ensure endpoint starts with a slash
				if (!endpoint.StartsWith("/"))
					endpoint = "/" + endpoint;

				var response = await _httpClient.GetAsync(_httpClient.BaseAddress + endpoint);
				response.EnsureSuccessStatusCode();
				string contentString = await response.Content.ReadAsStringAsync();

				Console.WriteLine($"Content type: {response.Content.Headers.ContentType}");
				Console.WriteLine($"Content preview: {contentString.Substring(0, Math.Min(100, contentString.Length))}");

				if (contentString.TrimStart().StartsWith("<"))
				{
					throw new ApiException($"Received HTML instead of JSON from {endpoint}. First 100 chars: {contentString.Substring(0, Math.Min(100, contentString.Length))}");
				}
				// First check the content type
				return JsonSerializer.Deserialize<T>(contentString, _jsonOptions);
			}
			catch (JsonException ex)
			{
				throw new ApiException($"Error deserializing response from {endpoint}", ex);
			}
			catch (Exception ex)
			{
				throw new ApiException($"Error making GET request to {endpoint}", ex);
			}
		}

		/// <summary>
		/// Makes a POST request to the specified endpoint with the given data
		/// </summary>
		protected async Task<TResponse> PostAsync<TRequest, TResponse>(string endpoint, TRequest data)
		{
			try
			{
				var content = new StringContent(
					JsonSerializer.Serialize(data, _jsonOptions),
					Encoding.UTF8,
					"application/json");

				var response = await _httpClient.PostAsync(endpoint, content);
				response.EnsureSuccessStatusCode();

				// Read the raw response content as string
				string contentString = await response.Content.ReadAsStringAsync();

				// Deserialize the content using the configured options
				return JsonSerializer.Deserialize<TResponse>(contentString, _jsonOptions);
			}
			catch (JsonException ex)
			{
				throw new ApiException($"Error deserializing response from {endpoint}", ex);
			}
			catch (Exception ex)
			{
				throw new ApiException($"Error making POST request to {endpoint}", ex);
			}
		}
	}
}

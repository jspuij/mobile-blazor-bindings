---
title: Mobile Blazor Bindings Security additional security scenarios
---
#  Mobile Blazor Bindings Security additional security scenarios

By [Javier Calvarro Nelson](https://github.com/javiercn), [Luke Latham](https://github.com/guardrex) and [Jan-Willem Spuij](https://github.com/jspuij)

## Attach tokens to outgoing requests

<xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler> is a <xref:System.Net.Http.DelegatingHandler> used to attach access tokens to outgoing <xref:System.Net.Http.HttpResponseMessage> instances. Tokens are acquired using the <xref:Microsoft.MobileBlazorBindings.Authentication.IAccessTokenProvider> service, which is registered by the framework. If a token can't be acquired, an <xref:Microsoft.MobileBlazorBindings.Authentication.AccessTokenNotAvailableException> is thrown. <xref:Microsoft.MobileBlazorBindings.Authentication.AccessTokenNotAvailableException> has a <xref:Microsoft.MobileBlazorBindings.Authentication.AccessTokenNotAvailableException.RequestPermission%2A> method that can be used to use the browser to navigate the user to the identity provider to acquire a new token.

For convenience, the framework provides the <xref:Microsoft.MobileBlazorBindings.Authentication.ApiAuthorizationMessageHandler> preconfigured with a specified API address as an authorized URL. **Access tokens are only added when the request URI is within the API URI.** When outgoing request URIs aren't within the API URI, use a [custom `AuthorizationMessageHandler` class (*recommended*)](#custom-authorizationmessagehandler-class) or [configure the `AuthorizationMessageHandler`](#configure-authorizationmessagehandler).

> [!NOTE]
> In addition to the app configuration for server API access, the server API must also allow cross-origin requests (CORS) for the Url that hosts the app. This Url might reside on a custom scheme. For more information on server-side CORS configuration, see the [Cross-origin resource sharing (CORS)](#cross-origin-resource-sharing-cors) section later in this article.

In the following example:

* <xref:Microsoft.Extensions.DependencyInjection.HttpClientFactoryServiceCollectionExtensions.AddHttpClient%2A> adds <xref:System.Net.Http.IHttpClientFactory> and related services to the service collection and configures a named <xref:System.Net.Http.HttpClient> (`ServerAPI`). <xref:System.Net.Http.HttpClient.BaseAddress?displayProperty=nameWithType> is the base address of the resource URI when sending requests. <xref:System.Net.Http.IHttpClientFactory> is provided by the [`Microsoft.Extensions.Http`](https://www.nuget.org/packages/Microsoft.Extensions.Http) NuGet package.
* <xref:Microsoft.MobileBlazorBindings.Authentication.ApiAddressAuthorizationMessageHandler> is the <xref:System.Net.Http.DelegatingHandler> used to attach access tokens to outgoing <xref:System.Net.Http.HttpResponseMessage> instances. Access tokens are only added when the request URI is within the API's URI.
* <xref:System.Net.Http.IHttpClientFactory.CreateClient%2A?displayProperty=nameWithType> creates and configures an <xref:System.Net.Http.HttpClient> instance for outgoing requests using the configuration that corresponds to the named <xref:System.Net.Http.HttpClient> (`ServerAPI`).
* Because the AuthorizationMessageHandlers have their own scopes to resolve dependencies from, we need to register the TokenProvider with the Message Handler whenever a new HttpClient is created.

```csharp
using System.Net.Http;
using Microsoft.MobileBlazorBindings.Authentication;
...
private const string BaseUrl = "https://example.com/";
...
// Register app-specific services
// Configure HttpClient for use when talking to server backend
services.AddHttpClient("ServerAPI",
    client => client.BaseAddress = new Uri(BaseAddress))
    .AddHttpMessageHandler(() => new ApiAuthorizationMessageHandler(BaseAddress));

// Add the http client as the default to inject.
services.AddScoped<HttpClient>(sp =>
{
    var accessTokenProvider = sp.GetRequiredService<IAccessTokenProvider>();
    var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
    ApiAuthorizationMessageHandler.RegisterTokenProvider(BaseAddress, accessTokenProvider);
    return httpClientFactory.CreateClient("ServerAPI");
});

```

The configured <xref:System.Net.Http.HttpClient> is used to make authorized requests using the [`try-catch`](/dotnet/csharp/language-reference/keywords/try-catch) pattern:

```razor
@using Microsoft.MobileBlazorBindings.Authentication
@inject HttpClient Http

...

protected override async Task OnInitializedAsync()
{
    private ExampleType[] examples;

    try
    {
        examples = 
            await Http.GetFromJsonAsync<ExampleType[]>("ExampleAPIMethod");

        ...
    }
    catch (AccessTokenNotAvailableException exception)
    {
        exception.RequestPermission();
    }
}
```

### Custom `AuthorizationMessageHandler` class

*This guidance in this section is recommended for apps that make outgoing requests to additional URIs that aren't within the base URI.*

In the following example, a custom class extends <xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler> for use as the <xref:System.Net.Http.DelegatingHandler> for an <xref:System.Net.Http.HttpClient>. <xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler.ConfigureHandler%2A> configures this handler to authorize outbound HTTP requests using an access token. The access token is only attached if at least one of the authorized URLs is a base of the request URI (<xref:System.Net.Http.HttpRequestMessage.RequestUri?displayProperty=nameWithType>).

```csharp
using Microsoft.AspNetCore.Components;
using Microsoft.MobileBlazorBindings.Authentication;

public class CustomAuthorizationMessageHandler : AuthorizationMessageHandler
{
    public CustomAuthorizationMessageHandler(IAccessTokenProvider provider, 
        NavigationManager navigationManager)
        : base(provider, navigationManager)
    {
        ConfigureHandler(
            authorizedUrls: new[] { "https://www.example.com/base" },
            scopes: new[] { "example.read", "example.write" });
    }
}
```

In `Program.Main` (`Program.cs`), `CustomAuthorizationMessageHandler` is registered as a scoped service and is configured as the <xref:System.Net.Http.DelegatingHandler> for outgoing <xref:System.Net.Http.HttpResponseMessage> instances made by a named <xref:System.Net.Http.HttpClient>:

```csharp
services.AddScoped<CustomAuthorizationMessageHandler>();

services.AddHttpClient("ServerAPI",
        client => client.BaseAddress = new Uri("https://www.example.com/base"))
    .AddHttpMessageHandler<CustomAuthorizationMessageHandler>();
```

The configured <xref:System.Net.Http.HttpClient> is used to make authorized requests using the [`try-catch`](/dotnet/csharp/language-reference/keywords/try-catch) pattern. Where the client is created with <xref:System.Net.Http.IHttpClientFactory.CreateClient%2A> ([`Microsoft.Extensions.Http`](https://www.nuget.org/packages/Microsoft.Extensions.Http) package), the <xref:System.Net.Http.HttpClient> is supplied instances that include access tokens when making requests to the server API. If the request URI is a relative URI, as it is in the following example (`ExampleAPIMethod`), it's combined with the <xref:System.Net.Http.HttpClient.BaseAddress> when the client app makes the request:

```razor
@inject IHttpClientFactory ClientFactory

...

@code {
    private ExampleType[] examples;

    protected override async Task OnInitializedAsync()
    {
        try
        {
            var client = ClientFactory.CreateClient("ServerAPI");

            examples = 
                await client.GetFromJsonAsync<ExampleType[]>("ExampleAPIMethod");
        }
        catch (AccessTokenNotAvailableException exception)
        {
            exception.RequestPermission();
        }
    }
}
```

### Configure `AuthorizationMessageHandler`

<xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler> can be configured with authorized URLs, scopes, and a return URL using the <xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler.ConfigureHandler%2A> method. <xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler.ConfigureHandler%2A> configures the handler to authorize outbound HTTP requests using an access token. The access token is only attached if at least one of the authorized URLs is a base of the request URI (<xref:System.Net.Http.HttpRequestMessage.RequestUri?displayProperty=nameWithType>). If the request URI is a relative URI, it's combined with the <xref:System.Net.Http.HttpClient.BaseAddress>.

In the following example, <xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler> configures an <xref:System.Net.Http.HttpClient> in `Program.Main` (`Program.cs`):

```csharp
using System.Net.Http;
using Microsoft.MobileBlazorBindings.Authentication;

...

builder.Services.AddScoped(sp => new HttpClient(
    sp.GetRequiredService<AuthorizationMessageHandler>()
    .ConfigureHandler(
        authorizedUrls: new[] { "https://www.example.com/base" },
        scopes: new[] { "example.read", "example.write" }))
    {
        BaseAddress = new Uri("https://www.example.com/base")
    });
```

## Typed `HttpClient`

A typed client can be defined that handles all of the HTTP and token acquisition concerns within a single class.

`WeatherForecastClient.cs`:

```csharp
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.MobileBlazorBindings.Authentication;
using static {APP ASSEMBLY}.Data;

public class WeatherForecastClient
{
    private readonly HttpClient http;
 
    public WeatherForecastClient(HttpClient http)
    {
        this.http = http;
    }
 
    public async Task<WeatherForecast[]> GetForecastAsync()
    {
        var forecasts = new WeatherForecast[0];

        try
        {
            forecasts = await http.GetFromJsonAsync<WeatherForecast[]>(
                "WeatherForecast");
        }
        catch (AccessTokenNotAvailableException exception)
        {
            exception.RequestPermission();
        }

        return forecasts;
    }
}
```

The placeholder `{APP ASSEMBLY}` is the app's assembly name (for example, `using static BlazorSample.Data;`).

`Program.Main` (`Program.cs`):

```csharp
using System.Net.Http;
using Microsoft.MobileBlazorBindings.Authentication;

...

builder.Services.AddHttpClient<WeatherForecastClient>(
        client => client.BaseAddress = new Uri("https://www.example.com/base"))
    .AddHttpMessageHandler(() => new ApiAuthorizationMessageHandler("https://www.example.com/base"));
```

`FetchData` component (`Pages/FetchData.razor`):

```razor
@inject WeatherForecastClient Client

...

protected override async Task OnInitializedAsync()
{
    forecasts = await Client.GetForecastAsync();
}
```

## Configure the `HttpClient` handler

The handler can be further configured with <xref:Microsoft.MobileBlazorBindings.Authentication.AuthorizationMessageHandler.ConfigureHandler%2A> for outbound HTTP requests.

`Program.Main` (`Program.cs`):

```csharp
builder.Services.AddHttpClient<WeatherForecastClient>(
        client => client.BaseAddress = new Uri("https://www.example.com/base"))
    .AddHttpMessageHandler(sp => sp.GetRequiredService<AuthorizationMessageHandler>()
    .ConfigureHandler(
        authorizedUrls: new [] { "https://www.example.com/base" },
        scopes: new[] { "example.read", "example.write" }));
```

For a Blazor app based on the Blazor WebAssembly Hosted project template, <xref:Microsoft.AspNetCore.Components.WebAssembly.Hosting.IWebAssemblyHostEnvironment.BaseAddress?displayProperty=nameWithType> is assigned to the following by default:

* The <xref:System.Net.Http.HttpClient.BaseAddress?displayProperty=nameWithType> (`new Uri(builder.HostEnvironment.BaseAddress)`).
* A URL of the `authorizedUrls` array.

## Unauthenticated or unauthorized web API requests in an app with a secure default client

If the Blazor WebAssembly app ordinarily uses a secure default <xref:System.Net.Http.HttpClient>, the app can also make unauthenticated or unauthorized web API requests by configuring a named <xref:System.Net.Http.HttpClient>:

`Program.Main` (`Program.cs`):

```csharp
builder.Services.AddHttpClient("ServerAPI.NoAuthenticationClient", 
    client => client.BaseAddress = new Uri("https://www.example.com/base"));
```

The preceding registration is in addition to the existing secure default <xref:System.Net.Http.HttpClient> registration.

A component creates the <xref:System.Net.Http.HttpClient> from the <xref:System.Net.Http.IHttpClientFactory> ([`Microsoft.Extensions.Http`](https://www.nuget.org/packages/Microsoft.Extensions.Http) package) to make unauthenticated or unauthorized requests:

```razor
@inject IHttpClientFactory ClientFactory

...

@code {
    private WeatherForecast[] forecasts;

    protected override async Task OnInitializedAsync()
    {
        var client = ClientFactory.CreateClient("ServerAPI.NoAuthenticationClient");

        forecasts = await client.GetFromJsonAsync<WeatherForecast[]>(
            "WeatherForecastNoAuthentication");
    }
}
```

> [!NOTE]
> The controller in the server API, `WeatherForecastNoAuthenticationController` for the preceding example, isn't marked with the [`[Authorize]`](xref:Microsoft.AspNetCore.Authorization.AuthorizeAttribute) attribute.

The decision whether to use a secure client or an insecure client as the default <xref:System.Net.Http.HttpClient> instance is up to the developer. One way to make this decision is to consider the number of authenticated versus unauthenticated endpoints that the app contacts. If the majority of the app's requests are to secure API endpoints, use the authenticated <xref:System.Net.Http.HttpClient> instance as the default. Otherwise, register the unauthenticated <xref:System.Net.Http.HttpClient> instance as the default.

An alternative approach to using the <xref:System.Net.Http.IHttpClientFactory> is to create a [typed client](#typed-httpclient) for unauthenticated access to anonymous endpoints.

## Request additional access tokens

Access tokens can be manually obtained by calling `IAccessTokenProvider.RequestAccessToken`. In the following example, an additional scope is required by an app for the default <xref:System.Net.Http.HttpClient>. The example below configures the scope with `OidcProviderOptions`:

`Program.Main` (`Program.cs`):

```csharp
builder.Services.AddOidcAuthentication(options =>
{
    ...

    options.ProviderOptions.DefaultScopes.Add("{CUSTOM SCOPE 1}");
    options.ProviderOptions.DefaultScopes.Add("{CUSTOM SCOPE 2}");
}
```

The `{CUSTOM SCOPE 1}` and `{CUSTOM SCOPE 2}` placeholders in the preceding example are custom scopes.

The `IAccessTokenProvider.RequestToken` method provides an overload that allows an app to provision an access token with a given set of scopes.

In a Razor component:

```razor
@using Microsoft.MobileBlazorBindings.Authentication
@inject IAccessTokenProvider TokenProvider

...

var tokenResult = await TokenProvider.RequestAccessToken(
    new AccessTokenRequestOptions
    {
        Scopes = new[] { "{CUSTOM SCOPE 1}", "{CUSTOM SCOPE 2}" }
    });

if (tokenResult.TryGetToken(out var token))
{
    ...
}
```

The `{CUSTOM SCOPE 1}` and `{CUSTOM SCOPE 2}` placeholders in the preceding example are custom scopes.

<xref:Microsoft.MobileBlazorBindings.Authentication.AccessTokenResult.TryGetToken%2A?displayProperty=nameWithType> returns:

* `true` with the `token` for use.
* `false` if the token isn't retrieved.

## Cross-origin resource sharing (CORS)

When sending credentials (authorization cookies/headers) on CORS requests, the `Authorization` header must be allowed by the CORS policy.

The following policy includes configuration for:

* Request origins (`http://localhost:5000`, `https://localhost:5001`, "app://0.0.0.0", "http://localhost").
* Any method (verb).
* `Content-Type` and `Authorization` headers. To allow a custom header (for example, `x-custom-header`), list the header when calling <xref:Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder.WithHeaders*>.
* Credentials set by client-side JavaScript code (`credentials` property set to `include`).

```csharp
app.UseCors(policy => 
    policy.WithOrigins("http://localhost:5000", "https://localhost:5001', "app://0.0.0.0", "http://localhost")
    .AllowAnyMethod()
    .WithHeaders(HeaderNames.ContentType, HeaderNames.Authorization, "x-custom-header")
    .AllowCredentials());
```

For more information, see <xref:security/cors> and the sample app's HTTP Request Tester component (`Components/HTTPRequestTester.razor`).

## Handle token request errors

When a Mobile Blazor Binding app authenticates a user using OpenID Connect (OIDC), the authentication state is maintained locally within the app and in the browser or secure webview in the form of a session cookie that's set as a result of the user providing their credentials.

The access tokens that the IP emits for the user typically are valid for short periods of time, about one hour normally, so the client app must regularly fetch new tokens. Otherwise, the user would be logged-out after the granted tokens expire. The IP might also provide refresh tokens that allow the app to get a new access token without
going through the interactive login process again. There are some cases in which the client can't get a token without user interaction, for example, when for some reason the user explicitly logs out from the IP. This scenario occurs if a user visits `https://login.microsoftonline.com` and logs out. In these scenarios, the app doesn't know immediately that the user has logged out. Any (access or refresh) token that the client holds might no longer be valid. Also, the client isn't able to provision a new token without user interaction after the current token expires.

These scenarios aren't specific to token-based authentication. They are part of the nature of apps. An app using cookies also fails to call a server API if the authentication cookie is revoked.

When an app performs API calls to protected resources, you must be aware of the following:

* To provision a new access token to call the API, the user might be required to authenticate again.
* Even if the client has a token that seems to be valid, the call to the server might fail because the token was revoked by the user.

When the app requests a token, there are two possible outcomes:

* The request succeeds, and the app has a valid token.
* The request fails, and the app must authenticate the user again to obtain a new token.

When the app somehow loses it's authentication state, but the browser retains the cookie, the user might be presented with a browser that pops up and immediately closes because of reauthentication.

## Customize app routes

By default, the [`Microsoft.MobileBlazorBindings.Authentication`](https://www.nuget.org/packages/Microsoft.MobileBlazorBindings.Authentication) library uses the routes shown in the following table for representing different authentication states.
It might be neccessary to change these Authentication paths based on the identity provider.

| Route                            | Purpose |
| -------------------------------- | ------- |
| `authentication/login-callback`  | Handles the result of any sign-in operation. |
| `authentication/logout-callback` | Handles the result of a sign-out operation. |
| `authentication/profile`         | The URL to open to edit the user profile. |
| `authentication/register`        | The URL to open to register a new user. |

The routes shown in the preceding table are configurable via <xref:Microsoft.MobileBlazorBindings.Authentication.RemoteAuthenticationOptions%601.AuthenticationPaths%2A?displayProperty=nameWithType>. 

The application constructor (`App.cs`):

```csharp
services.AddApiAuthorization(options => { 
    options.AuthenticationPaths.LogInCallbackPath = "security/login-callback";
    options.AuthenticationPaths.LogOutCallbackPath = "security/logout-callback";
    options.AuthenticationPaths.ProfilePath = "security/profile";
    options.AuthenticationPaths.RegisterPath = "security/register";
});
```

## Customize the user

Users bound to the app can be customized.

### Customize the user with a payload claim

In the following example, the app's authenticated users receive an `amr` claim for each of the user's authentication methods. The `amr` claim identifies how the subject of the token was authenticated in Microsoft Identity Platform v1.0 [payload claims](/azure/active-directory/develop/access-tokens#the-amr-claim). The example uses a custom user account class based on <xref:Microsoft.MobileBlazorBindings.Authentication.RemoteUserAccount>.

Create a class that extends the <xref:Microsoft.MobileBlazorBindings.Authentication.RemoteUserAccount> class. The following example sets the `AuthenticationMethod` property to the user's array of `amr` JSON property values. `AuthenticationMethod` is populated automatically by the framework when the user is authenticated.

```csharp
using System.Text.Json.Serialization;
using Microsoft.MobileBlazorBindings.Authentication;

public class CustomUserAccount : RemoteUserAccount
{
    [JsonPropertyName("amr")]
    public string[] AuthenticationMethod { get; set; }
}
```

Create a factory that extends <xref:Microsoft.MobileBlazorBindings.Authentication.AccountClaimsPrincipalFactory%601> to create claims from the user's authentication methods stored in `CustomUserAccount.AuthenticationMethod`:

```csharp
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.MobileBlazorBindings.Authentication;
using Microsoft.MobileBlazorBindings.Authentication.Internal;

public class CustomAccountFactory 
    : AccountClaimsPrincipalFactory<CustomUserAccount>
{
    public CustomAccountFactory(NavigationManager navigationManager, 
        IAccessTokenProviderAccessor accessor) : base(accessor)
    {
    }
  
    public async override ValueTask<ClaimsPrincipal> CreateUserAsync(
        CustomUserAccount account, RemoteAuthenticationUserOptions options)
    {
        var initialUser = await base.CreateUserAsync(account, options);

        if (initialUser.Identity.IsAuthenticated)
        {
            foreach (var value in account.AuthenticationMethod)
            {
                ((ClaimsIdentity)initialUser.Identity)
                    .AddClaim(new Claim("amr", value));
            }
        }

        return initialUser;
    }
}
```

Register the `CustomAccountFactory` for the authentication provider in use. Any of the following registrations are valid:

* <xref:Microsoft.Extensions.DependencyInjection.MobileBlazorBindingsAuthenticationServiceExtensions.AddOidcAuthentication%2A>:

  ```csharp
  using Microsoft.MobileBlazorBindings.Authentication;

  ...

  builder.Services.AddOidcAuthentication<RemoteAuthenticationState, 
      CustomUserAccount>(options =>
      {
          ...
      })
      .AddAccountClaimsPrincipalFactory<RemoteAuthenticationState, 
          CustomUserAccount, CustomAccountFactory>();
  ```

* <xref:Microsoft.Extensions.DependencyInjection.MsalAuthenticationServiceExtensions.AddMsalAuthentication%2A>:

  ```csharp
  using Microsoft.MobileBlazorBindings.Authentication;

  ...

  builder.Services.AddMsalAuthentication<RemoteAuthenticationState, 
      CustomUserAccount>(options =>
      {
          ...
      })
      .AddAccountClaimsPrincipalFactory<RemoteAuthenticationState, 
          CustomUserAccount, CustomAccountFactory>();
  ```
  
* <xref:Microsoft.Extensions.DependencyInjection.MobileBlazorBindingsAuthenticationServiceExtensions.AddApiAuthorization%2A>:

  ```csharp
  using Microsoft.MobileBlazorBindings.Authentication;

  ...

  builder.Services.AddApiAuthorization<RemoteAuthenticationState, 
      CustomUserAccount>(options =>
      {
          ...
      })
      .AddAccountClaimsPrincipalFactory<RemoteAuthenticationState, 
          CustomUserAccount, CustomAccountFactory>();
  ```

### AAD security groups and roles with a custom user account class

For an additional example that works with AAD security groups and AAD Administrator Roles and a custom user account class, see <xref:blazor/security/webassembly/aad-groups-roles>.

## Options for hosted apps and third-party login providers

When authenticating and authorizing a hosted Mobile Blazor Bindings app with a third-party provider, there are several options available for authenticating the user. Which one you choose depends on your scenario.

For more information, see <xref:security/authentication/social/additional-claims>.

### Authenticate users to only call protected third party APIs

Authenticate the user with a client-side OAuth flow against the third-party API provider:

 ```csharp
 builder.services.AddOidcAuthentication(options => { ... });
 ```
 
 In this scenario:

* The server hosting the app doesn't play a role.
* APIs on the server can't be protected.
* The app can only call protected third-party APIs.

### Authenticate users with a third-party provider and call protected APIs on the host server and the third party

Configure Identity with a third-party login provider. Obtain the tokens required for third-party API access and store them.

When a user logs in, Identity collects access and refresh tokens as part of the authentication process. At that point, there are a couple of approaches available for making API calls to third-party APIs.

#### Use a server access token to retrieve the third-party access token

Use the access token generated on the server to retrieve the third-party access token from a server API endpoint. From there, use the third-party access token to call third-party API resources directly from Identity on the client.

We don't recommend this approach. This approach requires treating the third-party access token as if it were generated for a public client. In OAuth terms, the public app doesn't have a client secret because it can't be trusted to store secrets safely, and the access token is produced for a confidential client. A confidential client is a client that has a client secret and is assumed to be able to safely store secrets.

* The third-party access token might be granted additional scopes to perform sensitive operations based on the fact that the third-party emitted the token for a more trusted client.
* Similarly, refresh tokens shouldn't be issued to a client that isn't trusted, as doing so gives the client unlimited access unless other restrictions are put into place.

#### Make API calls from the client to the server API in order to call third-party APIs

Make an API call from the client to the server API. From the server, retrieve the access token for the third-party API resource and issue whatever call is necessary.

While this approach requires an extra network hop through the server to call a third-party API, it ultimately results in a safer experience:

* The server can store refresh tokens and ensure that the app doesn't lose access to third-party resources.
* The app can't leak access tokens from the server that might contain more sensitive permissions.

## Use OpenID Connect (OIDC) v2.0 endpoints

The authentication library and Blazor project templates use OpenID Connect (OIDC) v1.0 endpoints. To use a v2.0 endpoint, configure the JWT Bearer <xref:Microsoft.AspNetCore.Builder.JwtBearerOptions.Authority?displayProperty=nameWithType> option. In the following example, AAD is configured for v2.0 by appending a `v2.0` segment to the <xref:Microsoft.AspNetCore.Builder.JwtBearerOptions.Authority> property:

```csharp
services.Configure<JwtBearerOptions>(
    AzureADDefaults.JwtBearerAuthenticationScheme, 
    options =>
    {
        options.Authority += "/v2.0";
    });
```

Alternatively, the setting can be made in the app settings (`appsettings.json`) file:

```json
{
  "Local": {
    "Authority": "https://login.microsoftonline.com/common/oauth2/v2.0/",
    ...
  }
}
```

If tacking on a segment to the authority isn't appropriate for the app's OIDC provider, such as with non-AAD providers, set the <xref:Microsoft.AspNetCore.Builder.OpenIdConnectOptions.Authority> property directly. Either set the property in <xref:Microsoft.AspNetCore.Builder.JwtBearerOptions> or in the app settings file (`appsettings.json`) with the `Authority` key.

The list of claims in the ID token changes for v2.0 endpoints. For more information, see [Why update to Microsoft identity platform (v2.0)?](/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison).

## Configure and use gRPC in components

To configure a Mobile Blazor Bindings app to use the [ASP.NET Core gRPC framework](xref:grpc/index):

* Enable gRPC-Web on the server. For more information, see <xref:grpc/browser>.
* Register gRPC services for the app's message handler. The following example configures the app's authorization message handler to use the [`GreeterClient` service from the gRPC tutorial](xref:tutorials/grpc/grpc-start#create-a-grpc-service) (`Program.Main`):

```csharp
using System.Net.Http;
using Microsoft.MobileBlazorBindings.Authentication;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;
using {APP ASSEMBLY}.Shared;

...

services.AddScoped(sp =>
{
    var apiAddressMessageHandler = 
        sp.GetRequiredService<ApiAddressAuthorizationMessageHandler>();
    apiAddressMessageHandler.InnerHandler = new HttpClientHandler();
    var grpcWebHandler = 
        new GrpcWebHandler(GrpcWebMode.GrpcWeb, apiAddressMessageHandler);
    var channel = GrpcChannel.ForAddress(BaseAddress, 
        new GrpcChannelOptions { HttpHandler = grpcWebHandler });

    return new Greeter.GreeterClient(channel);
});
```

The placeholder `{APP ASSEMBLY}` is the app's assembly name (for example, `BlazorSample`). Place the `.proto` file in the `Shared` project of the hosted Blazor solution.

A component in the client app can make gRPC calls using the gRPC client (`Pages/Grpc.razor`):

```razor
@page "/grpc"
@attribute [Authorize]
@using Microsoft.AspNetCore.Authorization
@using {APP ASSEMBLY}.Shared
@inject Greeter.GreeterClient GreeterClient

<h1>Invoke gRPC service</h1>

<p>
    <input @bind="name" placeholder="Type your name" />
    <button @onclick="GetGreeting" class="btn btn-primary">Call gRPC service</button>
</p>

Server response: <strong>@serverResponse</strong>

@code {
    private string name = "Bert";
    private string serverResponse;

    private async Task GetGreeting()
    {
        try
        {
            var request = new HelloRequest { Name = name };
            var reply = await GreeterClient.SayHelloAsync(request);
            serverResponse = reply.Message;
        }
        catch (Grpc.Core.RpcException ex)
            when (ex.Status.DebugException is 
                AccessTokenNotAvailableException tokenEx)
        {
            tokenEx.RequestPermission();
        }
    }
}
```

The placeholder `{APP ASSEMBLY}` is the app's assembly name (for example, `BlazorSample`). To use the `Status.DebugException` property, use [Grpc.Net.Client](https://www.nuget.org/packages/Grpc.Net.Client) version 2.30.0 or later.

For more information, see <xref:grpc/browser>.

## Additional resources

* <xref:mobile-blazor-bindings/authentication/graph-api>

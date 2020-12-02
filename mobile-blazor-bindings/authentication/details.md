---
title: Securing a Mobile Blazor Bindings App
---
# Securing a Mobile Blazor Bindings App

By [Javier Calvarro Nelson](https://github.com/javiercn), [Jan-Willem Spuij](https://github.com/jspuij)

Mobile Blazor Bindings apps are secured in the same manner as Native apps. There are several approaches for authenticating users to Native apps, but the most common and comprehensive approach is to use an implementation based on the [OAuth 2.0 protocol](https://oauth.net/), such as [OpenID Connect (OIDC)](https://openid.net/connect/).

## Authentication library

Mobile Blazor Bindings supports authenticating and authorizing apps using OIDC via the [`Microsoft.MobileBlazorBindings.Authentication`](https://www.nuget.org/packages/Microsoft.MobileBlazorBindings.Authentication) library. The library provides a set of primitives for seamlessly authenticating against ASP.NET Core backends. The library integrates ASP.NET Core Identity with API authorization support built on top of [Identity Server](https://identityserver.io/). The library can authenticate against any third-party Identity Provider (IP) that supports OIDC, which are called OpenID Providers (OP).

The authentication support in Mobile Blazor Bindings is built on top of the [`IdentityModel.OidcClient`](https://github.com/IdentityModel/IdentityModel.OidcClient) library, which is used to handle the underlying authentication protocol details.

The library can secure Mobile Blazor Bindings apps that use Xamarin.Forms (Native) controls, as well as Mobile Blazor Bindings Hybrid app. Routing, and securing with the Authorize attribute is only supported in Hybrid apps.

## Authentication process with OIDC

The [`Microsoft.MobileBlazorBindings.Authentication`](https://www.nuget.org/packages/Microsoft.MobileBlazorBindings.Authentication) library offers several primitives to implement authentication and authorization using OIDC. In broad terms, authentication works as follows:

  * When an anonymous user selects the login button or requests a page with the [`[Authorize]`](xref:Microsoft.AspNetCore.Authorization.AuthorizeAttribute) attribute applied, the authentication process is started.
  * The authentication library will lauch a Browser Window (Windows, macOS) or a secure Webview (iOS, Android) to connect to the authorization endpoint of the OIDC provider. The user can verify the URL and certificate to make sure that they connect with the correct provider. The endpoint is responsible for determining whether the user is authenticated and for issuing an authentication code. The authentication library provides a login callback to receive the authentication code response.
  * If the user isn't authenticated, the user is redirected to the underlying authentication system, which is usually ASP.NET Core Identity.
  * If the user was already authenticated, the authorization endpoint generates the appropriate authentication code and redirects the browser back to the login callback endpoint (this endpoint is platform specific).
  * The Mobile Blazor Bindings app listens for the request it will receive on the login callback endpoint, as soon as it receives the authentication response, it is processed.
  * If an authentication code is received, this is exchanged for a set of tokens (access, id and refresh) and the authentication process completes successfully. Subsequently all components listening to a change in Authentication State will refresh.

This process is called the Autorization Code Flow with PKCE. It is important to use this flow as it is the only secure flow within OIDC and OAuth that can be used by something called a Public Client. A Public Client is an application that cannot protect its authentication flow with a Client Secret, because its code or distribution can be inspected for keys.

## `IAuthenticationService` interface

The `IAuthenticationService` interface can be injected into components and handles remote authentication operations and permits the app to:

* Perform a sign-in operation with the ODIC provider.
* Ask for consent for additional scopes.
* Perform a sign-out operation with the ODIC provider.
* Initiate registration a new user.
* Manage a users profile.

Authentication actions, such as registering or signing in a user, are passed to the Mobile Blazor Bindings' <xref:Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider>, which will handle the actual operations.

For more information and examples, see <xref:mobile-blazor-bindings/authentication/additional-scenarios>.

## Authorization

In Mobile Blazor Bindings apps, authorization checks can be bypassed because all client-side code can be modified by users. The same is true for all client-side app technologies, including JavaScript SPA frameworks or native apps for any operating system.

**Always perform authorization checks on the server within any API endpoints accessed by your client-side app.**

## Require authorization for the entire app

> [!NOTE]
> This section only applies to Mobile Blazor Bindings Hybrid Applications, as Native applications currently have no router nor navigation.

Apply the [`[Authorize]` attribute](xref:blazor/security/index#authorize-attribute) ([API documentation](xref:System.Web.Mvc.AuthorizeAttribute)) to each Razor component of the app using one of the following approaches:

* Use the [`@attribute`](xref:mvc/views/razor#attribute) directive in the `_Imports.razor` file:

  ```razor
  @using Microsoft.AspNetCore.Authorization
  @attribute [Authorize]
  ```

* Add the attribute to each Razor component in the `Pages` folder.

> [!NOTE]
> Setting an <xref:Microsoft.AspNetCore.Authorization.AuthorizationOptions.FallbackPolicy?displayProperty=nameWithType> to a policy with <xref:Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder.RequireAuthenticatedUser%2A> is **not** supported.

## Refresh tokens

Mobile Blazor Bindings provides protected storage for the storage of refresh tokens. The refresh tokens are neccessary to allow the app to reauthenticate without going through the Browser or Webview to sign in. This would create a visual disturbance by quickly showing the browser and closing it again as soon as the cookie is used to reauthenticate.

Without refresh tokens the app will not reauthenticate when restarted. The associated scope that you should request is called `offline_access`. 

## Establish claims for users

Apps often require claims for users based on a web API call to a server. For example, claims are frequently used to [establish authorization](xref:mobile-blazor-bindings/authentication/overview#authorization) in an app. In these scenarios, the app requests an access token to access the service and uses the token to obtain the user data for the claims. For examples, see the following resources:

* [Additional scenarios: Customize the user](xref:mobile-blazor-bindings/authentication/additional-scenarios#customize-the-user)
* <xref:mobile-blazor-bindings/authentication/aad-groups-roles>

## Implementation guidance

Articles under this *Overview* provide information on authenticating users in Mobile Blazor Bindings apps against specific providers.

Standalone Mobile Blazor Bindings apps:

* [General guidance for OIDC providers and the WebAssembly Authentication Library](xref:mobile-blazor-bindings/authentication/authentication-library)
* [Microsoft Accounts](xref:mobile-blazor-bindings/authentication/microsoft-accounts)
* [Azure Active Directory (AAD)](xref:mobile-blazor-bindings/azure-active-directory)
* [Azure Active Directory (AAD) B2C](xref:mobile-blazor-bindings/azure-active-directory-b2c)
* [Identity Server](xref:blazor/security/webassembly/identity-server)

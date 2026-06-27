<?php

namespace Grocy\Middleware;

use Grocy\Services\SessionService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Routing\RouteContext;

/**
 * Base authentication middleware for Grocy.
 *
 * The concrete authentication strategy is determined by the `AUTH_CLASS`
 * container setting (set in `data/config.php`). Available implementations:
 *
 * - \Grocy\Middleware\DefaultAuthMiddleware  – built-in username/password (default)
 * - \Grocy\Middleware\ApiKeyAuthMiddleware   – API key via header
 * - \Grocy\Middleware\SessionAuthMiddleware  – session-cookie based (alias of Default)
 * - \Grocy\Middleware\LdapAuthMiddleware     – LDAP / Active Directory bind
 * - \Grocy\Middleware\ReverseProxyAuthMiddleware – trust a reverse-proxy header
 *
 * ## Bypass flags (all disable real authentication)
 *
 * | Constant / env var          | Effect |
 * |-----------------------------|--------|
 * | `GROCY_MODE`                | Authentication is bypassed when set to `dev`, `demo`, or `prerelease`. |
 * | `GROCY_IS_EMBEDDED_INSTALL` | When truthy, authentication is bypassed. |
 * | `GROCY_DISABLE_AUTH`        | When truthy, authentication is bypassed. |
 *                              | ⚠️  **WARNING:** Setting `GROCY_DISABLE_AUTH` exposes the entire instance
 *                              |    without any access control. Only use in isolated, trusted networks. |
 *
 * ## ApiKeyAuthMiddleware configuration
 *
 * The API key header name defaults to `GROCY-API-KEY`. Override it by setting
 * the `ApiKeyHeaderName` key in the DI container configuration:
 *
 *     $container->set('ApiKeyHeaderName', 'X-Custom-Key');
 *
 * The API key itself is the user's API key stored in the `users` table
 * (`api_key` column) and must be sent in the request header.
 *
 * ## LdapAuthMiddleware configuration
 *
 * Required constants / environment variables:
 *
 * | Constant                  | Example                                  | Description                         |
 * |---------------------------|------------------------------------------|-------------------------------------|
 * | `GROCY_LDAP_ADDRESS`      | `ldap://ldap.example.com:389`            | LDAP server URI                     |
 * | `GROCY_LDAP_BASE_DN`      | `dc=example,dc=com`                      | Base DN for user lookups            |
 * | `GROCY_LDAP_BIND_DN`      | `cn=readonly,dc=example,dc=com`          | DN used for the initial bind        |
 * | `GROCY_LDAP_BIND_PW`      | `s3cret`                                 | Password for the bind DN            |
 * | `GROCY_LDAP_UID_ATTR`     | `uid` (or `sAMAccountName` for AD)       | Attribute that matches the username |
 * | `GROCY_LDAP_USER_FILTER`  | `(&(objectClass=person)(uid=%s))`        | LDAP search filter; `%s` is replaced with the username |
 * | `GROCY_LDAP_IGNORE_CERT`  | `false`                                  | Set to `true` to skip TLS certificate verification (not recommended for production) |
 *
 * If a user does not yet exist locally, it is auto-created on first successful
 * LDAP login (same behaviour as `DefaultAuthMiddleware` auto-creation).
 *
 * ## ReverseProxyAuthMiddleware configuration
 *
 * Required constants / environment variables:
 *
 * | Constant                          | Example            | Description                           |
 * |-----------------------------------|--------------------|---------------------------------------|
 * | `GROCY_REVERSE_PROXY_AUTH_USE_ENV`| `true`             | Must be truthy to enable this mode    |
 * | `GROCY_REVERSE_PROXY_AUTH_HEADER` | `REMOTE_USER`      | Server variable or header that contains the authenticated username |
 *
 * Ensure that your reverse-proxy strips or overwrites the header from
 * external requests so that clients cannot spoof identities.
 *
 * @see \Grocy\Middleware\DefaultAuthMiddleware
 * @see \Grocy\Middleware\ApiKeyAuthMiddleware
 * @see \Grocy\Middleware\LdapAuthMiddleware
 * @see \Grocy\Middleware\ReverseProxyAuthMiddleware
 */
abstract class AuthMiddleware extends BaseMiddleware
{
	public function __invoke(Request $request, RequestHandler $handler): Response
	{
		$routeContext = RouteContext::fromRequest($request);
		$route = $routeContext->getRoute();
		$routeName = $route->getName();
		$isApiRoute = string_starts_with($request->getUri()->getPath(), '/api/');

		if ($routeName === 'root')
		{
			return $handler->handle($request);
		}
		elseif ($routeName === 'login')
		{
			define('GROCY_AUTHENTICATED', false);
			return $handler->handle($request);
		}

		if (GROCY_MODE === 'dev' || GROCY_MODE === 'demo' || GROCY_MODE === 'prerelease' || GROCY_IS_EMBEDDED_INSTALL || GROCY_DISABLE_AUTH)
		{
			$sessionService = SessionService::GetInstance();
			$user = $sessionService->GetDefaultUser();

			define('GROCY_AUTHENTICATED', true);
			define('GROCY_USER_USERNAME', $user->username);
			define('GROCY_USER_PICTURE_FILE_NAME', $user->picture_file_name);

			return $handler->handle($request);
		}
		else
		{
			$user = $this->authenticate($request);

			if ($user === null)
			{
				define('GROCY_AUTHENTICATED', false);

				$response = $this->ResponseFactory->createResponse();

				if ($isApiRoute)
				{
					return $response->withStatus(401);
				}
				else
				{
					return $response->withStatus(302)->withHeader('Location', $this->AppContainer->get('UrlManager')->ConstructUrl('/login'));
				}
			}
			else
			{
				define('GROCY_AUTHENTICATED', true);
				define('GROCY_USER_ID', $user->id);
				define('GROCY_USER_USERNAME', $user->username);
				define('GROCY_USER_PICTURE_FILE_NAME', $user->picture_file_name);

				return $response = $handler->handle($request);
			}
		}
	}

	protected static function SetSessionCookie($sessionKey)
	{
		// Cookie never expires, session validity is up to SessionService
		setcookie(SessionService::SESSION_COOKIE_NAME, $sessionKey, PHP_INT_SIZE == 4 ? PHP_INT_MAX : PHP_INT_MAX >> 32);
	}

	/**
	 * @param array $postParams
	 * @return bool True/False if the provided credentials were valid
	 * @throws \Exception Throws an \Exception if an error happened during credentials processing or if this AuthMiddleware doesn't provide credentials processing (e. g. handles this externally)
	 */
	abstract public static function ProcessLogin(array $postParams);

	/**
	 * @param Request $request
	 * @return mixed|null the user row or null if the request is not authenticated
	 * @throws \Exception Throws an \Exception if config is invalid.
	 */
	abstract protected function authenticate(Request $request);
}

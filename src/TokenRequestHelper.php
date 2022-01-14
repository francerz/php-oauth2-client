<?php

namespace Francerz\OAuth2\Client;

use Exception;
use Fig\Http\Message\RequestMethodInterface;
use Francerz\Http\Utils\Constants\MediaTypes;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\GrantTypesEnum;
use Francerz\OAuth2\OAuth2Error;
use Francerz\OAuth2\OAuth2ErrorException;
use Francerz\OAuth2\ScopeHelper;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * @internal
 */
abstract class TokenRequestHelper
{
    private static function embedClientCredentials(OAuth2Client $client, RequestInterface $request)
    {
        return $request
            ->withHeader('Authorization', base64_encode("{$client->getClientId()}:{$client->getClientSecret()}"));
    }

    private static function createTokenRequest(OAuth2Client $client, array $params)
    {
        $requestFactory = $client->getRequestFactory();
        if (is_null($requestFactory)) {
            throw new Exception('Missing RequestFactory in OAuth2Client.');
        }
        $request = $requestFactory
            ->createRequest(RequestMethodInterface::METHOD_POST, $client->getTokenEndpoint())
            ->withHeader('Content-Type', MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED);
        $request->getBody()->write(http_build_query($params));
        return $request;
    }

    /**
     * Retrieves an Access Token from given Response. If error is returned,
     * OAuth2ErrorException is thrown.
     *
     * @param ResponseInterface $response
     * @return Accesstoken
     *
     * @throws OAuth2ErrorException
     */
    public static function getAccessTokenFromResponse(ResponseInterface $response)
    {
        $error = OAuth2Error::fromResponse($response);
        if (!is_null($error)) {
            throw new OAuth2ErrorException($error, $error->getErrorDescription());
        }
        return AccessToken::fromMessage($response);
    }

    /**
     * @param OAuth2Client $client
     * @param string $code
     * @param string|null $verifier Used in PKCE.
     * @return RequestInterface
     */
    public static function createFetchAccessTokenWithCodeRequest(
        OAuth2Client $client,
        string $code
    ) {
        $params = [
            'grant_type' => GrantTypesEnum::AUTHORIZATION_CODE,
            'code' => $code
        ];
        $callbackEndpoint = $client->getCallbackEndpoint();
        if (!is_null($callbackEndpoint)) {
            $params['redirect_uri'] = (string)$callbackEndpoint;
        }
        $pkceManager = $client->getPKCEManager();
        if (isset($pkceManager)) {
            $pkceCode = $pkceManager->getPKCECode();
            if (!is_null($pkceCode)) {
                $params['code_verifier'] = $pkceCode->getCode();
            }
        }
        $request = static::createTokenRequest($client, $params);
        $request = static::embedClientCredentials($client, $request);
        return $request;
    }

    /**
     * @param OAuth2Client $client
     * @param string $username
     * @param string|null $password
     * @param string[]|string|null $scope
     * @return RequestInterface
     */
    public static function createFetchAccesstokenWithPasswordRequest(
        OAuth2Client $client,
        string $username,
        string $password,
        $scope = []
    ) {
        $params = [
            'grant_type' => GrantTypesEnum::PASSWORD,
            'username' => $username,
            'password' => $password
        ];
        if (!empty($scope)) {
            $params['scope'] = ScopeHelper::toString($scope);
        }
        $request = static::createTokenRequest($client, $params);
        $request = static::embedClientCredentials($client, $request);
        return $request;
    }

    /**
     * @param OAuth2Client $client
     * @param string[]|string|null $scope
     * @return RequestInterface
     */
    public static function createFetchAccessTokenWithClientCredentialsRequest(OAuth2Client $client, $scope = [])
    {
        $params = [
            'grant_type' => GrantTypesEnum::CLIENT_CREDENTIALS
        ];
        if (!empty($scope)) {
            $params['scope'] = ScopeHelper::toString($scope);
        }

        $request = static::createTokenRequest($client, $params);
        $request = static::embedClientCredentials($client, $request);
        return $request;
    }

    /**
     * @param OAuth2Client $client
     * @param RefreshToken|string $refreshToken
     * @param string[]|string|null $scope
     * @return RequestInterface
     */
    public static function createFetchAccessTokenWithRefreshTokenRequest(
        OAuth2Client $client,
        $refreshToken,
        $scope = []
    ) {
        $params = [
            'grant_type' => GrantTypesEnum::REFRESH_TOKEN,
            'refresh_token' => (string)$refreshToken,
        ];
        if (!empty($scope)) {
            $params['scope'] = ScopeHelper::toString($scope);
        }
        $request = static::createTokenRequest($client, $params);
        $request = static::embedClientCredentials($client, $request);
        return $request;
    }
}

<?php

namespace Francerz\OAuth2\Client;

use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\CodeChallengeMethodsEnum;
use Francerz\OAuth2\PKCEHelper;
use Francerz\OAuth2\ResponseTypesEnum;
use Francerz\OAuth2\ScopeHelper;
use Psr\Http\Message\UriInterface;

class AuthorizeRequestHelper
{
    /**
     * @param ClientParameters $client
     * @param ResponseTypesEnum|string $responseType
     * @param string[]|string $scopes
     * @param string|null $state
     * @return UriInterface
     */
    public static function createUri(ClientParameters $client, $responseType, $scopes = [], $state = null): UriInterface
    {
        $params = [
            'response_type' => $responseType,
            'client_id' => $client->getClientId()
        ];
        if (!empty($client->getCallbackEndpoint())) {
            $params['redirect_uri'] = $client->getCallbackEndpoint();
        }
        if (!empty($scopes)) {
            $params['scope'] = ScopeHelper::toString($scopes);
        }
        if (!empty($state)) {
            $params['state'] = $state;
        }
        return UriHelper::withQueryParams($client->getAuthorizationEndpoint(), $params);
    }

    public static function createCodeUri(ClientParameters $client, $scopes = [], $state = null): UriInterface
    {
        return static::createUri($client, ResponseTypesEnum::AUTHORIZATION_CODE, $scopes, $state);
    }

    /**
     * @param ClientParameters $client
     * @param PKCECode $pkceCode
     * @param string[]|string $scopes
     * @param string|null $state
     * @return UriInterface
     */
    public static function createCodeWithPKCEUri(
        ClientParameters $client,
        PKCECode $pkceCode,
        $scopes = [],
        $state = null
    ): UriInterface {
        $uri = static::createCodeUri($client, $scopes, $state);
        $pkceMethod = $pkceCode->getMethod();
        $params = ['code_challenge' => PKCEHelper::urlEncode($pkceCode->getCode(), $pkceMethod)];
        if ($pkceMethod != CodeChallengeMethodsEnum::PLAIN) {
            $params['code_challenge_method'] = (string)$pkceMethod;
        }
        return UriHelper::withQueryParams($uri, $params);
    }

    public static function createTokenUri(ClientParameters $client, $scopes = [], $state = null): UriInterface
    {
        return static::createUri($client, ResponseTypesEnum::TOKEN, $scopes, $state);
    }
}

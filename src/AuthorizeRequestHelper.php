<?php

namespace Francerz\OAuth2\Client;

use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\CodeChallengeMethodsEnum;
use Francerz\OAuth2\PKCEHelper;
use Francerz\OAuth2\ResponseTypesEnum;
use Francerz\OAuth2\ScopeHelper;
use Psr\Http\Message\UriInterface;

/**
 * @internal
 */
class AuthorizeRequestHelper
{
    /**
     * @param OAuth2Client $client
     * @param ResponseTypesEnum|string $responseType
     * @param string[]|string $scopes
     * @param string|null $state
     * @return UriInterface
     */
    public static function createUri(OAuth2Client $client, $responseType, $scopes = []): UriInterface
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
        $stateManager = $client->getStateManager();
        if (isset($stateManager)) {
            $params['state'] = $stateManager->generateState();
        }
        return UriHelper::withQueryParams($client->getAuthorizationEndpoint(), $params);
    }

    public static function createCodeUri(OAuth2Client $client, $scopes = []): UriInterface
    {
        $uri = static::createUri($client, ResponseTypesEnum::AUTHORIZATION_CODE, $scopes);

        $pkceManager = $client->getPKCEManager();
        if (isset($pkceManager)) {
            $params = [];
            $pkceCode = $pkceManager->generatePKCECode();
            $pkceMethod = $pkceCode->getMethod();
            $params['code_challenge'] = PKCEHelper::urlEncode($pkceCode->getCode(), $pkceMethod);
            if ($pkceMethod != CodeChallengeMethodsEnum::PLAIN) {
                $params['code_challenge_method'] = (string)$pkceMethod;
            }
            $uri = UriHelper::withQueryParams($uri, $params);
        }

        return $uri;
    }

    public static function createTokenUri(OAuth2Client $client, $scopes = []): UriInterface
    {
        return static::createUri($client, ResponseTypesEnum::TOKEN, $scopes);
    }
}

<?php

namespace Francerz\OAuth2\Client;

use Francerz\Http\Utils\Constants\MediaTypes;
use Francerz\Http\Utils\Constants\Methods;
use Francerz\Http\Utils\Headers\BasicAuthorizationHeader;
use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\HttpHelper;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\ScopeHelper;
use Francerz\OAuth2\TokenRequestGrantTypes;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use LogicException;
use Psr\Http\Client\ClientInterface as HttpClient;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use RuntimeException;

class AuthClient
{
    private $httpFactory;
    private $httpClient;
    private $httpHelper;

    private $clientId; // string
    private $clientSecret; // string
    private $authorizationEndpoint; // UriInterface
    private $tokenEndpoint; // UriInterface
    private $callbackEndpoint; // UriInterface

    private $checkStateHandler; // callback
    private $ownerAccessTokenChangedHandler; // callback
    private $clientAccessTokenChangedHandler; // callback

    private $ownerAccessToken;
    private $clientAccessToken;
    private $clientScopes = [];

    private $preferBodyAuthenticationFlag = false;

    public function __construct(
        HttpFactoryManager $httpFactory,
        HttpClient $httpClient,
        string $clientId = '',
        string $clientSecret = '',
        $tokenEndpoint = null,
        $authorizationEndpoint = null,
        $callbackEndpoint = null
    ) {
        $this->httpFactory = $httpFactory;
        $this->httpHelper = new HttpHelper($httpFactory);
        $this->httpClient = $httpClient;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        $this->setTokenEndpoint($tokenEndpoint);
        $this->setAuthorizationEndpoint($authorizationEndpoint);
        $this->setCallbackEndpoint($callbackEndpoint);
    }

    #region Accessors
    public function setClientId(string $clientId)
    {
        $this->clientId = $clientId;
    }

    public function getClientId() : string
    {
        return $this->clientId;
    }

    public function setClientSecret(string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }
    
    public function getClientSecret() : string
    {
        return $this->clientSecret;
    }

    public function setAuthorizationEndpoint($authorizationEndpoint)
    {
        if (is_string($authorizationEndpoint)) {
            $authorizationEndpoint = $this->httpFactory->getUriFactory()
                ->createUri($authorizationEndpoint);
        }
        if ($authorizationEndpoint instanceof UriInterface) {
            $this->authorizationEndpoint = $authorizationEndpoint;
        }
    }

    public function getAuthorizationEndpoint() : ?UriInterface
    {
        return $this->authorizationEndpoint;
    }

    public function setTokenEndpoint($tokenEndpoint)
    {
        if (is_string($tokenEndpoint)) {
            $tokenEndpoint = $this->httpFactory->getUriFactory()
                ->createUri($tokenEndpoint);
        }
        if ($tokenEndpoint instanceof UriInterface) {
            $this->tokenEndpoint = $tokenEndpoint;
        }
    }

    public function getTokenEndpoint() : ?UriInterface
    {
        return $this->tokenEndpoint;
    }

    public function setCallbackEndpoint($callbackEndpoint)
    {
        if (is_string($callbackEndpoint)) {
            $callbackEndpoint = $this->httpFactory->getUriFactory()
                ->createUri($callbackEndpoint);
        }
        if ($callbackEndpoint instanceof UriInterface) {
            $this->callbackEndpoint = $callbackEndpoint;
        }
    }

    public function getCallbackEndpoint() : ?UriInterface
    {
        return $this->callbackEndpoint;
    }

    /**
     * @deprecated v0.2.9 Use setOwnerAccessToken instead
     *
     * @param AccessToken $accessToken
     * @param boolean $fireCallback
     * @return void
     */
    public function setAccessToken(AccessToken $accessToken, bool $fireCallback = false)
    {
        $this->setOwnerAccessToken($accessToken, $fireCallback);
    }

    /**
     * @deprecated v0.2.9 Use getOwnerAccessToken instead
     *
     * @return AccessToken|null
     */
    public function getAccessToken() : ?AccessToken
    {
        return $this->getOwnerAccessToken();
    }

    public function setOwnerAccessToken(AccessToken $accessToken, bool $fireCallback = false)
    {
        $this->ownerAccessToken = $accessToken;
        if ($fireCallback && is_callable($this->ownerAccessTokenChangedHandler)) {
            call_user_func($this->ownerAccessTokenChangedHandler, $accessToken);
        }
    }

    public function getOwnerAccessToken() : ?AccessToken
    {
        return $this->ownerAccessToken;
    }


    public function setClientAccessToken(AccessToken $accessToken, bool $fireCallback = false)
    {
        $this->clientAccessToken = $accessToken;
        if ($fireCallback && is_callable($this->clientAccessTokenChangedHandler)) {
            call_user_func($this->clientAccessTokenChangedHandler, $accessToken);
        }
    }

    public function getClientAccessToken() : ?AccessToken
    {
        return $this->clientAccessToken;
    }

    public function preferBodyAuthentication(bool $prefer)
    {
        $this->preferBodyAuthenticationFlag = $prefer;
    }

    public function isBodyAuthenticationPreferred() : bool
    {
        return $this->preferBodyAuthenticationFlag;
    }

    public function getHttpFactory() : HttpFactoryManager
    {
        return $this->httpFactory;
    }

    public function getHttpHelper() : HttpHelper
    {
        return $this->httpHelper;
    }

    /**
     * Undocumented function
     *
     * @param callable $handler Signature (string $state) : bool
     * @return void
     */
    public function setCheckStateHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, ['string'], 'bool')) {
            throw new InvalidArgumentException('Funtion expected signature is: (string $state) : bool');
        }

        $this->checkStateHandler = $handler;
    }

    /**
     * @deprecated v0.2.9 Use setOwnerAccessTokenChangedHandler instead 
     *
     * @param callable $handler
     * @return void
     */
    public function setAccessTokenChangedHandler(callable $handler)
    {
        $this->setOwnerAccessTokenChangedHandler($handler);
    }

    public function setOwnerAccessTokenChangedHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AccessToken::class])) {
            throw new InvalidArgumentException('Function expected signature is: (AccessToken $accessToken) : void');
        }

        $this->ownerAccessTokenChangedHandler = $handler;
    }

    public function setClientAccessTokenChangedHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AccessToken::class])) {
            throw new InvalidArgumentException('Function expected signature is: (AccessToken $accessToken) : void');
        }
        $this->clientAccessTokenChangedHandler = $handler;
    }
    #endregion
    
    private function getAccessTokenFromResponse(ResponseInterface $response) : AccessToken
    {
        if (HttpHelper::isError($response)) {
            $resp = HttpHelper::getContent($response);
            throw new \Exception($resp->error.': '.PHP_EOL.$resp->error_description);
        }

        return AccessToken::fromHttpMessage($response);
    }

    private function embedRequestClientCredentials(RequestInterface $request) : RequestInterface
    {
        if ($this->preferBodyAuthenticationFlag) {
            $bodyParams = HttpHelper::getContent($request);
            $bodyParams['client_id'] = $this->getClientId();
            $bodyParams['client_secret'] = $this->getClientSecret();
            $request = $this->httpHelper->withContent($request, MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED, $bodyParams);
        } else {
            $request = $request->withHeader(
                'Authorization',
                (string)new BasicAuthorizationHeader(
                    $this->getClientId(),
                    $this->getClientSecret()
                )
            );
        }

        return $request;
    }

    public function getAuthorizationCodeRequestUri(array $scopes = [], string $state = '') : UriInterface
    {
        $authCodeReq = new AuthorizationCodeRequest($this);
        $authCodeReq = $authCodeReq
            ->withAddedScope($scopes)
            ->withState($state);
        return $authCodeReq->getRequestUri();
    }

    private function getFetchAccessTokenWithCodeRequest(RequestInterface $request) : RequestInterface
    {
        $params = UriHelper::getQueryParams($request->getUri());

        if (array_key_exists('error', $params)) {
            throw new \Exception("{$params['error']}:{$params['error_description']}");
        }

        if (array_key_exists('state', $params)) {
            if (isset($this->checkStateHandler) && 
                !call_user_func($this->checkStateHandler, $params['state'])
            ) {
                throw new \Exception('Failed state matching.');
            }
        }

        if (!array_key_exists('code', $params)) {
            throw new \Exception('Missing \'code\' parameter.');
        }

        $code = $params['code'];
        $redeemReq = new RedeemCodeRequestBuilder($this, $code);
        return $redeemReq->getRequest();
    }

    public function handleCallbackRequest(RequestInterface $request) : AccessToken
    {
        $fetchRequest = $this->getFetchAccessTokenWithCodeRequest($request);
        $fetchRequest = $this->embedRequestClientCredentials($fetchRequest);
        $response = $this->httpClient->sendRequest($fetchRequest);
        $accessToken = $this->getAccessTokenFromResponse($response);
        $this->setOwnerAccessToken($accessToken, true);
        return $accessToken;
    }

    private function getFetchAccessTokenRequest(array $bodyParams = []) : RequestInterface
    {
        $requestFactory = $this->httpFactory->getRequestFactory();
        $request = $requestFactory->createRequest(Methods::POST, $this->tokenEndpoint);

        $request = $this->httpHelper->withContent(
            $request,
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            $bodyParams
        );

        return $request;
    }

    private function getFetchClientAccessTokenRequest(array $scopes = []) : RequestInterface
    {
        return $this->getFetchAccessTokenRequest(array(
            'grant_type' => TokenRequestGrantTypes::CLIENT_CREDENTIALS,
            'scope' => ScopeHelper::toString($scopes)
        ));
    }

    public function fetchClientAccessToken(array $scopes = []) : AccessToken
    {
        $scopes = ScopeHelper::merge($this->clientScopes, $scopes);
        $fetchRequest = $this->getFetchClientAccessTokenRequest($scopes);
        $fetchRequest = $this->embedRequestClientCredentials($fetchRequest);
        $response = $this->httpClient->sendRequest($fetchRequest);
        $accessToken = $this->getAccessTokenFromResponse($response);
        $this->clientScopes = $accessToken->hasParameter('scope') ?
            ScopeHelper::toArray($accessToken->getParameter('scope')) :
            $scopes;
        $this->setClientAccessToken($accessToken, true);
        return $accessToken;
    }

    private function getFetchAccessTokenWithRefreshTokenRequest(string $refreshToken) : RequestInterface
    {
        return $this->getFetchAccessTokenRequest(array(
            'grant_type' => TokenRequestGrantTypes::REFRESH_TOKEN,
            'refresh_token' => $refreshToken
        ));
    }

    public function fetchAccessTokenWithRefreshToken(string $refreshToken) : AccessToken
    {
        $fetchRequest = $this->getFetchAccessTokenWithRefreshTokenRequest($refreshToken);
        $fetchRequest = $this->embedRequestClientCredentials($fetchRequest);
        $response = $this->httpClient->sendRequest($fetchRequest);
        $accessToken = $this->getAccessTokenFromResponse($response);
        if (is_null($accessToken->getRefreshToken())) {
            $accessToken->setRefreshToken($refreshToken);
        }
        $this->setOwnerAccessToken($accessToken, true);
        return $accessToken;
    }

    private function refreshAccessToken()
    {
        if (is_null($this->ownerAccessToken)) {
            throw new RuntimeException('Cannot refresh token without access_token.');
        }
        $refreshToken = $this->ownerAccessToken->getRefreshToken();
        if (is_null($refreshToken)) {
            throw new RuntimeException('No Refresh Token available.');
        }
        $this->fetchAccessTokenWithRefreshToken($refreshToken);
    }

    /**
     * @param RequestInterface $request
     * @return RequestInterface|null
     */
    public function bindAccessToken(RequestInterface $request) : ?RequestInterface
    {
        if (!isset($this->ownerAccessToken) || !$this->ownerAccessToken instanceof AccessToken) {
            throw new LogicException('No access token available');
        }
        if ($this->ownerAccessToken->isExpired()) {
            $this->refreshAccessToken();
        }
        return $request->withHeader('Authorization', (string)$this->ownerAccessToken);
    }

    /**
     * Binds Client AccessToken to RequestInterface object.
     *
     * @param RequestInterface $request
     * @return RequestInterface|null
     */
    public function bindClientAccessToken(RequestInterface $request, array $scopes = []) : ?RequestInterface
    {
        if (!isset($this->clientAccessToken) ||
            !$this->clientAccessToken instanceof AccessToken ||
            $this->clientAccessToken->isExpired()
        ) {
            $this->fetchClientAccessToken($scopes);
        }
        return $request->withHeader('Authorization', (string)$this->clientAccessToken);
    }
}
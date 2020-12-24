<?php

namespace Francerz\OAuth2\Client;

use Francerz\Http\Utils\Constants\MediaTypes;
use Francerz\Http\Utils\Constants\Methods;
use Francerz\Http\Utils\Headers\BasicAuthorizationHeader;
use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\MessageHelper;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
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

    private $clientId; // string
    private $clientSecret; // string
    private $authorizationEndpoint; // UriInterface
    private $tokenEndpoint; // UriInterface
    private $callbackEndpoint; // UriInterface

    private $checkStateHandler; // callback
    private $accessTokenChangedHandler; // callback
    private $clientAccessTokenChangedHandler; // callback

    private $accessToken;
    private $clientAccessToken;
    private $clientScopes;

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

    public function setAccessToken(AccessToken $accessToken, bool $fireCallback = false)
    {
        $this->accessToken = $accessToken;
        if ($fireCallback && is_callable($this->accessTokenChangedHandler)) {
            call_user_func($this->accessTokenChangedHandler, $accessToken);
        }
    }

    public function getAccessToken() : ?AccessToken
    {
        return $this->accessToken;
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

    public function setAccessTokenChangedHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AccessToken::class])) {
            throw new InvalidArgumentException('Function expected signature is: (AccessToken $accessToken) : void');
        }

        $this->accessTokenChangedHandler = $handler;
    }
    #endregion
    
    private function getAccessTokenFromResponse(ResponseInterface $response) : AccessToken
    {
        if (MessageHelper::isError($response)) {
            $resp = MessageHelper::getContent($response);
            throw new \Exception($resp->error.': '.PHP_EOL.$resp->error_description);
        }

        return AccessToken::fromHttpMessage($response);
    }

    private function embedRequestClientCredentials(RequestInterface $request) : RequestInterface
    {
        if ($this->preferBodyAuthenticationFlag) {
            $bodyParams = MessageHelper::getContent($request);
            $bodyParams['client_id'] = $this->getClientId();
            $bodyParams['client_secret'] = $this->getClientSecret();
            $request = MessageHelper::withContent($request, MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED, $bodyParams);
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
            $csh = $this->checkStateHandler;
            if (isset($csh) && !$csh($params['state'])) {
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
        $this->setAccessToken($accessToken, true);
        return $accessToken;
    }

    private function getFetchAccessTokenRequest(array $bodyParams = []) : RequestInterface
    {
        $requestFactory = $this->httpFactory->getRequestFactory();
        $request = $requestFactory->createRequest(Methods::POST, $this->tokenEndpoint);

        MessageHelper::setHttpFactoryManager($this->httpFactory);
        $request = MessageHelper::withContent(
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
            'scope' => join(' ', $scopes)
        ));
    }

    public function fetchClientAccessToken(array $scopes = []) : AccessToken
    {
        $scopes = array_unique(array_merge($this->clientScopes, $scopes));
        $fetchRequest = $this->getFetchClientAccessTokenRequest($scopes);
        $fetchRequest = $this->embedRequestClientCredentials($fetchRequest);
        $response = $this->httpClient->sendRequest($fetchRequest);
        $accessToken = $this->getAccessTokenFromResponse($response);
        if ($accessToken->hasParameter('scope')) {
            $this->clientScopes = explode(' ', $accessToken->getParameter('scope'));
        } else {
            $this->clientScopes = $scopes;
        }
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
        $this->setAccessToken($accessToken, true);
        return $accessToken;
    }

    private function refreshAccessToken()
    {
        if (is_null($this->accessToken)) {
            throw new RuntimeException('Cannot refresh token without access_token.');
        }
        $refreshToken = $this->accessToken->getRefreshToken();
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
        if (!isset($this->accessToken) || !$this->accessToken instanceof AccessToken) {
            throw new LogicException('No access token available');
        }
        if ($this->accessToken->isExpired()) {
            $this->refreshAccessToken();
        }
        return $request->withHeader('Authorization', (string)$this->accessToken);
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
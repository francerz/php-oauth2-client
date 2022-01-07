<?php

namespace Francerz\OAuth2\Client;

use Fig\Http\Message\RequestMethodInterface;
use Francerz\Http\Utils\Constants\MediaTypes;
use Francerz\Http\Utils\Headers\BasicAuthorizationHeader;
use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\HttpHelper;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Client\Exceptions\MissingAuthorizationCodeException;
use Francerz\OAuth2\Client\Exceptions\StateMismatchException;
use Francerz\OAuth2\Error;
use Francerz\OAuth2\GrantTypesEnum;
use Francerz\OAuth2\ResponseTypesEnum;
use Francerz\OAuth2\ScopeHelper;
use LogicException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use RuntimeException;

class AuthClient
{
    private $httpFactory;
    private $httpHelper;

    /** @var UriFactoryInterface */
    private $uriFactory;

    /** @var string|null */
    private $clientId;
    /** @var string|null */
    private $clientSecret;
    /** @var UriInterface|null */
    private $authorizationEndpoint;
    /** @var UriInterface|null */
    private $tokenEndpoint;
    /** @var UriInterface|null */
    private $callbackEndpoint;

    /** @var StateCheckerInterface|null */
    private $stateChecker;
    /** @var AccessTokenSaverInterface|null */
    private $ownerAccessTokenSaver;
    /** @var AccessTokenSaverInterface|null */
    private $clientAccessTokenSaver;

    /** @var AccessToken|null */
    private $ownerAccessToken;
    /** @var AccessToken|null */
    private $clientAccessToken;
    /** @var string[] */
    private $clientScopes = [];

    private $preferBodyAuthenticationFlag = false;

    public function __construct(
        HttpFactoryManager $httpFactory,
        ?string $clientId = null,
        ?string $clientSecret = null,
        $tokenEndpoint = null,
        $authorizationEndpoint = null,
        $callbackEndpoint = null
    ) {
        $this->httpFactory = $httpFactory;
        $this->httpHelper = new HttpHelper($httpFactory);
        $this->uriFactory = $httpFactory->getUriFactory();
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;

        $this->setTokenEndpoint($tokenEndpoint);
        $this->setAuthorizationEndpoint($authorizationEndpoint);
        $this->setCallbackEndpoint($callbackEndpoint);
    }

    #region Accessors
    public function setClientId(?string $clientId)
    {
        $this->clientId = $clientId;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function setClientSecret(?string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    /**
     * @param UriInterface|string $authorizationEndpoint
     */
    public function setAuthorizationEndpoint($authorizationEndpoint)
    {
        if (is_string($authorizationEndpoint)) {
            $authorizationEndpoint = $this->uriFactory->createUri($authorizationEndpoint);
        }
        if ($authorizationEndpoint instanceof UriInterface) {
            $this->authorizationEndpoint = $authorizationEndpoint;
        }
    }

    /**
     * @return UriInterface|null
     */
    public function getAuthorizationEndpoint(): ?UriInterface
    {
        return $this->authorizationEndpoint;
    }

    /**
     * @param UriInterface|string $tokenEndpoint
     */
    public function setTokenEndpoint($tokenEndpoint)
    {
        if (is_string($tokenEndpoint)) {
            $tokenEndpoint = $this->uriFactory->createUri($tokenEndpoint);
        }
        if ($tokenEndpoint instanceof UriInterface) {
            $this->tokenEndpoint = $tokenEndpoint;
        }
    }

    /**
     * @return UriInterface|null
     */
    public function getTokenEndpoint(): ?UriInterface
    {
        return $this->tokenEndpoint;
    }

    /**
     * @param UriInterface|string $callbackEndpoint
     */
    public function setCallbackEndpoint($callbackEndpoint)
    {
        if (is_string($callbackEndpoint)) {
            $callbackEndpoint = $this->uriFactory->createUri($callbackEndpoint);
        }
        if ($callbackEndpoint instanceof UriInterface) {
            $this->callbackEndpoint = $callbackEndpoint;
        }
    }

    /**
     * @return UriInterface|null
     */
    public function getCallbackEndpoint(): ?UriInterface
    {
        return $this->callbackEndpoint;
    }

    /**
     * Sets Resource Owner(user) Access Token.
     *
     * @param AccessToken $accessToken
     * @param boolean $fireCallback
     */
    public function setOwnerAccessToken(AccessToken $accessToken, bool $fireCallback = false)
    {
        $this->ownerAccessToken = $accessToken;
        if ($fireCallback && isset($this->ownerAccessTokenSaver)) {
            $this->ownerAccessTokenSaver->saveAccessToken($accessToken);
        }
    }

    /**
     * Retrieves Resource Owner(user) Access Token.
     *
     * @return AccessToken|null
     */
    public function getOwnerAccessToken(): ?AccessToken
    {
        return $this->ownerAccessToken;
    }

    /**
     * Sets Client(application) Access Token.
     *
     * @param AccessToken $accessToken
     * @param boolean $fireCallback
     */
    public function setClientAccessToken(AccessToken $accessToken, bool $fireCallback = false)
    {
        $this->clientAccessToken = $accessToken;
        if ($fireCallback && isset($this->clientAccessTokenSaver)) {
            $this->clientAccessTokenSaver->saveAccessToken($accessToken);
        }
    }

    /**
     * Retrieves Client(application) Access Token.
     *
     * @return AccessToken|null
     */
    public function getClientAccessToken(): ?AccessToken
    {
        return $this->clientAccessToken;
    }

    /**
     * @param boolean $prefer
     */
    public function preferBodyAuthentication(bool $prefer = true)
    {
        $this->preferBodyAuthenticationFlag = $prefer;
    }

    public function isBodyAuthenticationPreferred(): bool
    {
        return $this->preferBodyAuthenticationFlag;
    }

    public function getHttpFactory(): HttpFactoryManager
    {
        return $this->httpFactory;
    }

    public function getHttpHelper(): HttpHelper
    {
        return $this->httpHelper;
    }

    public function setStateChecker(?StateCheckerInterface $checker)
    {
        $this->stateChecker = $checker;
    }

    public function setOwnerAccessTokenSaver(?AccessTokenSaverInterface $saver)
    {
        $this->ownerAccessTokenSaver = $saver;
    }

    public function setClientAccessTokenSaver(?AccessTokenSaverInterface $saver)
    {
        $this->clientAccessTokenSaver = $saver;
    }
    #endregion

    private function getAccessTokenFromResponse(ResponseInterface $response): AccessToken
    {
        if (HttpHelper::isError($response)) {
            $error = Error::fromResponse($response);
            throw new \Exception("{$error->getError()}\n{$error->getErrorDescription()}");
        }
        return AccessToken::fromMessage($response);
    }

    private function embedRequestClientCredentials(RequestInterface $request): RequestInterface
    {
        if ($this->preferBodyAuthenticationFlag) {
            $bodyParams = HttpHelper::getContent($request);
            $bodyParams['client_id'] = $this->getClientId();
            $bodyParams['client_secret'] = $this->getClientSecret();
            return $this->httpHelper->withContent(
                $request,
                MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
                $bodyParams
            );
        }
        return $request->withHeader(
            'Authorization',
            (string)new BasicAuthorizationHeader($this->getClientId(), $this->getClientSecret())
        );
    }

    /**
     * @param ResponseTypesEnum|string $responseType
     * @param string[]|string $scopes
     * @param string|null $state
     * @return UriInterface
     */
    public function createAuthorizeRequestUri($responseType, $scopes = [], $state = null): UriInterface
    {
        $params = [
            'response_type' => $responseType,
            'client_id' => $this->clientId
        ];
        if (isset($this->callbackEndpoint)) {
            $params['redirect_uri'] = (string)$this->callbackEndpoint;
        }
        if (!empty($scopes)) {
            $params['scope'] = ScopeHelper::toString($scopes);
        }
        if (isset($state)) {
            $params['state'] = $state;
        }
        return UriHelper::withQueryParams($this->authorizationEndpoint, $params);
    }

    private function getFetchAccessTokenWithCodeRequest(ServerRequestInterface $request): RequestInterface
    {
        $params = UriHelper::getQueryParams($request->getUri());
        if (array_key_exists('error', $params)) {
            $error = Error::fromRequest($request);
            throw new \Exception("{$error->getError()}:{$error->getErrorDescription()}");
        }

        if (
            array_key_exists('state', $params) &&
            isset($this->stateChecker) &&
            !$this->stateChecker->checkState($params['state'])
        ) {
            throw new StateMismatchException();
        }

        if (!array_key_exists('code', $params)) {
            throw new MissingAuthorizationCodeException();
        }

        $code = $params['code'];
        $redeemReq = new RedeemCodeRequestBuilder($this, $code);
        return $redeemReq->getRequest();
    }

    public function handleCallbackRequest(RequestInterface $request): AccessToken
    {
        $fetchRequest = $this->getFetchAccessTokenWithCodeRequest($request);
        $fetchRequest = $this->embedRequestClientCredentials($fetchRequest);
        $response = $this->httpClient->sendRequest($fetchRequest);
        $accessToken = $this->getAccessTokenFromResponse($response);
        $this->setOwnerAccessToken($accessToken, true);
        return $accessToken;
    }

    private function getFetchAccessTokenRequest(array $bodyParams = []): RequestInterface
    {
        $requestFactory = $this->httpFactory->getRequestFactory();
        $request = $requestFactory->createRequest(RequestMethodInterface::METHOD_POST, $this->tokenEndpoint);

        $request = $this->httpHelper->withContent(
            $request,
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            $bodyParams
        );

        return $request;
    }

    private function getFetchClientAccessTokenRequest(array $scopes = []): RequestInterface
    {
        return $this->getFetchAccessTokenRequest(array(
            'grant_type' => GrantTypesEnum::CLIENT_CREDENTIALS,
            'scope' => ScopeHelper::toString($scopes)
        ));
    }

    public function fetchClientAccessToken(array $scopes = []): AccessToken
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

    private function getFetchAccessTokenWithRefreshTokenRequest(string $refreshToken): RequestInterface
    {
        return $this->getFetchAccessTokenRequest(array(
            'grant_type' => GrantTypesEnum::REFRESH_TOKEN,
            'refresh_token' => $refreshToken
        ));
    }

    public function fetchAccessTokenWithRefreshToken(string $refreshToken): AccessToken
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
    public function bindAccessToken(RequestInterface $request): ?RequestInterface
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
    public function bindClientAccessToken(RequestInterface $request, array $scopes = []): ?RequestInterface
    {
        if (
            !isset($this->clientAccessToken) ||
            !$this->clientAccessToken instanceof AccessToken ||
            $this->clientAccessToken->isExpired()
        ) {
            $this->fetchClientAccessToken($scopes);
        }
        return $request->withHeader('Authorization', (string)$this->clientAccessToken);
    }
}

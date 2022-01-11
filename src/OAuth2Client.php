<?php

namespace Francerz\OAuth2\Client;

use Exception;
use Francerz\OAuth2\AccessToken;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;

class OAuth2Client
{
    #region Atributes
    /** @var string */
    private $clientId;
    /** @var string|null */
    private $clientSecret;
    /** @var UriInterface|null */
    private $authorizationEndpoint;
    /** @var UriInterface|null */
    private $tokenEndpoint;
    /** @var UriInterface|null */
    private $callbackEndpoint;

    /** @var ClientInterface|null */
    private $httpClient;
    /** @var RequestFactoryInterface|null */
    private $requestFactory;
    /** @var UriFactoryInterface|null */
    private $uriFactory;

    /** @var bool */
    private $preferBodyAuthentication = false;

    /** @var StateManagerInterface|null */
    private $stateManager;
    /** @var PKCEManagerInterface|null */
    private $pkceManager;
    /** @var OwnerAccessTokenSaverInterface|null */
    private $ownerAcccessTokenSaver;
    /** @var ClientAccessTokenSaverInterface|null */
    private $clientAccessTokenSaver;

    /** @var AccessToken|null */
    private $ownerAccessToken;
    /** @var AccessToken|null */
    private $clientAccessToken;
    #endregion

    public function __construct(
        string $clientId,
        ?string $clientSecret = null,
        ?UriInterface $authorizationEndpoint = null,
        ?UriInterface $tokenEndpoint = null,
        ?UriInterface $callbackEndpoint = null
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->authorizationEndpoint = $authorizationEndpoint;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->callbackEndpoint = $callbackEndpoint;
    }

    #region ClientParameters
    public function setClientId(string $clientId)
    {
        $this->clientId = $clientId;
    }

    public function getClientId()
    {
        return $this->clientId;
    }

    public function setClientSecret(?string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    public function setAuthorizationEndpoint(?UriInterface $authorizationEndpoint)
    {
        $this->authorizationEndpoint = $authorizationEndpoint;
    }

    public function getAuthorizationEndpoint()
    {
        return $this->authorizationEndpoint;
    }

    public function setTokenEndpoint(?UriInterface $tokenEndpoint)
    {
        $this->tokenEndpoint = $tokenEndpoint;
    }

    public function getTokenEndpoint()
    {
        return $this->tokenEndpoint;
    }

    public function setCallbackEndpoint(?UriInterface $callbackEndpoint)
    {
        $this->callbackEndpoint = $callbackEndpoint;
    }

    public function getCallbackEndpoint()
    {
        return $this->callbackEndpoint;
    }

    public function preferBodyAuthentication(bool $prefer = true)
    {
        $this->preferBodyAuthentication = $prefer;
    }

    public function isBodyAuthenticationPreferred()
    {
        return $this->preferBodyAuthentication;
    }
    #endregion

    #region HTTP Utilities
    public function setHttpClient(ClientInterface $httpClient)
    {
        $this->httpClient = $httpClient;
    }

    public function getHttpClient()
    {
        return $this->httpClient;
    }

    public function setRequestFactory(RequestFactoryInterface $requestFactory)
    {
        $this->requestFactory = $requestFactory;
    }

    public function getRequestFactory()
    {
        return $this->requestFactory;
    }

    public function setUriFactory(UriFactoryInterface $uriFactory)
    {
        $this->uriFactory = $uriFactory;
    }

    public function getUriFactory()
    {
        return $this->uriFactory;
    }
    #endregion

    #region Decorators
    public function setStateManager(?StateManagerInterface $stateManager)
    {
        $this->stateManager = $stateManager;
    }

    public function getStateManager()
    {
        return $this->stateManager;
    }

    public function setPKCEManager(?PKCEManagerInterface $pkceManager)
    {
        $this->pkceManager = $pkceManager;
    }

    public function getPKCEManager()
    {
        return $this->pkceManager;
    }

    public function setOwnerAccessTokenSaver(?OwnerAccessTokenSaverInterface $saver)
    {
        $this->ownerAcccessTokenSaver = $saver;
    }

    public function getOwnerAccessTokenSaver()
    {
        return $this->ownerAcccessTokenSaver;
    }

    public function setClientAccessTokenSaver(?ClientAccessTokenSaverInterface $saver)
    {
        $this->clientAccessTokenSaver = $saver;
    }

    public function getClientAccessTokenSaver()
    {
        return $this->clientAccessTokenSaver;
    }
    #endregion

    #region Access Tokens
    public function setOwnerAccessToken(AccessToken $accessToken, $autosave = false)
    {
        $this->ownerAccessToken = $accessToken;
        if ($autosave && isset($this->ownerAcccessTokenSaver)) {
            $this->ownerAcccessTokenSaver->saveOwnerAccessToken($accessToken);
        }
    }

    public function getOwnerAccessToken(): ?AccessToken
    {
        if (!isset($this->ownerAccessToken) && isset($this->ownerAcccessTokenSaver)) {
            $this->ownerAccessToken = $this->ownerAcccessTokenSaver->loadOwnerAccessToken();
        }
        return $this->ownerAccessToken;
    }

    public function setClientAccessToken(AccessToken $accessToken, $autosave = false)
    {
        $this->clientAccessToken = $accessToken;
        if ($autosave && isset($this->clientAccessTokenSaver)) {
            $this->clientAccessToken = $this->clientAccessTokenSaver->loadClientAccessToken();
        }
    }

    public function getClientAccessToken(): ?AccessToken
    {
        if (!isset($this->clientAccessToken) && isset($this->clientAccessTokenSaver)) {
            $this->clientAccessToken = $this->clientAccessTokenSaver->loadClientAccessToken();
        }
        return $this->clientAccessToken;
    }
    #endregion

    #region Authorization Uri Creators
    public function createAuthorizationCodeUri($scopes = [])
    {
        $state = null;
        if (isset($this->stateManager)) {
            $state = $this->stateManager->generateState();
        }
        if (isset($this->pkceManager)) {
            return AuthorizeRequestHelper::createCodeWithPKCEUri(
                $this,
                $this->pkceManager->generateCode(),
                $scopes,
                $state
            );
        }
        return AuthorizeRequestHelper::createCodeUri($this, $scopes, $state);
    }

    public function createImplicitAuthorizationUri($scopes = [])
    {
        $state = null;
        if (isset($this->stateManager)) {
            $state = $this->stateManager->generateState();
        }
        return AuthorizeRequestHelper::createTokenUri($this, $scopes, $state);
    }
    #endregion

    #region Access Token fetchers
    public function fetchAccessTokenFromRequestCallback(ServerRequestInterface $request, $autosave = true)
    {
        $accessToken = CallbackEndpointHandler::handle($this, $request);
        if ($autosave) {
            $this->setOwnerAccessToken($accessToken, true);
        }
        return $accessToken;
    }

    public function handleCallback(ServerRequestInterface $request, $autosave = true)
    {
        return $this->fetchAccessTokenFromRequestCallback($request, $autosave);
    }

    /**
     * @param string $code
     * @param boolean $autosave
     * @return AccessToken
     *
     * @throws OAuth2ErrorException
     */
    public function fetchAccessTokenWithCode(string $code, $autosave = true)
    {
        $verifier = null;
        if (isset($this->pkceManager)) {
            $verifier = $this->pkceManager->getCode()->getCode();
        }
        $request = TokenRequestHelper::createFetchAccessTokenWithCodeRequest($this, $code, $verifier);
        $response = $this->getHttpClient()->sendRequest($request);
        $accessToken = TokenRequestHelper::getAccessTokenFromResponse($response);
        if ($autosave) {
            $this->setOwnerAccessToken($accessToken, true);
        }
        return $accessToken;
    }

    /**
     * @param string $username
     * @param string $password
     * @param string[]|string $scope
     * @param boolean $autosave
     * @return void
     */
    public function fetchAccessTokenWithPassword(string $username, string $password, $scope = [], $autosave = true)
    {
        $request = TokenRequestHelper::createFetchAccesstokenWithPasswordRequest($this, $username, $password, $scope);
        $response = $this->getHttpClient()->sendRequest($request);
        $accessToken = TokenRequestHelper::getAccessTokenFromResponse($response);
        if ($autosave) {
            $this->setOwnerAccessToken($accessToken, true);
        }
        return $accessToken;
    }

    public function fetchAccessTokenWithClientCredentials($scope = [], $autosave = true)
    {
        $request = TokenRequestHelper::createFetchAccessTokenWithClientCredentialsRequest($this, $scope);
        $response = $this->getHttpClient()->sendRequest($request);
        $accessToken = TokenRequestHelper::getAccessTokenFromResponse($response);
        if ($autosave) {
            $this->setClientAccessToken($accessToken, true);
        }
        return $accessToken;
    }

    public function fetchAccessTokenWithRefreshToken(string $refreshToken, $scope = [], $autosave = true)
    {
        $request = TokenRequestHelper::createFetchAccessTokenWithRefreshTokenRequest($this, $refreshToken, $scope);
        $response = $this->getHttpClient()->sendRequest($request);
        $accessToken = TokenRequestHelper::getAccessTokenFromResponse($response);
        if (is_null($accessToken->getRefreshToken())) {
            $accessToken->setRefreshToken($refreshToken);
        }
        if ($autosave) {
            $this->setOwnerAccessToken($accessToken, true);
        }
        return $accessToken;
    }
    #endregion

    #region Access Token binders
    private function refreshAccessToken(AccessToken $accessToken)
    {
        $refreshToken = $accessToken->getRefreshToken();
        if (is_null($refreshToken)) {
            throw new Exception("No Refresh Token available.");
        }
        return $this->fetchAccessTokenWithRefreshToken($refreshToken);
    }

    public function bindOwnerAccessToken(RequestInterface $request): RequestInterface
    {
        $accessToken = $this->getOwnerAccessToken();
        if (!isset($accessToken)) {
            throw new Exception("Missing Owner Access Token");
        }
        if ($accessToken->isExpired()) {
            $accessToken = $this->refreshAccessToken($accessToken);
        }
        return $request->withHeader('Authorization', (string)$accessToken);
    }

    public function bindClientAccessToken(RequestInterface $request): RequestInterface
    {
        $accessToken = $this->getClientAccessToken();
        if (!isset($accessToken) || $accessToken->isExpired()) {
            $accessToken = $this->fetchAccessTokenWithClientCredentials();
        }
        return $request->withHeader('Authorization', (string)$accessToken);
    }
    #endregion
}

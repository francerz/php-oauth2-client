<?php

namespace Francerz\OAuth2\Client;

use Exception;
use Francerz\OAuth2\AccessToken;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

class OAuth2Client
{
    #region Atributes
    /** @var ClientParametersInterface */
    private $client;

    /** @var ClientInterface|null */
    private $httpClient;
    /** @var RequestFactoryInterface|null */
    private $requestFactory;

    /** @var bool */
    private $preferBodyAuthentication = false;

    /** @var ClientAccessTokenSaverInterface|null */
    private $clientAccessTokenSaver;
    /** @var OwnerAccessTokenSaverInterface|null */
    private $ownerAcccessTokenSaver;
    /** @var StateManagerInterface|null */
    private $stateManager;
    /** @var PKCEManagerInterface|null */
    private $pkceManager;

    /** @var AccessToken|null */
    private $ownerAccessToken;
    /** @var AccessToken|null */
    private $clientAccessToken;
    #endregion

    /**
     * Undocumented function
     *
     * @param ClientParametersInterface $client
     * @param ClientInterface|null $httpClient
     *        Used to fetch Access Tokens to Token Endpoint.
     *
     *        Not required for Authorize Requests.
     * @param RequestFactoryInterface|null $requestFactory
     *        Used to fetch Access Tokens to Token Endpoint.
     *
     *        Not required for Authorize Requests.
     * @param ClientAccessTokenSaverInterface|null $clientSaver
     *        Used to store Client Access Token.
     * @param OwnerAccessTokenSaverInterface|null $ownerSaver
     *        Used to store Resources' Owner Access Token.
     * @param StateManagerInterface|null $stateManager
     *        Generates and checks State attribute which is used to prevent
     *        CSRF (Cross-Site Resource Forgery)
     * @param PKCEManagerInterface|null $pkceManager
     *        Generates and stores Code Challenge and Verifier to prevent
     *        Authorization Code interception attacks.
     */
    public function __construct(
        ClientParametersInterface $client,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?ClientAccessTokenSaverInterface $clientSaver = null,
        ?OwnerAccessTokenSaverInterface $ownerSaver = null,
        ?StateManagerInterface $stateManager = null,
        ?PKCEManagerInterface $pkceManager = null
    ) {
        $this->client = $client;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->clientAccessTokenSaver = $clientSaver;
        $this->ownerAcccessTokenSaver = $ownerSaver;
        $this->stateManager = $stateManager;
        $this->pkceManager = $pkceManager;
    }

    #region ClientParameters
    public function getClientId()
    {
        return $this->client->getClientId();
    }

    public function getClientSecret()
    {
        return $this->client->getClientSecret();
    }

    public function getAuthorizationEndpoint()
    {
        return $this->client->getAuthorizationEndpoint();
    }

    public function getTokenEndpoint()
    {
        return $this->client->getTokenEndpoint();
    }

    public function getCallbackEndpoint()
    {
        return $this->client->getCallbackEndpoint();
    }

    // public function preferBodyAuthentication(bool $prefer = true)
    // {
    //     $this->preferBodyAuthentication = $prefer;
    // }

    // public function isBodyAuthenticationPreferred()
    // {
    //     return $this->preferBodyAuthentication;
    // }
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
    #endregion

    #region
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

    public function getOwnerAccessToken($autoload = true): ?AccessToken
    {
        if ($autoload && !isset($this->ownerAccessToken) && isset($this->ownerAcccessTokenSaver)) {
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

    public function getClientAccessToken($autoload = true): ?AccessToken
    {
        if ($autoload && !isset($this->clientAccessToken) && isset($this->clientAccessTokenSaver)) {
            $this->clientAccessToken = $this->clientAccessTokenSaver->loadClientAccessToken();
        }
        return $this->clientAccessToken;
    }
    #endregion

    #region Authorization Uri Creators
    public function createAuthorizationCodeUri($scopes = [])
    {
        return AuthorizeRequestHelper::createCodeUri($this, $scopes);
    }

    public function createImplicitAuthorizationUri($scopes = [])
    {
        return AuthorizeRequestHelper::createTokenUri($this, $scopes);
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
            $verifier = $this->pkceManager->getPKCECode()->getCode();
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

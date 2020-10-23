<?php

use Francerz\Http\Client;
use Francerz\Http\Constants\MediaTypes;
use Francerz\Http\Constants\Methods;
use Francerz\Http\HttpFactory;
use Francerz\Http\Tools\HttpFactoryManager;
use Francerz\Http\Tools\MessageHelper;
use Francerz\Http\Tools\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthorizeRequestTypes;
use Francerz\OAuth2\Client\AuthClient;
use Francerz\OAuth2\TokenRequestGrantTypes;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

class AuthClientTest extends TestCase
{
    private $httpFactory;

    public function __construct()
    {
        parent::__construct();
        $this->httpFactory = new HttpFactoryManager(new HttpFactory());
    }

    private static function callPrivateMethod($obj, string $method, ...$args)
    {
        $reflection = new ReflectionClass($obj);
        $method = $reflection->getMethod($method);
        $method->setAccessible(true);
        return $method->invokeArgs($obj, $args);
    }

    public function createAuthClient()
    {
        $authClient = new AuthClient(
            $this->httpFactory,
            new Client(),
            '0123456789abcdef',
            '4j8zc7h8kalipt69mqd1id9q',
            'https://oauth2.server.com/token',
            'https://oauth2.server.com/authorize',
            'https://example.com/oauth2/callback'
        );

        $authClient->setCheckStateHandler(function(string $state) : bool {
            return true;
        });

        return $authClient;
    }

    public function testGetAuthorizationCodeRequestUri_Empty()
    {
        $authClient = $this->createAuthClient();

        $uri = $authClient->getAuthorizationCodeRequestUri();

        $this->assertEquals('https', $uri->getScheme());
        $this->assertEquals('oauth2.server.com', $uri->getHost());
        $this->assertEquals('/authorize', $uri->getPath());

        $query = UriHelper::getQueryParams($uri);
        $this->assertArrayNotHasKey('scope', $query);
        $this->assertArrayNotHasKey('state', $query);
        $this->assertEquals('https://example.com/oauth2/callback', $query['redirect_uri']);
        $this->assertEquals(AuthorizeRequestTypes::AUTHORIZATION_CODE, $query['response_type']);
        $this->assertEquals($authClient->getClientId(), $query['client_id']);
    }

    public function testGetAuthorizationCodeRequestUri()
    {
        $authClient = $this->createAuthClient();

        $uri = $authClient->getAuthorizationCodeRequestUri(['scope1', 'scope2'], 'aBcXyZ.123');

        $this->assertEquals('https', $uri->getScheme());
        $this->assertEquals('oauth2.server.com', $uri->getHost());
        $this->assertEquals('/authorize', $uri->getPath());

        $query = UriHelper::getQueryParams($uri);
        $this->assertEquals('scope1 scope2', $query['scope']);
        $this->assertEquals('aBcXyZ.123', $query['state']);
        $this->assertEquals('https://example.com/oauth2/callback', $query['redirect_uri']);
        $this->assertEquals(AuthorizeRequestTypes::AUTHORIZATION_CODE, $query['response_type']);
        $this->assertEquals($authClient->getClientId(), $query['client_id']);
    }

    public function createCallbackCodeRequest()
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        $requestFactory = $this->httpFactory->getRequestFactory();

        $uri = $uriFactory->createUri('https://example.com/oauth2/callback');
        $uri = UriHelper::withQueryParams($uri, array(
            'state' => 'aBcXyZ.123',
            'code' => 'A1lfLISBC4BK'
        ));

        $request = $requestFactory->createRequest(Methods::GET, $uri);

        return $request;
    }

    public function testHandleCallbackCodeRequest()
    {
        $authClient = $this->createAuthClient();
        $codeRequest = $this->createCallbackCodeRequest();

        $request = static::callPrivateMethod($authClient, 'getFetchAccessTokenWithCodeRequest', $codeRequest);

        if (!$request instanceof RequestInterface) return;

        $this->assertEquals(Methods::POST, $request->getMethod());
        $this->assertStringStartsWith(
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            $request->getHeaderLine('Content-Type')
        );

        $uri = $request->getUri();
        $this->assertEquals('https', $uri->getScheme());
        $this->assertEquals('oauth2.server.com', $uri->getHost());
        $this->assertEquals('/token', $uri->getPath());

        $params = MessageHelper::getContent($request);
        $this->assertEquals(TokenRequestGrantTypes::AUTHORIZATION_CODE, $params['grant_type']);
        $this->assertEquals('A1lfLISBC4BK', $params['code']);
        $this->assertEquals('https://example.com/oauth2/callback', $params['redirect_uri']);
    }

    public function testGetFetchAccessTokenWithRefreshTokenRequest()
    {
        $authClient = $this->createAuthClient();
        
        $request = static::callPrivateMethod(
            $authClient,
            'getFetchAccessTokenWithRefreshTokenRequest',
            'xcag6ykryl8ocr1hrac6q4k2qlf3zm1a'
        );

        if (!$request instanceof RequestInterface) return;

        $this->assertEquals(Methods::POST, $request->getMethod());
        $this->assertStringStartsWith(
            MediaTypes::APPLICATION_X_WWW_FORM_URLENCODED,
            $request->getHeaderLine('Content-Type')
        );

        $uri = $request->getUri();
        $this->assertEquals('https', $uri->getScheme());
        $this->assertEquals('oauth2.server.com', $uri->getHost());
        $this->assertEquals('/token', $uri->getPath());

        $params = MessageHelper::getContent($request);
        $this->assertEquals(TokenRequestGrantTypes::REFRESH_TOKEN, $params['grant_type']);
        $this->assertEquals('xcag6ykryl8ocr1hrac6q4k2qlf3zm1a', $params['refresh_token']);
    }

    private function createAccessTokenResponse()
    {
        $responseFactory = $this->httpFactory->getResponseFactory();
        $response = $responseFactory->createResponse()
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
        
        $accessToken = new AccessToken(
            'doh8ny4a9h5r72ng52iizjxj', // access token
            'Bearer',
            3600,
            'xcag6ykryl8ocr1hrac6q4k2qlf3zm1a', // refresh token
            null,
            'scope1 scope2'
        );

        $response = MessageHelper::withContent($response, MediaTypes::APPLICATION_JSON, $accessToken);

        return $response;
    }

    public function testGetAccessTokenFromResponse()
    {
        $authClient = $this->createAuthClient();
        $response = $this->createAccessTokenResponse();

        $accessToken = static::callPrivateMethod($authClient, 'getAccessTokenFromResponse', $response);

        if (!$accessToken instanceof AccessToken) return;

        $this->assertEquals('doh8ny4a9h5r72ng52iizjxj', $accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(3600, $accessToken->getExpiresIn());
        $this->assertEquals('xcag6ykryl8ocr1hrac6q4k2qlf3zm1a', $accessToken->getRefreshToken());
    }
}
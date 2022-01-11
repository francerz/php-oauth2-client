<?php

namespace Francerz\OAuth2\Client\Tests;

use Exception;
use Fig\Http\Message\RequestMethodInterface;
use Francerz\Http\ServerRequest;
use Francerz\Http\Uri;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthorizeErrorEnum;
use Francerz\OAuth2\Client\Exceptions\AuthorizeAccessDeniedException;
use Francerz\OAuth2\Client\OAuth2Client;
use PHPUnit\Framework\TestCase;

class OAuth2ClientTest extends TestCase
{
    private $client;

    public function __construct($name = null, $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->client = new OAuth2Client(
            'abcdef',
            '123456',
            new Uri('https://auth.server.com/authorize'),
            new Uri('https://auth.server.com/token'),
            new Uri('https://example.com/oauth2/callback')
        );
    }

    public function testHandleCallbackTokenUriFragment()
    {
        $uri = $this->client->getCallbackEndpoint();
        $uri = UriHelper::withFragmentParams($uri, [
            'access_token' => 'AzByCxDwEv',
            'token_type' => 'Bearer',
            'expires_in' => 1800,
            'scope' => 'scp1 scp2'
        ]);
        $request = new ServerRequest($uri, RequestMethodInterface::METHOD_GET);
        $accessToken = $this->client->handleCallback($request);

        $expected = new AccessToken(
            'AzByCxDwEv',
            'Bearer',
            1800,
            null,
            'scp1 scp2',
            $accessToken->getCreateTime()
        );
        $this->assertEquals($expected, $accessToken);
    }

    public function testHandleCallbackTokenCode()
    {
        $uri = $this->client->getCallbackEndpoint();
        $uri = UriHelper::withQueryParams($uri, [
            'code' => 'A1B2C3D4E5'
        ]);
        $request = new ServerRequest($uri, RequestMethodInterface::METHOD_GET);

        try {
            $this->client->handleCallback($request);
        } catch (Exception $ex) {
            $this->assertStringContainsString('HTTP Client', $ex->getMessage());
        }
    }

    public function testHandleCallbackErrorUriFragment()
    {
        $uri = $this->client->getCallbackEndpoint();
        $uri = UriHelper::withFragmentParams($uri, [
            'error' => AuthorizeErrorEnum::ACCESS_DENIED,
            'error_description' => 'Resource owner denied access to protected resources.',
            'error_uri' => 'https://help.server.com/oauth2/error/access_denied'
        ]);
        $request = new ServerRequest($uri, RequestMethodInterface::METHOD_GET);

        try {
            $this->client->handleCallback($request);
        } catch (AuthorizeAccessDeniedException $ex) {
            $this->assertEquals(AuthorizeErrorEnum::ACCESS_DENIED, $ex->getError());
            $this->assertEquals('Resource owner denied access to protected resources.', $ex->getErrorDescription());
            $this->assertEquals('https://help.server.com/oauth2/error/access_denied', $ex->getErrorUri());
        }
    }

    public function testHandleCallbackErrorUriQueryString()
    {
        $uri = $this->client->getCallbackEndpoint();
        $uri = UriHelper::withQueryParams($uri, [
            'error' => AuthorizeErrorEnum::ACCESS_DENIED,
            'error_description' => 'Resource owner denied access to protected resources.',
            'error_uri' => 'https://help.server.com/oauth2/error/access_denied'
        ]);
        $request = new ServerRequest($uri, RequestMethodInterface::METHOD_GET);

        try {
            $this->client->handleCallback($request);
        } catch (AuthorizeAccessDeniedException $ex) {
            $this->assertEquals(AuthorizeErrorEnum::ACCESS_DENIED, $ex->getError());
            $this->assertEquals('Resource owner denied access to protected resources.', $ex->getErrorDescription());
            $this->assertEquals('https://help.server.com/oauth2/error/access_denied', $ex->getErrorUri());
        }
    }
}

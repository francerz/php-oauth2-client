<?php

namespace Francerz\OAuth2\Client\Tests;

use Francerz\Http\HttpFactory;
use Francerz\OAuth2\Client\Dev\Client;
use Francerz\OAuth2\Client\OAuth2Client;
use Francerz\OAuth2\Client\TokenRequestHelper;
use PHPUnit\Framework\TestCase;

class TokenRequestHelperTest extends TestCase
{
    private $client;
    public function __construct($name = null, $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $client = new Client();
        $this->client = new OAuth2Client($client, null, null, null, null, null, $client);
        $httpFactory = new HttpFactory();
        $this->client->setRequestFactory($httpFactory);
    }

    public function testCreateAccessTokenWithCodeRequest()
    {
        $request = TokenRequestHelper::createFetchAccessTokenWithCodeRequest(
            $this->client,
            'a1b2c3d4e5'
        );
        $this->assertEquals('YWJjZGVmOjEyMzQ1Ng==', $request->getHeaderLine('Authorization'));
        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $expectedBody =
            'grant_type=authorization_code' .
            '&code=a1b2c3d4e5' .
            '&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback' .
            '&code_verifier=A1B2C3D4E5F6';
        $this->assertEquals($expectedBody, (string)$request->getBody());
    }

    public function testCreateAccessTokenWithPasswordRequest()
    {
        $request = TokenRequestHelper::createFetchAccessTokenWithPasswordRequest(
            $this->client,
            'my.username',
            'a1b2c3d4e5',
            ['scp1', 'scp2']
        );
        $this->assertEquals('YWJjZGVmOjEyMzQ1Ng==', $request->getHeaderLine('Authorization'));
        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $expectedBody =
            'grant_type=password' .
            '&username=my.username' .
            '&password=a1b2c3d4e5' .
            '&scope=scp1+scp2';
        $this->assertEquals($expectedBody, (string)$request->getBody());
    }

    public function testCreateAccessTokenWithClientCredentialsRequest()
    {
        $request = TokenRequestHelper::createFetchAccessTokenWithClientCredentialsRequest(
            $this->client,
            ['scp1', 'scp2']
        );
        $this->assertEquals('YWJjZGVmOjEyMzQ1Ng==', $request->getHeaderLine('Authorization'));
        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $expectedBody =
            'grant_type=client_credentials' .
            '&scope=scp1+scp2';
        $this->assertEquals($expectedBody, (string)$request->getBody());
    }

    public function testCreateAccessTokenWithRefreshTokenRequest()
    {
        $request = TokenRequestHelper::createFetchAccessTokenWithRefreshTokenRequest(
            $this->client,
            'A1b9C3d8E5f7',
            ['scp1', 'scp2']
        );
        $this->assertEquals('YWJjZGVmOjEyMzQ1Ng==', $request->getHeaderLine('Authorization'));
        $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        $expectedBody =
            'grant_type=refresh_token' .
            '&refresh_token=A1b9C3d8E5f7' .
            '&scope=scp1+scp2';
        $this->assertEquals($expectedBody, (string)$request->getBody());
    }
}

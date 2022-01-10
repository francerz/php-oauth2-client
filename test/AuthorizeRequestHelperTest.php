<?php

namespace Francerz\OAuth2\Client\Tests;

use Francerz\Http\Uri;
use Francerz\OAuth2\Client\AuthorizeRequestHelper;
use Francerz\OAuth2\Client\OAuth2Client;
use Francerz\OAuth2\ResponseTypesEnum;
use PHPUnit\Framework\TestCase;

class AuthorizeRequestHelperTest extends TestCase
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

    public function testCreateCodeUri()
    {
        $uri = AuthorizeRequestHelper::createCodeUri($this->client, ['scp1', 'scp2'], 'xyz');
        $expectedUrl =
            'https://auth.server.com/authorize' .
            '?response_type=code' .
            '&client_id=abcdef' .
            '&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback' .
            '&scope=scp1+scp2' .
            '&state=xyz';
        $this->assertEquals($expectedUrl, (string)$uri);
    }

    public function testCreateTokenUri()
    {
        $uri = AuthorizeRequestHelper::createTokenUri($this->client, ['scp1', 'scp2'], 'xyz');
        $expectedUrl =
            'https://auth.server.com/authorize' .
            '?response_type=token' .
            '&client_id=abcdef' .
            '&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback' .
            '&scope=scp1+scp2' .
            '&state=xyz';
        $this->assertEquals($expectedUrl, (string)$uri);
    }
}

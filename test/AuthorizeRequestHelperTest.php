<?php

namespace Francerz\OAuth2\Client\Tests;

use Francerz\OAuth2\Client\AuthorizeRequestHelper;
use Francerz\OAuth2\Client\Dev\Client;
use Francerz\OAuth2\Client\OAuth2Client;
use PHPUnit\Framework\TestCase;

class AuthorizeRequestHelperTest extends TestCase
{
    private $client;
    public function __construct($name = null, $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $client = new Client();
        $this->client = new OAuth2Client($client, null, null, $client, $client, $client, $client);
    }

    public function testCreateCodeUri()
    {
        $uri = AuthorizeRequestHelper::createCodeUri($this->client, ['scp1', 'scp2']);
        $expectedUrl =
            'https://auth.server.com/authorize' .
            '?response_type=code' .
            '&client_id=abcdef' .
            '&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback' .
            '&scope=scp1+scp2' .
            '&state=zAyBxC' .
            '&code_challenge=jsK6canPDi-AJ3lpjkot6qgWhuRGLaQb7-LWvI-uMSM' .
            '&code_challenge_method=S256';
        $this->assertEquals($expectedUrl, (string)$uri);
    }

    public function testCreateTokenUri()
    {
        $uri = AuthorizeRequestHelper::createTokenUri($this->client, ['scp1', 'scp2']);
        $expectedUrl =
            'https://auth.server.com/authorize' .
            '?response_type=token' .
            '&client_id=abcdef' .
            '&redirect_uri=https%3A%2F%2Fexample.com%2Foauth2%2Fcallback' .
            '&scope=scp1+scp2' .
            '&state=zAyBxC';
        $this->assertEquals($expectedUrl, (string)$uri);
    }
}

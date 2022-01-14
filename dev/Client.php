<?php

namespace Francerz\OAuth2\Client\Dev;

use Francerz\Http\Uri;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Client\ClientAccessTokenSaverInterface;
use Francerz\OAuth2\Client\OAuth2ClientInterface;
use Francerz\OAuth2\Client\OwnerAccessTokenSaverInterface;
use Francerz\OAuth2\Client\PKCECode;
use Francerz\OAuth2\Client\PKCEManagerInterface;
use Francerz\OAuth2\Client\StateManagerInterface;
use Francerz\OAuth2\CodeChallengeMethodsEnum;
use Psr\Http\Message\UriInterface;

class Client implements
    OAuth2ClientInterface,
    ClientAccessTokenSaverInterface,
    OwnerAccessTokenSaverInterface,
    PKCEManagerInterface,
    StateManagerInterface
{
    private $pkceCode;

    public function __construct()
    {
        $this->pkceCode = new PKCECode(
            'A1B2C3D4E5F6',
            CodeChallengeMethodsEnum::SHA256
        );
    }

    public function getClientId(): string
    {
        return 'abcdef';
    }

    public function getClientSecret(): ?string
    {
        return '123456';
    }

    public function getAuthorizationEndpoint(): ?UriInterface
    {
        return new Uri('https://auth.server.com/authorize');
    }

    public function getTokenEndpoint(): ?UriInterface
    {
        return new Uri('https://auth.server.com/token');
    }

    public function getCallbackEndpoint(): ?UriInterface
    {
        return new Uri('https://example.com/oauth2/callback');
    }

    public function loadClientAccessToken(): ?AccessToken
    {
        return null;
    }

    public function saveClientAccessToken(AccessToken $accessToken)
    {
    }

    public function loadOwnerAccessToken(): ?AccessToken
    {
        return null;
    }

    public function saveOwnerAccessToken(AccessToken $accessToken)
    {
    }

    public function generatePKCECode(): PKCECode
    {
        return $this->pkceCode;
    }

    public function getPKCECode(): PKCECode
    {
        return $this->pkceCode;
    }

    public function generateState(): string
    {
        return 'zAyBxC';
    }
    public function getState(): ?string
    {
        return 'zAyBxC';
    }
}

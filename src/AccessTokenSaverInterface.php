<?php

namespace Francerz\OAuth2\Client;

use Francerz\OAuth2\AccessToken;

interface AccessTokenSaverInterface
{
    public function loadAccessToken(): ?AccessToken;
    public function saveAccessToken(AccessToken $accessToken);
}

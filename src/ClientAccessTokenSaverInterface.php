<?php

namespace Francerz\OAuth2\Client;

use Francerz\OAuth2\AccessToken;

interface ClientAccessTokenSaverInterface
{
    public function loadClientAccessToken(): ?AccessToken;
    public function saveClientAccessToken(AccessToken $accessToken);
}

<?php

namespace Francerz\OAuth2\Client;

use Francerz\OAuth2\AccessToken;

interface OwnerAccessTokenSaverInterface
{
    public function loadOwnerAccessToken(): ?AccessToken;
    public function saveOwnerAccessToken(AccessToken $accessToken);
    public function discardOwnerAccessToken();
}

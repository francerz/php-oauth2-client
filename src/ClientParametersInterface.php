<?php

namespace Francerz\OAuth2\Client;

use Psr\Http\Message\UriInterface;

interface ClientParametersInterface
{
    public function getClientId(): string;
    public function getClientSecret(): ?string;
    public function getAuthorizationEndpoint(): ?UriInterface;
    public function getTokenEndpoint(): ?UriInterface;
    public function getCallbackEndpoint(): ?UriInterface;
}

<?php

namespace Francerz\OAuth2\Client;

use Psr\Http\Message\UriInterface;

interface OAuth2ClientInterface
{
    public function getClientId(): string;
    public function getClientSecret(): ?string;
    public function getAuthorizationEndpoint(): ?UriInterface;
    public function getTokenEndpoint(): ?UriInterface;
    public function getCallbackEndpoint(): ?UriInterface;
}

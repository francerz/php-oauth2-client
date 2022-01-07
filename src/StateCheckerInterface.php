<?php

namespace Francerz\OAuth2\Client;

interface StateManagerInterface
{
    public function generateState(): string;
    public function checkState(string $state): bool;
}

<?php

namespace Francerz\OAuth2\Client;

interface PKCEManagerInterface
{
    public function generatePKCECode(): PKCECode;
    public function getPKCECode(): PKCECode;
}

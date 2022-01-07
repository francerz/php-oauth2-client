<?php

namespace Francerz\OAuth2\Client;

interface PKCEManagerInterface
{
    public function generateCode(): PKCECode;
    public function getCode(): PKCECode;
}

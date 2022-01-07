<?php

namespace Francerz\OAuth2\Client;

use Francerz\OAuth2\CodeChallengeMethodsEnum;

class PKCECode
{
    private $code;
    private $method;

    public function __construct(string $code, $method = CodeChallengeMethodsEnum::PLAIN)
    {
        $this->code = $code;
        $this->method = $method;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function getMethod()
    {
        return $this->method;
    }
}

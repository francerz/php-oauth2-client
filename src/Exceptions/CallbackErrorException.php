<?php

namespace Francerz\OAuth2\Client\Exceptions;

use Francerz\OAuth2\OAuth2Exception;
use Throwable;

class CallbackErrorException extends OAuth2Exception
{
    private $error;
    private $description;
    private $uri;

    public function __construct(
        $error,
        $description = '',
        $uri = null,
        $message = '',
        $code = 0,
        ?Throwable $previous = null
    ) {
        $this->error = $error;
        $this->description = $description;
        $this->uri = $uri;
        if (empty($message)) {
            $message = $description;
        }
        parent::__construct($message, $code, $previous);
    }

    public function getError()
    {
        return $this->error;
    }

    public function getErrorDescription()
    {
        return $this->description;
    }

    public function getErrorUri()
    {
        return $this->uri;
    }
}

<?php

namespace Francerz\OAuth2\Client\Exceptions;

use Francerz\OAuth2\AuthorizeErrorEnum;
use Throwable;

class AuthorizeUnsupportedResponseTypeException extends CallbackErrorException
{
    public function __construct($description, $uri, $message = '', $code = 0, ?Throwable $previous = null)
    {
        parent::__construct(
            AuthorizeErrorEnum::UNSUPPORTED_RESPONSE_TYPE,
            $description,
            $uri,
            $message,
            $code,
            $previous
        );
    }
}

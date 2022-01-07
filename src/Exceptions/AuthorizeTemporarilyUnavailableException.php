<?php

namespace Francerz\OAuth2\Client\Exceptions;

use Francerz\OAuth2\AuthorizeErrorEnum;
use Throwable;

class AuthorizeTemporarilyUnavailableException extends CallbackErrorException
{
    public function __construct($description, $uri, $message = '', $code = 0, ?Throwable $previous = null)
    {
        parent::__construct(
            AuthorizeErrorEnum::TEMPORARILY_UNAVAILABLE,
            $description,
            $uri,
            $message,
            $code,
            $previous
        );
    }
}

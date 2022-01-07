<?php

namespace Francerz\OAuth2\Client;

use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\AuthorizeErrorEnum;
use Francerz\OAuth2\Client\Exceptions\AuthorizeAccessDeniedException;
use Francerz\OAuth2\Client\Exceptions\AuthorizeInvalidRequestException;
use Francerz\OAuth2\Client\Exceptions\AuthorizeInvalidScopeException;
use Francerz\OAuth2\Client\Exceptions\AuthorizeServerErrorException;
use Francerz\OAuth2\Client\Exceptions\AuthorizeTemporarilyUnavailableException;
use Francerz\OAuth2\Client\Exceptions\AuthorizeUnauthorizedClientException;
use Francerz\OAuth2\Client\Exceptions\AuthorizeUnsupportedResponseTypeException;
use Francerz\OAuth2\Client\Exceptions\CallbackErrorException;
use Francerz\OAuth2\Client\Exceptions\StateMismatchException;
use Francerz\OAuth2\OAuth2Exception;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

class CallbackEndpointHandler
{

    private static function checkState(ClientParameters $client, $state)
    {
        $stateChecker = $client->getStateManager();
        if (is_null($stateChecker)) {
            return true;
        }
        return $stateChecker->checkState($state);
    }

    /**
     * @param string[] $params
     */
    private static function handleError(ClientParameters $client, array $params)
    {
        if (array_key_exists('state', $params) && !static::checkState($client, $params['state'])) {
            throw new StateMismatchException();
        }
        switch ($params['error']) {
            case AuthorizeErrorEnum::INVALID_REQUEST:
                throw new AuthorizeInvalidRequestException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
            case AuthorizeErrorEnum::UNAUTHORIZED_CLIENT:
                throw new AuthorizeUnauthorizedClientException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
            case AuthorizeErrorEnum::ACCESS_DENIED:
                throw new AuthorizeAccessDeniedException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
            case AuthorizeErrorEnum::UNSUPPORTED_RESPONSE_TYPE:
                throw new AuthorizeUnsupportedResponseTypeException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
            case AuthorizeErrorEnum::INVALID_SCOPE:
                throw new AuthorizeInvalidScopeException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
            case AuthorizeErrorEnum::SERVER_ERROR:
                throw new AuthorizeServerErrorException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
            case AuthorizeErrorEnum::TEMPORARILY_UNAVAILABLE:
                throw new AuthorizeTemporarilyUnavailableException(
                    $params['error_description'] ?? '',
                    $params['error_uri'] ?? null
                );
        }
        throw new CallbackErrorException(
            $params['error'] ?? 'unknown_error',
            $params['error_description'] ?? '',
            $params['error_uri'] ?? null
        );
    }

    private static function handleCode(ClientParameters $client, array $params)
    {
        if (array_key_exists('state', $params) && !static::checkState($client, $params['state'])) {
            throw new StateMismatchException();
        }
        $httpClient = $client->getHttpClient();
        if (is_null($httpClient)) {
            throw new LogicException("Missing HTTP Client in ClientParams.");
        }

        $request = TokenRequestHelper::createFetchAccessTokenWithCodeRequest($client, $params['code']);
        $response = $httpClient->sendRequest($request);
        $accessToken = TokenRequestHelper::getAccessTokenFromResponse($response);
        return $accessToken;
    }

    private static function handleToken(ClientParameters $client, array $params)
    {
        if (array_key_exists('state', $params) && !static::checkState($client, $params['state'])) {
            throw new StateMismatchException();
        }
        $accessToken = new AccessToken(
            $params['access_token'],
            $params['token_type'] ?? 'Bearer',
            $params['expires_in'] ?? 3600,
            null,
            $params['scope'] ?? ''
        );
        return $accessToken;
    }

    public static function handle(ClientParameters $client, ServerRequestInterface $request)
    {
        $params = UriHelper::getQueryParams($request->getUri());
        if (array_key_exists('error', $params)) {
            return static::handleError($client, $params);
        }
        if (array_key_exists('code', $params)) {
            return static::handleCode($client, $params);
        }
        $params = UriHelper::getFragmentParams($request->getUri());
        if (array_key_exists('error', $params)) {
            return static::handleError($client, $params);
        }
        if (array_key_exists('access_token', $params)) {
            return static::handleToken($client, $params);
        }
        throw new OAuth2Exception("Invalid callback request");
    }
}

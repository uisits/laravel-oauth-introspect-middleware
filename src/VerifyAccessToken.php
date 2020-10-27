<?php

/**
 * Middleware for verifying the Bearer OAuth2 access token as provided in the HTTP Authorization-header.
 */

namespace ArieTimmerman\Laravel\OAuth2;

use Closure;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Cache;
use ArieTimmerman\Laravel\OAuth2\Exceptions\InvalidAccessTokenException;
use ArieTimmerman\Laravel\OAuth2\Exceptions\InvalidInputException;
use ArieTimmerman\Laravel\OAuth2\Exceptions\InvalidEndpointException;

class VerifyAccessToken
{

    private $client = null;

    private function getClient()
    {
        if ($this->client == null) {
            $this->client = new \GuzzleHttp\Client();
        }

        return $this->client;
    }

    public function setClient(\GuzzleHttp\Client $client)
    {
        $this->client = $client;
    }

    /**
     */
    protected function getIntrospect($accessToken)
    {
        $guzzle = $this->getClient();

        try {
            $response = $guzzle->post(
                config('authorizationserver.authorization_server_introspect_url'), [
                    'form_params' => [
                        'token' => $accessToken,
                        'client_id' => config('authorizationserver.authorization_server_client_id'),
                        'client_secret' => config('authorizationserver.authorization_server_client_secret'),
                    ],
                ]
            );
        } catch(RequestException $e) {

            // Access token might have expired, just retry getting one
            \Cache::forget('accessToken');
        }

        return json_decode(( string ) $response->getBody(), true);
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure                 $next
     * @return mixed
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        $authorization = $request->header('Authorization');

        if (strlen($authorization) == 0) {
            throw new InvalidInputException("No Authorization header present");
        }

        $receivedAccessToken = preg_replace('/^Bearer (.*?)$/', '$1', $authorization);

        // Just to be sure it is really an access token
        if (strlen($receivedAccessToken) <= 1) {
            throw new InvalidInputException("No Bearer token in the Authorization header present");
        }

        // Now verify the user provided access token
        try {

            $result = $this->getIntrospect($receivedAccessToken);
            if (! $result ['active']) {
                throw new InvalidAccessTokenException("Invalid token!");
            } else if ($scopes != null) {

                if (! \is_array($scopes)) {
                    $scopes = [
                        $scopes
                    ];
                }

                $scopesForToken = \explode(" ", $result ['scope']);

                if (count($misingScopes = array_diff($scopes, $scopesForToken)) > 0 ) {
                    throw new InvalidAccessTokenException("Missing the following required scopes: " . implode(" ,", $misingScopes));
                } else {
                }
            }
        } catch ( RequestException $e ) {
            if ($e->hasResponse()) {
                $result = json_decode(( string ) $e->getResponse()->getBody(), true);

                if (isset($result ['error'])) {
                    throw new InvalidAccessTokenException($result ['error'] ['title'] ?? "Invalid token!");
                } else {
                    throw new InvalidAccessTokenException("Invalid token!");
                }
            } else {
                throw new InvalidAccessTokenException($e);
            }
        }

        return $next($request);
    }
}

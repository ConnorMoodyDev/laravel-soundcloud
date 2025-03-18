<?php

namespace Noweh\SoundcloudApi;

use InvalidArgumentException;
use RuntimeException;
use Config;

class Soundcloud
{
    /**
     * OAuth client id
     *
     * @var string
     *
     * @access private
     */
    private string $_clientId;

    /**
     * OAuth client secret
     *
     * @var string
     *
     * @access private
     */
    private string $_clientSecret;

    /**
     * OAuth redirect URI
     *
     * @var string
     *
     * @access private
     */
    private string $_redirectUri;

    /**
     * Access code
     *
     * @var string
     *
     * @access private
     */
    private string $_code = '';

    /**
     * Access token returned by the service provider after a successful authentication
     *
     * @var string
     *
     * @access private
     */
    private string $_accessToken = '';

    private string $_refreshToken = '';

    /**
     * Code verifier
     *
     * @var string
     *
     * @access private
     */
    private string $_codeVerifier;

    /**
     * Code challenge
     *
     * @var string
     *
     * @access private
     */
    private string $_codeChallenge;

    /**
     * Class constructor.
     *
     * @return void
     * @throws InvalidArgumentException
     *
     * @access public
     */
    public function __construct()
    {
        if (!Config::has('soundcloud.client_id') || !Config::has('soundcloud.client_secret')) {
            throw new InvalidArgumentException('client_id and client_secret must be set in config file');
        }
        $this->_clientId = Config::get('soundcloud.client_id');
        $this->_clientSecret = Config::get('soundcloud.client_secret');
        $this->_redirectUri = Config::get('soundcloud.callback_url');

        // Generate code verifier and challenge
        $this->_codeVerifier = Config::get('soundcloud.code_verifier');
        $this->_codeChallenge = $this->generateCodeChallenge($this->_codeVerifier);
    }

    private function generateCodeChallenge(string $codeVerifier): string
    {
        $hash = hash('sha256', $codeVerifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Get authorization URL.
     *
     * @param string $state Any value included here will be appended to te redirect URI
     *
     * @return string
     */
    public function getAuthorizeUrl(string $state): string
    {
        $params = [
            'client_id' => $this->_clientId,
            'redirect_uri' => $this->_redirectUri,
            'response_type' => 'code',
            'code_challenge' => $this->_codeChallenge,
            'code_challenge_method' => 'S256',
            'state' => $state
        ];

        return $this->buildUrl('authorize', $params, true);
    }

    /**
     * Send a GET HTTP request.
     *
     * @param string $path Request path
     * @param array $params Optional query string parameters
     * @param array $curlOptions Optional cURL options
     * @param bool $needAccessToken Optional add/remove access token in header
     *
     * @return mixed
     * @throws \RuntimeException
     * @throws \JsonException
     * @throws InvalidArgumentException
     */
    public function get(string $path, array $params = [], array $curlOptions = [], bool $needAccessToken = true)
    {
        $url = $this->buildUrl($path, $params);

        return $this->performRequest($url, $curlOptions, $needAccessToken);
    }

    /**
     * Send a POST HTTP request.
     *
     * @param string $path Request path
     * @param array $postData Optional post data
     * @param array $curlOptions Optional cURL options
     * @param bool $needAccessToken Optional add/remove access token in header
     *
     * @return mixed
     * @throws RuntimeException
     * @throws \JsonException
     * @throws InvalidArgumentException
     */
    public function post(string $path, array $postData = [], array $curlOptions = [], bool $needAccessToken = true)
    {
        $url = $this->buildUrl($path);
        $options = [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postData),
        ];
        $options = array_replace($options, $curlOptions);

        return $this->performRequest($url, $options, $needAccessToken);
    }

    /**
     * Send a PUT HTTP request.
     *
     * @param string $path Request path
     * @param array $postData Optional post data
     * @param array $curlOptions Optional cURL options
     * @param bool $needAccessToken Optional add/remove access token in header
     *
     * @return mixed
     * @throws RuntimeException
     * @throws \JsonException
     * @throws InvalidArgumentException
     */
    public function put(string $path, array $postData, array $curlOptions = [], bool $needAccessToken = true)
    {
        $url = $this->buildUrl($path);
        $options = [
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS => $postData
        ];
        $options = array_replace($options, $curlOptions);

        return $this->performRequest($url, $options, $needAccessToken);
    }

    /**
     * Send a DELETE HTTP request.
     *
     * @param string $path Request path
     * @param array $params Optional query string parameters
     * @param array $curlOptions Optional cURL options
     * @param bool $needAccessToken Optional add/remove access token in header
     *
     * @return mixed
     * @throws \RuntimeException
     * @throws \JsonException
     * @throws InvalidArgumentException
     */
    public function delete(string $path, array $params = [], array $curlOptions = [], bool $needAccessToken = true)
    {
        $url = $this->buildUrl($path, $params);
        $options = [CURLOPT_CUSTOMREQUEST => 'DELETE'];
        $options = array_replace($options, $curlOptions);

        return $this->performRequest($url, $options, $needAccessToken);
    }

    /**
     * Serve the widget embed code for any SoundCloud URL pointing to a user, set, or a playlist.
     *
     * @param string $url
     * @param int $maxheight
     * @param bool $sharing
     * @param bool $liking
     * @param false $download
     * @param bool $show_comments
     * @param false $show_playcount
     * @param false $show_user
     * @return mixed
     * @throws RuntimeException
     * @throws \JsonException
     */
    public function getPlayerEmbed(
        string $url,
        int $maxheight = 180,
        bool $sharing = true,
        bool $liking = true,
        bool $download = false,
        bool $show_comments = true,
        bool $show_playcount = false,
        bool $show_user = false
    ) {
        $soundcloudResponse = $this->get('https://soundcloud.com/oembed',
            [
                'url' => $url,
                'maxheight' => $maxheight,
                'sharing' => $sharing,
                'liking' => $liking,
                'download' => $download,
                'show_comments' => $show_comments,
                'show_playcount' => $show_playcount,
                'show_user' => $show_user
            ],
            [
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.A.B.C Safari/525.13',

            ],
            false
        );

        return $soundcloudResponse->html ?? null;
    }

    public function setCode(string $code): void
    {
        $this->_code = $code;
    }

    /**
     * Set Access Token
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->_accessToken = $accessToken;
    }

    /**
     * Get Access Token
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @throws \JsonException
     */
    public function getAccessToken(): string
    {
        if (!$this->_accessToken) {
            // Try to auto retrieve the access token with code in instance or in the URL
            if (!$this->_code) {
                if (request()->has('code')) {
                    $this->_code = request()->get('code');
                } else {
                    throw new InvalidArgumentException('accessToken must be set or accessible in URL parameters');
                }
            }

            $soundCloudResponse = $this->post(
                $this->buildUrl('oauth/token', [], true),
                [
                    'grant_type' => 'authorization_code',
                    'client_id' => $this->_clientId,
                    'client_secret' => $this->_clientSecret,
                    'redirect_uri' => $this->_redirectUri,
                    'code_verifier' => $this->_codeVerifier,
                    'code' => $this->_code,
                ],
                [],
                false
            );

            if ($soundCloudResponse && $soundCloudResponse->access_token) {
                $this->_accessToken = $soundCloudResponse->access_token;
            }

            if($soundCloudResponse && $soundCloudResponse->refresh_token) {
                $this->_refreshToken = $soundCloudResponse->refresh_token;
            }
        }

        return $this->_accessToken;
    }

    public function refreshToken(): string {
        return $this->_refreshToken;
    }

    /**
     * Construct a URL
     *
     * @param string  $path           Relative or absolute URI
     * @param array   $params         Optional query string parameters
     * @param bool    $secureMode     Optional secure mode
     *
     * @return string $url
     *
     * @access protected
     */
    protected function buildUrl(string $path, array $params = [], bool $secureMode = false): string
    {
        if (preg_match('/^https?\:\/\//', $path)) {
            $url = $path;
        } else {
            if ($path[0] === '/') {
                $path = substr($path, 1);
            }

            if ($secureMode) {
                $url = 'https://secure.soundcloud.com/';
            } else {
                $url = 'https://api.soundcloud.com/';
            }

            $url .= $path;
        }

        $url .= (count($params)) ? '?' . http_build_query($params) : '';

        return $url;
    }

    /**
     * Performs the actual HTTP request using cURL
     *
     * @param string $url Absolute URL to request
     * @param array $curlOptions Optional cURL options
     *
     * @return mixed
     * @throws RuntimeException
     * @throws \JsonException
     * @throws InvalidArgumentException
     *
     * @access protected
     */
    protected function performRequest(string $url, array $curlOptions = [], $needAccessToken = true)
    {
        $ch = curl_init($url);

        if (!isset($curlOptions[CURLOPT_HTTPHEADER])) {
            $curlOptions[CURLOPT_HTTPHEADER] = [];
        }

        $curlOptions[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded';
        $curlOptions[CURLOPT_HTTPHEADER][] = 'Accept: application/json';
        $curlOptions[CURLOPT_RETURNTRANSFER] = true;

        if ($needAccessToken) {
            $curlOptions[CURLOPT_HTTPHEADER][] = 'Authorization: OAuth ' . $this->getAccessToken();
        }

        curl_setopt_array($ch, $curlOptions);

        $data = curl_exec($ch);
        $info = curl_getinfo($ch);
        $error = curl_error($ch);

        if ($info['http_code'] !== 200) {
            $errorMessage = $data ?? $error;
            throw new RuntimeException(
                $data ? : $error, $info['http_code']
            );
        }

        return json_decode($data, false, 512, JSON_THROW_ON_ERROR);
    }
}

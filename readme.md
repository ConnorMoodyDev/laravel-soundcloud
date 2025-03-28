# SoundCloud API for Laravel

![SoundCloud](https://img.shields.io/static/v1?style=flat-square&message=SoundCloud&color=FF3300&logo=SoundCloud&logoColor=FFFFFF&label=)
![Laravel](https://img.shields.io/badge/Laravel-v5/6/7/8/9/10-828cb7.svg?style=flat-square&logo=Laravel&color=FF2D20)
![PHP](https://img.shields.io/badge/PHP-v7.3-828cb7.svg?style=flat-square&logo=php)
[![MIT Licensed](https://img.shields.io/github/license/noweh/laravel-soundcloud)](licence.md)
[![last version](https://img.shields.io/packagist/v/noweh/laravel-soundcloud)](https://packagist.org/packages/noweh/laravel-soundcloud)
[![Downloads](https://img.shields.io/packagist/dt/noweh/laravel-soundcloud)](https://packagist.org/packages/noweh/laravel-soundcloud)

A Laravel Wrapper for the SoundCloud REST API endpoints.

## Installation
First, you need to add the component to your composer.json.
```
composer require noweh/laravel-soundcloud
```
Update your packages with *composer update* or install with *composer install*.

Laravel uses Package Auto-Discovery, so doesn't require you to manually add the ServiceProvider.

### Laravel without auto-discovery

    Noweh\SoundcloudApi\SoundcloudServiceProvider::class,

To use the facade, add this in app.php:

    'Soundcloud' => Noweh\SoundcloudApi\SoundcloudFacade::class,

### Service Provider
After updating composer, add the ServiceProvider to the providers array in config/app.php

## Configuration file

Next, you must migrate config :

    php artisan vendor:publish --provider="Noweh\SoundcloudApi\SoundcloudServiceProvider"

⚠️ `{CALLBACK_URL}` must be identical to the one indicated in your SoundCloud account.
⚠️ `{SOUNDCLOUD_CODE_VERIFIER}` must be a random string of 43 to 128 characters: (https://blog.postman.com/what-is-pkce/)

## Usage

⚠️ Since [July 2021](https://developers.soundcloud.com/blog/security-updates-api), most calls to SoundCloud REST API requires an `access_token`.
⚠️ Since October 2024, SoundCloud will require all API calls to be authenticated with an `code_verifier`.

You have to redirect the user to the SoundCloud login page:
```php
return redirect(\Soundcloud::getAuthorizeUrl('a_custom_param_to_retrieve_in_callback'));
```

On your callback URL, you can call GET/POST/PUT/DELETE methods. The `access_token` will be automatically generated with the `code` parameter present in this URL.

If you want to use API calls in another page, you have to set manually this data:
```
\Soundcloud::setCode('3-134981-158678512-IwAXqypKWlDJCF');

// API Call
...
```


### Get Player Embed
#### This call doest not requires an access_token.

To retrieve the widget embed code for any SoundCloud URL pointing to a user, set, or a playlist, do the following:
```
// Required parameter
$url = 'https://soundcloud.com/......';

// Optional parameters
$maxheight = 180;
$sharing = true;
$liking = true;
$download = false;
$show_comments = true;
$show_playcount = false;
$show_user = false;

try {
    $response = \Soundcloud::getPlayerEmbed($url, $maxheight, $sharing, $liking, $download, $show_comments, $show_playcount, $show_user)
} catch (Exception $e) {
    exit($e->getMessage());
}
```

### GET
```
try {
    $response = \Soundcloud::get('users/{CLIENT_ID}/tracks');
} catch (Exit $e) {
    exit($e->getMessage());
}
```

### GET with pagination

Most results from our API are returned as a collection. The number of items in the collection returned is limited to 50 by default with a maximum value of 200. Most endpoints support a linked_partitioning parameter that allows you to page through collections. When this parameter is passed, the response will contain a next_href property if there are additional results. To fetch the next page of results, simply follow that URI. If the response does not contain a next_href property, you have reached the end of the results.

```
try {
    $tracks = [];
    $params = ['linked_partitioning' => true, 'limit' => 100 ];
    $response = \Soundcloud::get('users/{CLIENT_ID}/tracks', $params);
    while (property_exists($response, 'next_href') && !empty($response->next_href)) {
        $tracks = array_merge($tracks,$response->collection);
        $response = \Soundcloud::get($response->next_href);
    }
} catch (Exit $e) {
    exit($e->getMessage());
}
```

### POST
```
try {
    $response = \Soundcloud::post(
        'tracks/1/comments',
        [
            'body' => 'a new comment'
        ]
    );
} catch (Exception $e) {
    exit($e->getMessage());
}
```

### PUT
```
try {
    $response = \Soundcloud::put(
        'tracks/1',
        [
            'title' => 'my new title'
        ]
    );
} catch (Exception $e) {
    exit($e->getMessage());
}
```

### DELETE
```
try {
    $response = \Soundcloud::delete('tracks/1');
} catch (Exception $e) {
    exit($e->getMessage());
}
```

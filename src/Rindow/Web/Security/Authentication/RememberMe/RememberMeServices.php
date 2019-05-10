<?php
namespace Rindow\Web\Security\Authentication\RememberMe;

use Psr\Http\Message\ServerRequestInterface;
use Interop\Lenient\Security\Authentication\Authentication;

interface RememberMeServices
{
    /**
     * @return Authentication
     */
    public function autoLogin(ServerRequestInterface $request, /*CookieContext*/$responseCookies);

    /**
     * @return void
     */
    public function loginFail(ServerRequestInterface $request, /*CookieContext*/$responseCookies);

    /**
     * @return void
     */
    public function loginSuccess(ServerRequestInterface $request, /*CookieContext*/$responseCookies,
            Authentication $successfulAuthentication);
}

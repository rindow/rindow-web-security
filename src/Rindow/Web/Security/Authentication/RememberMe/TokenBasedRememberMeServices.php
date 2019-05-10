<?php
namespace Rindow\Web\Security\Authentication\RememberMe;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Interop\Lenient\Security\Authentication\Authentication;

use Rindow\Web\Security\Authentication\Exception;

class TokenBasedRememberMeServices extends AbstractRememberMeServices
{
    protected $algorithm = 'sha256';

    public function setAlgorithm($algorithm)
    {
        $this->algorithm = $algorithm;
    }

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    protected function processAutoLoginCookie($cookieValue,ServerRequestInterface $request,$responseCookies)
    {
        $credencials = explode(':', base64_decode($cookieValue));
        if(count($credencials)!=3)
            throw new Exception\InvalidCookieException('Illegal RememberMe Cookie format');
        list($username,$expires,$signature) = $credencials;
        if($expires<time()) {
            throw new Exception\InvalidCookieException('Cookie has expired');
        }
        $username = base64_decode($username,true);
        $user = $this->loadUserByUsername($username);
        
        $reHash = $this->generateSignature($username,$expires,$user->getPassword());
        if($signature!==$reHash)
            throw new Exception\InvalidCookieException('Cookie contained invalid signature');
        return $user;
    }

    public function generateCookie($authentication)
    {
        $username = $authentication->getName();
        $expires = time() + $this->lifetime;
        $user = $this->loadUserByUsername($username);
        $password = $user->getPassword();
        $signature = $this->generateSignature($username,$expires,$password);
        $username = base64_encode($user->getUsername());
        $cookie = $username.':'.$expires.':'.$signature;
        return base64_encode($cookie);
    }

    protected function generateSignature($username,$expires,$password)
    {
        $signature = hash_hmac($this->algorithm,$username.$password.$expires,$this->getSecret());
        return $signature;
    }

    protected function onLoginSuccess(ServerRequestInterface $request, $responseCookies,
            Authentication $authentication)
    {
        $cookie = $this->generateCookie($authentication);
        $this->setCookie($cookie,$request,$responseCookies);
    }

    protected function onLoginFail(ServerRequestInterface $request, $responseCookies)
    {
        $this->cancelCookie($request,$responseCookies);
    }
}

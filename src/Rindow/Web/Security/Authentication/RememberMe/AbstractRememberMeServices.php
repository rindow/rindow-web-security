<?php
namespace Rindow\Web\Security\Authentication\RememberMe;

use Psr\Http\Message\ServerRequestInterface;
use Interop\Lenient\Security\Authentication\Authentication;
use Rindow\Security\Core\Authentication\Exception\AuthenticationException;
use Rindow\Security\Core\Authentication\Exception\UsernameNotFoundException;
use Rindow\Web\Security\Authentication\Exception\InvalidCookieException;

use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\UserDetails\Provider\DefaultPreUserDetailsAuthenticationChecker;
use Rindow\Security\Core\Authentication\UserDetails\Provider\DefaultPostUserDetailsAuthenticationChecker;

abstract class AbstractRememberMeServices implements RememberMeServices
{
    protected $secret;
    protected $cookieName = 'remember-me';
    protected $lifetime = 2592000; // 30 days = 30*24*3600
    protected $path;
    protected $domain = "";
    protected $secure = false;
    protected $httponly = true;
    protected $userDetailsService;
    protected $rememberMeAuthenticationProvider;
    protected $preAuthenticationUserDetailsChecker;
    protected $postAuthenticationUserDetailsChecker;
    protected $cookieManager;
    protected $debug = false;
    protected $logger;

    /**
     * @param  String $cookie
     * @return User
     */
    abstract protected function processAutoLoginCookie($cookie, ServerRequestInterface $request, /*CookieContext*/$responseCookies);

    public function __construct($userDetailsService=null,$rememberMeAuthenticationProvider=null)
    {
        if($userDetailsService)
            $this->setUserDetailsService($userDetailsService);
        if($rememberMeAuthenticationProvider)
            $this->setRememberMeAuthenticationProvider($rememberMeAuthenticationProvider);
        $this->preAuthenticationUserDetailsChecker  = new DefaultPreUserDetailsAuthenticationChecker();
        $this->postAuthenticationUserDetailsChecker = new DefaultPostUserDetailsAuthenticationChecker();
    }

    public function setUserDetailsService($userDetailsService)
    {
        $this->userDetailsService = $userDetailsService;
    }

    public function setRememberMeAuthenticationProvider($rememberMeAuthenticationProvider)
    {
        $this->rememberMeAuthenticationProvider = $rememberMeAuthenticationProvider;
    }

    public function setPreAuthenticationUserDetailsChecker($preAuthenticationUserDetailsChecker)
    {
        $this->preAuthenticationUserDetailsChecker = $preAuthenticationUserDetailsChecker;
    }

    public function setPostAuthenticationUserDetailsChecker($postAuthenticationUserDetailsChecker)
    {
        $this->postAuthenticationUserDetailsChecker = $postAuthenticationUserDetailsChecker;
    }

    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    protected function getSecret()
    {
        return $this->secret;
    }

    public function getHashKey()
    {
        return sha1($this->secret);
    }

    public function getCookieName()
    {
        return $this->cookieName;
    }

    public function getPath()
    {
        return $this->path;
    }

    public function setConfig($config)
    {
        if(isset($config['cookieName']))
            $this->cookieName = $config['cookieName'];
        if(isset($config['lifetime']))
            $this->lifetime = $config['lifetime'];
        if(isset($config['path']))
            $this->path = $config['path'];
        if(isset($config['domain']))
            $this->domain = $config['domain'];
        if(isset($config['secure']))
            $this->secure = $config['secure'];
        if(isset($config['httponly']))
            $this->httponly = $config['httponly'];
    }

    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    public function setDebug($debug)
    {
        $this->debug = $debug;
    }

    protected function loadUserByUsername($username)
    {
        return $this->userDetailsService->loadUserByUsername($username);
    }

    /**
     * @return Authentication
     */
    public function autoLogin(ServerRequestInterface $request, $responseCookies)
    {
        $cookies = $request->getCookieParams();
        if(!isset($cookies[$this->cookieName]))
            return null;
        try {
            $user = $this->processAutoLoginCookie($cookies[$this->cookieName],$request,$responseCookies);
            if(!$user) {
                return null;
            }
            $this->preAuthenticationUserDetailsChecker->check($user);
            $this->postAuthenticationUserDetailsChecker->check($user);
            $auth = $this->createSuccessfulAuthentication($request,$user);
            return $auth;
        } catch(AuthenticationException $e) {
            ;
        } catch(UsernameNotFoundException $e) {
            ;
        } catch(InvalidCookieException $e) {
            ;
        }
        $this->debugLogging(get_class($e).': '.$e->getMessage());
        $this->cancelCookie($request, $responseCookies);
        return null;
    }

    protected function createSuccessfulAuthentication($request,$user)
    {
        return $this->rememberMeAuthenticationProvider->createToken($user->getUsername(),$user->getAuthorities());
    }

    /**
     * @return void
     */
    public function loginSuccess(ServerRequestInterface $request, $responseCookies,
            Authentication $successfulAuthentication)
    {
        return $this->onLoginSuccess($request, $responseCookies, $successfulAuthentication);
    }

    /**
     * @return void
     */
    public function loginFail(ServerRequestInterface $request, $responseCookies)
    {
        return $this->onLoginFail($request, $responseCookies);
    }

    protected function setCookie($value, ServerRequestInterface $request, $responseCookies)
    {
        $expires = time() + $this->lifetime;
        if($this->path) {
            $path = $this->path;
        } else {
            $path = $request->getUri()->getPath();
        }
        $responseCookies->set($this->cookieName,$value,$expires,$path,$this->domain,$this->secure,$this->httponly);
    }

    protected function cancelCookie(ServerRequestInterface $request, $responseCookies)
    {
        $responseCookies->set($this->cookieName);
    }

    public function debugLogging($message)
    {
        if($this->debug && $this->logger)
            $this->logger->debug($message);
    }
}

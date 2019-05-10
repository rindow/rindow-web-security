<?php
namespace Rindow\Web\Security\Authentication\Support;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Interop\Lenient\Security\Authentication\Authentication;
use Rindow\Security\Core\Authentication\Exception\AuthenticationException;
use Rindow\Web\Security\Authentication\Exception\InvalidCookieException;

class RememberMeUtility
{
    protected $rememberMeServices;
    protected $securityContext;
    protected $cookieContextFactory;
    protected $authenticationManager;

    public function __construct(
        $rememberMeServices=null,
        $securityContext=null,
        $cookieContextFactory=null,
        $authenticationManager=null) {
        if($rememberMeServices)
            $this->setRememberMeServices($rememberMeServices);
        if($securityContext)
            $this->setSecurityContext($securityContext);
        if($cookieContextFactory)
            $this->setCookieContextFactory($cookieContextFactory);
        if($authenticationManager)
            $this->setAuthenticationManager($authenticationManager);
    }

    public function setRememberMeServices($rememberMeServices)
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    public function setSecurityContext($securityContext)
    {
        $this->securityContext = $securityContext;
    }

    public function setCookieContextFactory($cookieContextFactory)
    {
        $this->cookieContextFactory = $cookieContextFactory;
    }

    public function setAuthenticationManager($authenticationManager)
    {
        $this->authenticationManager = $authenticationManager;
    }

    /**
     * @param  boolean  &$loggedin  This is output. Set True when auto login　success
     * @return Response Response with Login cookie or Cancel cookie
     */
    public function autoLogin(&$loggedin,ServerRequestInterface $request, ResponseInterface $response)
    {
        $responseCookie = $this->cookieContextFactory->create();
        try {
            $auth = $this->rememberMeServices->autoLogin($request,$responseCookie);
            if($auth==null) {
                $loggedin = false;
            } else {
                $this->authenticationManager->authenticate($auth);
                $this->securityContext->setAuthentication($auth);
                $loggedin = true;
            }
            return $responseCookie->addToResponse($response);
        } catch(AuthenticationException $e) {
            ;
        }
        $loggedin = false;
        $this->rememberMeServices->loginFail($request,$responseCookie);
        return $responseCookie->addToResponse($response);
    }

    /**
     * @return Response  response with remember-me cookie
     */
    public function loginSuccess(ServerRequestInterface $request, ResponseInterface $response,
            Authentication $successfulAuthentication)
    {
        $responseCookie = $this->cookieContextFactory->create();
        $this->rememberMeServices->loginSuccess($request,$responseCookie,$successfulAuthentication);
        return $responseCookie->addToResponse($response);
    }

    /**
     * @return Response  response with cancel cookie
     */
    public function loginFail(ServerRequestInterface $request, ResponseInterface $response)
    {
        $responseCookie = $this->cookieContextFactory->create();
        $this->rememberMeServices->loginFail($request,$responseCookie);
        return $responseCookie->addToResponse($response);
    }

    /**
     * @return Response  response with cancel cookie
     */
    public function logout(ServerRequestInterface $request, ResponseInterface $response,$path=null)
    {
        $responseCookie = $this->cookieContextFactory->create();
        $this->rememberMeServices->loginFail($request,$responseCookie);
        if(!$this->rememberMeServices->getPath() && $path)
            $responseCookie->get($this->rememberMeServices->getCookieName())->setPath($path);
        return $responseCookie->addToResponse($response);
    }
}

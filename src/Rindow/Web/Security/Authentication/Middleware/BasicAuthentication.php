<?php
namespace Rindow\Web\Security\Authentication\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Rindow\Security\Core\Authentication\Exception\AuthenticationException;

class BasicAuthentication extends AbstractAuthentication
{
    protected $realm;
    protected $anonymousAuthenticationProvider;
    protected $usernamePasswordAuthenticationProvider;

    public function __construct($securityContext=null,$authenticationTrustResolver=null,$anonymousAuthenticationProvider=null,$usernamePasswordAuthenticationProvider=null)
    {
        if($securityContext)
            $this->setSecurityContext($securityContext);
        if($authenticationTrustResolver)
            $this->setAuthenticationTrustResolver($authenticationTrustResolver);
        if($anonymousAuthenticationProvider)
            $this->setAnonymousAuthenticationProvider($anonymousAuthenticationProvider);
        if($usernamePasswordAuthenticationProvider)
            $this->setUsernamePasswordAuthenticationProvider($usernamePasswordAuthenticationProvider);
    }

    public function setAnonymousAuthenticationProvider($anonymousAuthenticationProvider)
    {
        $this->anonymousAuthenticationProvider = $anonymousAuthenticationProvider;
    }

    public function setUsernamePasswordAuthenticationProvider($usernamePasswordAuthenticationProvider)
    {
        $this->usernamePasswordAuthenticationProvider = $usernamePasswordAuthenticationProvider;
    }

    protected function initSecurityContext(ServerRequestInterface $request)
    {
        $userpass = $request->getHeaderLine('Authorization');
        if(empty($userpass)) {
            $token = $this->anonymousAuthenticationProvider->createToken();
        } else {
            list($type,$password) = explode(' ', $userpass);
            if($type!='Basic') {
                throw new AuthenticationException('Invalid Authentication Type.');
            }
            $password = explode(':',base64_decode($password));
            $username = array_shift($password);
            $password = implode(':', $password);
            $token = $this->usernamePasswordAuthenticationProvider->createToken($username,$password);
            $token = $this->usernamePasswordAuthenticationProvider->authenticate($token);
        }
        $this->getSecurityContext()->setAuthentication($token);
    }

    protected function exitSecurityContext(ServerRequestInterface $request,$response)
    {}
    protected function exceptionsSecurityContext(ServerRequestInterface $request,$response,$exception)
    {}

    protected function createTransitioner(ServerRequestInterface $request, ResponseInterface $response, \Exception $e)
    {
        if($this->realm)
            $realm = ' realm="'.$this->realm.'"';
        else
            $realm = '';
        $response = $response->withAddedHeader('WWW-Authenticate', 'Basic'.$realm);
        return $response;
    }
}
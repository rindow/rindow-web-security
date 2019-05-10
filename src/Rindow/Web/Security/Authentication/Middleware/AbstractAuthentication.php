<?php
namespace Rindow\Web\Security\Authentication\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Rindow\Security\Core\Authentication\Exception\AuthenticationException;
use Rindow\Security\Core\Authorization\Exception\AccessDeniedException;
use Rindow\Security\Core\Authorization\Exception\AuthenticationRequiredException;

abstract class AbstractAuthentication
{
    abstract protected function initSecurityContext(ServerRequestInterface $request);
    abstract protected function createTransitioner(ServerRequestInterface $request, ResponseInterface $response, \Exception $e);

    protected $securityContext;

    public function setSecurityContext($securityContext)
    {
        $this->securityContext = $securityContext;
    }

    public function getSecurityContext()
    {
        return $this->securityContext;
    }

    public function setAuthenticationTrustResolver($authenticationTrustResolver)
    {
        $this->authenticationTrustResolver = $authenticationTrustResolver;
    }

    public function getAuthenticationTrustResolver()
    {
        return $this->authenticationTrustResolver;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        try {
            $this->initSecurityContext($request);
            if(is_object($next))
                return $next->__invoke($request, $response);
            return call_user_func($next, $request, $response);
        } catch(AuthenticationException $e) {
            ;
        } catch(AuthenticationRequiredException $e) {
            ;
        } catch(AccessDeniedException $e) {
            $token = $this->getSecurityContext()->getAuthentication();
            if(!$this->getAuthenticationTrustResolver()->isAnonymous($token))
                throw $e;
        }
        $response = $this->createTransitioner($request, $response, $e);
        return $response;
    }
}

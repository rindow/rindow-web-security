<?php
namespace Rindow\Web\Security\Authentication\Middleware;

use SimpleXMLElement;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Rindow\Security\Core\Authentication\Exception\AuthenticationException;
use Rindow\Web\Security\Authentication\Exception;
use Rindow\Security\Core\Authorization\Exception\FullAuthenticationRequiredException;

class CookieAuthentication extends AbstractAuthentication
{
    protected $anonymousAuthenticationProvider;
    protected $loginUrl;
    protected $urlGenerator;

    public function __construct($securityContext=null,$authenticationTrustResolver=null,$anonymousAuthenticationProvider=null,$loginUrl=null,$urlGenerator=null)
    {
        if($securityContext)
            $this->setSecurityContext($securityContext);
        if($authenticationTrustResolver)
            $this->setAuthenticationTrustResolver($authenticationTrustResolver);
        if($anonymousAuthenticationProvider)
            $this->setAnonymousAuthenticationProvider($anonymousAuthenticationProvider);
        if($loginUrl)
            $this->setLoginUrl($loginUrl);
        if($urlGenerator)
            $this->setUrlGenerator($urlGenerator);
    }

    public function setAnonymousAuthenticationProvider($anonymousAuthenticationProvider)
    {
        $this->anonymousAuthenticationProvider = $anonymousAuthenticationProvider;
    }

    public function setLoginUrl($loginUrl)
    {
        $this->loginUrl = $loginUrl;
    }

    public function setUrlGenerator($urlGenerator)
    {
        $this->urlGenerator = $urlGenerator;
    }

    protected function initSecurityContext(ServerRequestInterface $request)
    {
        $token = $this->anonymousAuthenticationProvider->createToken();
        $this->getSecurityContext()->setDefaultAuthentication($token);
    }

    protected function exitSecurityContext(ServerRequestInterface $request,$response)
    {}

    protected function exceptionsSecurityContext(ServerRequestInterface $request,$response,$exception)
    {}

    protected function createTransitioner(ServerRequestInterface $request, ResponseInterface $response, \Exception $e)
    {
        if(!isset($this->loginUrl))
            throw new Exception\DomainException('Login URL is not specified.');
        if($e instanceof AuthenticationException)
            throw $e;
        $type = $this->determineContentType($request);
        if($type=='application/json') {
            return $this->renderJson($request, $response, $e);
        } elseif($type=='application/xml') {
            return $this->renderXml($request, $response, $e);
        } else {
            return $this->redirect($request,$response,$e);
        }
    }

    protected function determineContentType($request)
    {
        $accept = $request->getHeaderLine('Accept');
        if(!$accept) {
            $type = 'text/html';
            return $type;
        }
        $types = array(
            'text/html','text/plain',
            'application/json','application/xml');
        $firstPos = 100000;
        $type = 'text/plain';
        foreach ($types as $select) {
            $pos = strpos($accept, $select);
            if($pos===false)
                continue;
            if($firstPos>$pos) {
                $firstPos = $pos;
                $type = $select;
            }
        }
        if($firstPos==100000 && strpos($accept,'*/*')!==false)
            $type = 'text/html';
        return $type;
    }

    protected function redirect($request,$response,$e)
    {
        $query = array('redirectUri'=>strval($request->getUri()));
        if($e instanceof FullAuthenticationRequiredException)
            $query['fullauth'] = '1';
        if($this->urlGenerator) {
            $uri = $this->urlGenerator->fromPath(
                $this->loginUrl,
                array('query'=>$query));
        } else {
            $uri = $this->loginUrl.'?'.http_build_query($query);
        }
        $response = $response->withAddedHeader('Location', $uri);
        return $response->withStatus(302);
    }

    public function renderJson($request, $response, $e)
    {
        $json = array('error' => array(
            'message'=>'Authentication required.',
        ));
        $output = json_encode($json,defined('JSON_PARTIAL_OUTPUT_ON_ERROR') ? JSON_PARTIAL_OUTPUT_ON_ERROR : 0);
        $response->getBody()->write($output);
        $response = $response->withHeader('Content-Type','application/json');
        return $response->withStatus(403);
    }

    public function renderXml($request, $response, $e)
    {
        $error = new SimpleXMLElement("<?xml version='1.0' encoding='utf-8'?><error/>");
        $error->addChild('message','Authentication required.');
        $output = $error->asXml();
        $response->getBody()->write($output);
        $response = $response->withHeader('Content-Type','application/xml');
        return $response->withStatus(403);
    }
}
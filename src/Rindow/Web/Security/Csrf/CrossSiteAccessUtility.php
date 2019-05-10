<?php
namespace Rindow\Web\Security\Csrf;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

use Rindow\Web\Security\Csrf\Exception;

class CrossSiteAccessUtility
{
    protected $csrfToken;
    protected $cookieContextFactory;
    protected $allowHeaders = array(
        'Headers'=>true,
        'Origin'=>true,
        'Methods'=>true,
        'Credentials'=>true,
        'Max-Age'=>true,
    );

    public function setCsrfToken($csrfToken)
    {
        $this->csrfToken = $csrfToken;
    }

    public function setCookieContextFactory($cookieContextFactory)
    {
        $this->cookieContextFactory = $cookieContextFactory;
    }

    public function assertCsrfTokenHeader(ServerRequestInterface $request,array $headerNames=null,$postField=null)
    {
        if(in_array(strtoupper($request->getMethod()),array('GET','HEAD','OPTIONS'))) {
            return;
        }
        if($headerNames==null||count($headerNames)==0)
            $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $valid = false;
        foreach ($headerNames as $name) {
            $requestCsrf = implode(',', $request->getHeader($name));
            if(!empty($requestCsrf)) {
                if(!$this->csrfToken->isValid($requestCsrf))
                    throw new Exception\CsrfException('Illegal access.');
                $valid = true;
            }
        }
        if($valid)
            return;
        if($postField) {
            $post = $request->getParsedBody();
            if(isset($post[$postField])) {
                if($this->csrfToken->isValid($post[$postField]))
                    return;
            }
        }
        throw new Exception\CsrfException('Illegal access.');
    }

    public function addCsrfTokenCookie(ServerRequestInterface $request,ResponseInterface $response,array $cookieNames=null,$path=null)
    {
        if($cookieNames==null||count($cookieNames)==0)
            return $response;
        $responseCookies = $this->cookieContextFactory->create();
        $token = $this->csrfToken->generateToken();
        if($path==null)
            $path = '';
        foreach ($cookieNames as $name) {
            $responseCookies->set(
                $name,$token,$expires=0,$path);
                //$domain='',$secure=false,$httponly=false);
            $response = $responseCookies->addToResponse($response);
        }
        return $response;
    }

    protected function assertOrigin(ServerRequestInterface $request,array $allowOrigins=null)
    {
        $origin = implode(',', $request->getHeader('origin'));
        if(empty($origin))
            return;
        $uri = $request->getUri();
        if($uri) {
            $uri = $uri->withPath('')->withQuery('')->withFragment('');
            if(rtrim($origin,'/')==rtrim($uri,'/'))
                return;
        }
        if($allowOrigins==null)
            throw new Exception\CorsException('Cross site access is not allowed.');

        if(in_array('*',$allowOrigins))
            return;
        foreach ($allowOrigins as $allowOrigin) {
            if(strpos($origin, $allowOrigin)===0)
                return;
        }
        throw new Exception\CorsException('Cross site access is not allowed.');
    }

    protected function assertMethod(ServerRequestInterface $request,array $allowMethods=null)
    {
        $corsRequest = implode(',',$request->getHeader('Access-Control-Request-Method'));
        if(empty($corsRequest))
            return;
        if(!empty($allowMethods)) {
            if(in_array($corsRequest, $allowMethods))
                return;
        }
        throw new Exception\CorsException('Cross site access is not allowed.');
    }

    public function assertCorsHeaders(ServerRequestInterface $request,array $allowOrigins=null,array $allowMethods=null)
    {
        $this->assertOrigin($request,$allowOrigins);
        $this->assertMethod($request,$allowMethods);
    }

    public function addCorsHeaders(ServerRequestInterface $request,ResponseInterface $response,array $headers=null)
    {
        // To Add Headers example
        //'Access-Control-Allow-Headers'=>'Content-Type',
        //'Access-Control-Allow-Origin'=>'*',
        //'Access-Control-Allow-Methods'=>'GET,POST,PUT,DELETE,HEAD,OPTIONS',
        //'Access-Control-Allow-Credentials'=>'true',
        //'Access-Control-Max-Age'=>'3628800',

        if($headers==null)
            return $response;
        foreach ($headers as $name => $value) {
            if(!isset($this->allowHeaders[$name])) {
                $uri = $request->getUri();
                throw new Exception\DomainException('Invalid CORS Header type "'.$name.'" adding in '.$uri);
            }
            if($name=='Origin') {
                $name = 'Access-Control-Allow-Origin';
                if($value=='*') {
                    $t = implode(',', $request->getHeader('Origin'));
                    if(!empty($t)) {
                        $value = $t;
                    }
                }
            } elseif($name=='Max-Age') {
                $name = 'Access-Control-Max-Age';
            } else {
                $name = 'Access-Control-Allow-'.$name;
            }
            if($value===true)
                $value = 'true';
            $value = strval($value);
            $response = $response->withAddedHeader($name,$value);
        }
        return $response;
    }
}
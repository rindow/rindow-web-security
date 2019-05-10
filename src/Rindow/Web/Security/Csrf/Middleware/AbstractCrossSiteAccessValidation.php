<?php
namespace Rindow\Web\Security\Csrf\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

use Rindow\Web\Security\Csrf\Exception;

abstract class AbstractCrossSiteAccessValidation
{
    abstract protected function getRequiredValidationConfig(ServerRequestInterface $request);

    protected $crossSiteAccess;
    protected $logger;
    protected $debug;

    public function setCrossSiteAccess($crossSiteAccess)
    {
        $this->crossSiteAccess = $crossSiteAccess;
    }

    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    public function setDebug($debug)
    {
        $this->debug = $debug;
    }

    protected function logDebug($message)
    {
        if($this->debug && $this->logger) 
            $this->logger->debug($message);
    }

    protected function chooseSwitchableConfig($config,$propertyName)
    {
        if(!isset($config[$propertyName]))
            return null;
        $names = array();
        foreach ($config[$propertyName] as $name => $switch) {
            if($switch) {
                $names[] = $name;
            }
        }
        return $names;
    }

    protected function responseForbidden($e,$request,$response)
    {
        if(class_exists('Rindow\\Web\\Mvc\\Exception\\ForbiddenException'))
            throw new \Rindow\Web\Mvc\Exception\ForbiddenException($e->getMessage(),$e->getCode(),$e);
        $response->getBody()->write($e->getMessage());
        $response = $response->withStatus(403);
        $response = $response->withHeader('Content-Type','text/plain');
        return $response;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        $config = $this->getRequiredValidationConfig($request);
        if($config) {
            $allowOrigins = $this->chooseSwitchableConfig($config,'corsAllowOrigins');
            $corsAllowMethods = $this->chooseSwitchableConfig($config,'corsAllowMethods');
            try {
                $this->crossSiteAccess->assertCorsHeaders($request,$allowOrigins,$corsAllowMethods);
                $this->logDebug('assertCorsHeaders:success');
            } catch(Exception\RuntimeException $e) {
                $origin = implode(',', $request->getHeader('origin'));
                $this->logDebug('assertCorsHeaders:failed[Origin:'.$origin.']');
                return $this->responseForbidden($e,$request,$response);
            }
            $disableCsrfTokenValidation = isset($config['disableCsrfTokenValidation']) ? $config['disableCsrfTokenValidation'] : false;
            if(!$disableCsrfTokenValidation) {
                $headers = $this->chooseSwitchableConfig($config,'xsrfHeaderNames');
                $postField = isset($config['csrfPostField'])?$config['csrfPostField']:null;
                try {
                    $this->crossSiteAccess->assertCsrfTokenHeader($request,$headers,$postField);
                    $this->logDebug('assertCsrfTokenHeader:success');
                } catch(Exception\RuntimeException $e) {
                    $strtkn = '';
                    foreach($headers as $name) {
                        $strtkn .= '('.$name.':'.implode(',', $request->getHeader($name)).')';
                    }
                    $post = $request->getParsedBody();
                    if($postField && isset($post[$postField])) {
                        $strtkn .= '('.$postField.':'.$post[$postField].')';
                    }
                    $this->logDebug('assertCsrfTokenHeader:failed['.$strtkn.']');
                    return $this->responseForbidden($e,$request,$response);
                }
            }
        }
        if(is_object($next))
            $newResponse = $next->__invoke($request, $response);
        else
            $newResponse = call_user_func($next, $request, $response);
        if(!($newResponse instanceof ResponseInterface)) {
            $type = is_object($newResponse) ? get_class($newResponse) : gettype($newResponse);
            throw new Exception\InvalidArgumentException('response is invalid type:'.$type);
        }
        $response = $newResponse;
        if($config) {
            $cookieNames = $this->chooseSwitchableConfig($config,'xsrfCookieNames');
            $cookiePath = isset($config['xsrfCookiePath']) ? $config['xsrfCookiePath'] : '';
            $response = $this->crossSiteAccess->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
            $strnames = implode(',', $cookieNames);
            $strtkn = implode(',', $response->getHeader('Set-Cookie'));
            $this->logDebug('addCsrfTokenCookie:'.$strnames.'[Set-Cookie:'.$strtkn.']');
            $origin = $request->getHeader('Origin');
            if(!empty($origin)) {
                $headers = isset($config['corsHeaders'])?$config['corsHeaders']:null;
                $response = $this->crossSiteAccess->addCorsHeaders($request,$response,$headers);
                $strtkn = empty($headers)?'':implode(',', array_keys($headers));
                $this->logDebug('addCorsHeaders:'.$strtkn);
            }
        }
        return $response;
    }
}

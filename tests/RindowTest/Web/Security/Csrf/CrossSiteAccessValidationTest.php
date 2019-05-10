<?php
namespace RindowTest\Web\Security\Csrf\CrossSiteAccessValidationTest;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Rindow\Web\Http\Cookie\GenericCookieContextFactory;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;
use Rindow\Web\Security\Csrf\CrossSiteAccessUtility;
use Rindow\Web\Security\Csrf\Middleware\CrossSiteAccessValidation;
use Rindow\Web\Mvc\HttpMessageAttribute;

class TestToken
{
    public $token = 'foo';
    public function generateToken()
    {
        return $this->token;
    }
    public function isValid($token)
    {
        return ($token==$this->token) ? true : false;
    }
}

class TestMiddleware
{
    public function __invoke($request,$response)
    {
        return $response;
    }
}

class Test extends TestCase
{
    public function getMiddleware(array $customConfig=null)
    {
        $config = array(
            'default' => array(
                'xsrfHeaderNames' => array(
                    'X-XSRF-TOKEN'=>true,
                    'X-CSRF-TOKEN'=>true,
                ),
                'xsrfCookieNames' => array(
                    'XSRF-TOKEN' => true,
                ),
                'xsrfCookiePath' => '/test',
            ),
            'checkAll' => array(
                'xsrfHeaderNames' => array(
                    'X-XSRF-TOKEN'=>true,
                    'X-CSRF-TOKEN'=>true,
                ),
                'xsrfCookieNames' => array(
                    'XSRF-TOKEN' => true,
                ),
                'xsrfCookiePath' => '/test',
                'corsAllowOrigins' => array(
                    '*' => true,
                ),
                'corsHeaders' => array(
                    'Origin'=>'*',
                    'Methods'=>'GET,POST,PUT,DELETE,OPTIONS,HEAD',
                    'Credentials'=>'true',
                    // If you needs
                    //'Headers'=>'Content-Type',
                    //'Max-Age'=>'3628800',
                ),

            ),
            'public' => array(
                'disableCsrfTokenValidation' => true,
                'xsrfHeaderNames' => array(
                    'X-XSRF-TOKEN'=>false,
                    'X-CSRF-TOKEN'=>false,
                ),
                'xsrfCookieNames' => array(
                    'XSRF-TOKEN' => false,
                ),
                'xsrfCookiePath' => '/test',
                'corsAllowOrigins' => array(
                    '*' => true,
                ),
                'corsHeaders' => array(
                    'Origin'=>'*',
                    'Methods'=>'GET,POST,PUT,DELETE,OPTIONS,HEAD',
                    'Credentials'=>'true',
                    // If you needs
                    //'Headers'=>'Content-Type',
                    //'Max-Age'=>'3628800',
                ),

            ),
        );
        if($customConfig) {
            $config = array_replace_recursive($config, $customConfig);
        }
        $csrfToken = new TestToken();
        $cookieContextFactory = new GenericCookieContextFactory();
        $utility = new CrossSiteAccessUtility();
        $utility->setCsrfToken($csrfToken);
        $utility->setCookieContextFactory($cookieContextFactory);
        $middleware = new CrossSiteAccessValidation();
        $middleware->setConfig($config);
        $middleware->setCrossSiteAccess($utility);
        $next = new TestMiddleware();
        return array($middleware,$next);
    }

    public function testValidDefaultGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));


        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = array('xsrf-token'=>'boo'),
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
        $this->assertEquals(array(),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }

    public function testValidDefaultOtherThanGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'foo')
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
        $this->assertEquals(array(),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }

    /**
     * @expectedException        Rindow\Web\Mvc\Exception\ForbiddenException
     * @expectedExceptionMessage Illegal access
     */
    public function testNoTokenDefaultOtherThanGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='POST',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }

    /**
     * @expectedException        Rindow\Web\Mvc\Exception\ForbiddenException
     * @expectedExceptionMessage Illegal access
     */
    public function testInvalidTokenDefaultOtherThanGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'boo')
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }

    /**
     * @expectedException        Rindow\Web\Mvc\Exception\ForbiddenException
     * @expectedExceptionMessage Cross site access is not allowed
     */
    public function testValidDefaultGetFromCrossOrigin()
    {
        list($middleware,$next) = $this->getMiddleware();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>'http://localhost:8000/')
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }

    public function testValidPublicGetFromCrossOrigin()
    {
        list($middleware,$next) = $this->getMiddleware();

        $route = array('view'=>'checkAll');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = array(HttpMessageAttribute::ROUTING_INFORMATION=>$route),
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://localhost:8000/'))
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
        $this->assertEquals(array('http://localhost:8000/'),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }

    public function testValidPublicOtherThanGetFromCrossOrigin()
    {
        list($middleware,$next) = $this->getMiddleware();

        $route = array('view'=>'checkAll');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = array(HttpMessageAttribute::ROUTING_INFORMATION=>$route),
            $uri = null,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'foo','Origin'=>array('http://localhost:8000/'))
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
        $this->assertEquals(array('http://localhost:8000/'),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }

    /**
     * @expectedException        Rindow\Web\Mvc\Exception\ForbiddenException
     * @expectedExceptionMessage Illegal access
     */
    public function testNoTokenPublicOtherThanGetFromCrossOrigin()
    {
        list($middleware,$next) = $this->getMiddleware();

        $route = array('view'=>'checkAll');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = array(HttpMessageAttribute::ROUTING_INFORMATION=>$route),
            $uri = null,
            $method='POST',
            $body=null,
            $headers=array('Origin'=>array('http://localhost:8000/'))
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }

    /**
     * @expectedException        Rindow\Web\Mvc\Exception\ForbiddenException
     * @expectedExceptionMessage Illegal access
     */
    public function testInvalidTokenPublicOtherThanGetFromCrossOrigin()
    {
        list($middleware,$next) = $this->getMiddleware();

        $route = array('view'=>'checkAll');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = array(HttpMessageAttribute::ROUTING_INFORMATION=>$route),
            $uri = null,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'boo','Origin'=>array('http://localhost:8000/'))
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }

    public function testValidPublicGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $route = array('view'=>'checkAll');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = array(HttpMessageAttribute::ROUTING_INFORMATION=>$route),
            $uri = null,
            $method='GET',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
        $this->assertEquals(array(),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }

    public function testDisableCsrfTokenValidation()
    {
        list($middleware,$next) = $this->getMiddleware();

        $route = array('view'=>'public');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = array(HttpMessageAttribute::ROUTING_INFORMATION=>$route),
            $uri = null,
            $method='POST',
            $body=null,
            $headers=array('Origin'=>array('http://localhost:8000/'))
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('http://localhost:8000/'),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }
}

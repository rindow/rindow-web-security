<?php
namespace RindowTest\Web\Security\Csrf\ForceXsrfTokenValidationTest;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Rindow\Web\Http\Cookie\GenericCookieContextFactory;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;
use Rindow\Web\Http\Message\Uri;
use Rindow\Web\Security\Csrf\CrossSiteAccessUtility;
use Rindow\Web\Security\Csrf\Middleware\ForceXsrfTokenValidation;
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
            'xsrfHeaderNames' => array(
                'X-XSRF-TOKEN'=>true,
                'X-CSRF-TOKEN'=>true,
            ),
            'xsrfCookieNames' => array(
                'XSRF-TOKEN' => true,
            ),
            'xsrfCookiePath' => '/test',
            'csrfPostField' => 'csrf_token',
            // 'excludingPaths' => array(
            //     '/path/path' => true,
            // ),
        );
        if($customConfig) {
            $config = array_replace_recursive($config, $customConfig);
        }
        $csrfToken = new TestToken();
        $cookieContextFactory = new GenericCookieContextFactory();
        $utility = new CrossSiteAccessUtility();
        $utility->setCsrfToken($csrfToken);
        $utility->setCookieContextFactory($cookieContextFactory);
        $middleware = new ForceXsrfTokenValidation();
        $middleware->setConfig($config);
        $middleware->setCrossSiteAccess($utility);
        $next = new TestMiddleware();
        return array($middleware,$next);
    }

    public function testValidDefaultGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $uri = new Uri('http://localhost:8000');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='GET',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    public function testValidDefaultOtherThanGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $uri = new Uri('http://localhost:8000');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'foo')
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
        $this->assertEquals(array(),$newResponse->getHeader('Access-Control-Allow-Origin'));
    }

    public function testValidFormDefaultOtherThanGetFromLocal()
    {
        list($middleware,$next) = $this->getMiddleware();

        $uri = new Uri('http://localhost:8000');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = array('csrf_token'=>'foo'),
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=null
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

        $uri = new Uri('http://localhost:8000');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }

    public function testValidDefaultGetFromLocalInsideExcludingPaths()
    {
        $config = array('excludingPaths'=>array('/nocheck'=>true));
        list($middleware,$next) = $this->getMiddleware($config);

        $uri = new Uri('http://localhost:8000/nocheck');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='GET',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array(),$newResponse->getHeader('Set-Cookie'));
    }

    public function testValidDefaultOtherThanGetFromLocalInsideExcludingPaths()
    {
        $config = array('excludingPaths'=>array('/nocheck'=>true));
        list($middleware,$next) = $this->getMiddleware($config);

        $uri = new Uri('http://localhost:8000/nocheck');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'foo')
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array(),$newResponse->getHeader('Set-Cookie'));
    }

    public function testNoTokenDefaultOtherThanGetFromLocalInsideExcludingPaths()
    {
        $config = array('excludingPaths'=>array('/nocheck'=>true));
        list($middleware,$next) = $this->getMiddleware($config);

        $uri = new Uri('http://localhost:8000/nocheck');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array(),$newResponse->getHeader('Set-Cookie'));
    }

    public function testValidDefaultGetFromLocalOutsideExcludingPaths()
    {
        $config = array('excludingPaths'=>array('/nocheck'=>true));
        list($middleware,$next) = $this->getMiddleware($config);

        $uri = new Uri('http://localhost:8000/');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='GET',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    public function testValidDefaultOtherThanGetFromLocalOutsideExcludingPaths()
    {
        $config = array('excludingPaths'=>array('/nocheck'=>true));
        list($middleware,$next) = $this->getMiddleware($config);

        $uri = new Uri('http://localhost:8000/');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=array('x-xsrf-token'=>'foo')
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    /**
     * @expectedException        Rindow\Web\Mvc\Exception\ForbiddenException
     * @expectedExceptionMessage Illegal access
     */
    public function testNoTokenDefaultOtherThanGetFromLocalOutsideExcludingPaths()
    {
        $config = array('excludingPaths'=>array('/nocheck'=>true));
        list($middleware,$next) = $this->getMiddleware($config);

        $uri = new Uri('http://localhost:8000/');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='POST',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $newResponse = $middleware->__invoke($request,$response,$next);
    }
}

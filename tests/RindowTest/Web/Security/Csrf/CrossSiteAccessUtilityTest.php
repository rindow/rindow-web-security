<?php
namespace RindowTest\Web\Security\Csrf\CrossSiteAccessUtilityTest;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Rindow\Web\Http\Cookie\GenericCookieContextFactory;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;
use Rindow\Web\Http\Message\Uri;
use Rindow\Web\Security\Csrf\CrossSiteAccessUtility;

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

class Test extends TestCase
{
	public function getUtility($config=null)
	{
		$csrfToken = new TestToken();
		$cookieContextFactory = new GenericCookieContextFactory();
		$utility = new CrossSiteAccessUtility();
		$utility->setCsrfToken($csrfToken);
		$utility->setCookieContextFactory($cookieContextFactory);

		return $utility;
	}

	public function testGetValidCsrfToken()
    {
    	$utility = $this->getUtility();

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

        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames);
        $this->assertTrue(true);
        $cookieNames = array('XSRF-TOKEN');
        $cookiePath = '/test';
        $newResponse = $utility->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
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
            $headers=array('X-XSRF-TOKEN'=>array('boo'))
        );
        $response = new Response();

        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames);
        $this->assertTrue(true);
        $cookieNames = array('XSRF-TOKEN');
        $cookiePath = '/test';
        $newResponse = $utility->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    public function testNoneGetValidCsrfToken()
    {
    	$utility = $this->getUtility();

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
        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames);
        $this->assertTrue(true);
        $cookieNames = array('XSRF-TOKEN');
        $cookiePath = '/test';
        $newResponse = $utility->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\RuntimeException
     * @expectedExceptionMessage Illegal access
     */
    public function testNoneGetNoHeaderCsrfToken()
    {
    	$utility = $this->getUtility();

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
        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames);
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\RuntimeException
     * @expectedExceptionMessage Illegal access
     */
    public function testNoneGetInvalidToken()
    {
    	$utility = $this->getUtility();

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
        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames);
    }

    public function testPostFieldValidCsrfToken()
    {
        $utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = array('csrf-token'=>'foo'),
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='POST',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $postField = 'csrf-token';
        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames,$postField);
        $this->assertTrue(true);
        $cookieNames = array('XSRF-TOKEN');
        $cookiePath = '/test';
        $newResponse = $utility->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\RuntimeException
     * @expectedExceptionMessage Illegal access
     */
    public function testPostFieldNoCsrfToken()
    {
        $utility = $this->getUtility();

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
        $postField = 'csrf-token';
        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames,$postField);
        $this->assertTrue(true);
        $cookieNames = array('XSRF-TOKEN');
        $cookiePath = '/test';
        $newResponse = $utility->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\RuntimeException
     * @expectedExceptionMessage Illegal access
     */
    public function testPostFieldInvalidCsrfToken()
    {
        $utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = array('csrf-token'=>'invalidToken'),
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri = null,
            $method='POST',
            $body=null,
            $headers=null
        );
        $response = new Response();
        $postField = 'csrf-token';
        $headerNames = array('X-XSRF-TOKEN','X-CSRF-TOKEN');
        $utility->assertCsrfTokenHeader($request,$headerNames,$postField);
        $this->assertTrue(true);
        $cookieNames = array('XSRF-TOKEN');
        $cookiePath = '/test';
        $newResponse = $utility->addCsrfTokenCookie($request,$response,$cookieNames,$cookiePath);
        $this->assertEquals(array('XSRF-TOKEN=foo; Path=/test'),$newResponse->getHeader('Set-Cookie'));
    }

	public function testNoOriginCorsHeaders()
    {
    	$utility = $this->getUtility();

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
        $allows = array('http://localhost:8000');
        $utility->assertCorsHeaders($request,$allows);
        $this->assertTrue(true);
    }

    public function testSameOriginCorsHeaders()
    {
        $utility = $this->getUtility();

        $uri = new Uri('http://localhost:8000/check?test=test#abc');
        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = null,
            $attributes = null,
            $uri,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://localhost:8000'))
        );
        $allows = null;
        $utility->assertCorsHeaders($request,$allows);
        $this->assertTrue(true);
    }

	public function testAllowsAnyOriginCorsHeaders()
    {
    	$utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = array('xsrf-token'=>'boo'),
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://foo.bar.com/test'))
        );

        $allows = array('baz','*');
        $utility->assertCorsHeaders($request,$allows);
        $this->assertTrue(true);
    }

	public function testAllowsSpecifiedOriginCorsHeaders()
    {
    	$utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = array('xsrf-token'=>'boo'),
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://foo.bar.com/test'))
        );

        $allows = array('baz','http://foo.bar.com/test');
        $utility->assertCorsHeaders($request,$allows);
        $this->assertTrue(true);
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\RuntimeException
     * @expectedExceptionMessage Cross site access is not allowed
     */
	public function testDenyAllOriginCorsHeaders()
    {
    	$utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = array('xsrf-token'=>'boo'),
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://foo.bar.com/test'))
        );

        $allows = null;
        $utility->assertCorsHeaders($request,$allows);
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\RuntimeException
     * @expectedExceptionMessage Cross site access is not allowed
     */
	public function testDenyOriginCorsHeaders()
    {
    	$utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = array('xsrf-token'=>'boo'),
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://foo.bar.com/test'))
        );

        $allows = array('http://localhost:8000');
        $utility->assertCorsHeaders($request,$allows);
    }

	public function testAddCorsHeaders()
    {
    	$utility = $this->getUtility();

        $request = new ServerRequest(
            $serverParams = null,
            $parsedBody = null,
            $uploadedParams = null,
            $cookieParams = array('xsrf-token'=>'boo'),
            $attributes = null,
            $uri = null,
            $method='GET',
            $body=null,
            $headers=array('Origin'=>array('http://foo.bar.com/'))
        );
        $response = new Response();

        $headers = array(
        	'Headers'=>'Content-Type',
        	'Origin'=>'*',
        	'Methods'=>'GET,POST,PUT,DELETE,OPTIONS',
        	'Credentials'=>true,
        	'Max-Age'=>3628800,
        );
        $newResponse = $utility->addCorsHeaders($request,$response,$headers);
        $this->assertEquals(array('Content-Type'),$newResponse->getHeader('Access-Control-Allow-Headers'));
        $this->assertEquals(array('http://foo.bar.com/'),$newResponse->getHeader('Access-Control-Allow-Origin'));
        $this->assertEquals(array('GET,POST,PUT,DELETE,OPTIONS'),$newResponse->getHeader('Access-Control-Allow-Methods'));
        $this->assertEquals(array('true'),$newResponse->getHeader('Access-Control-Allow-Credentials'));
        $this->assertEquals(array('3628800'),$newResponse->getHeader('Access-Control-Max-Age'));
    }
}
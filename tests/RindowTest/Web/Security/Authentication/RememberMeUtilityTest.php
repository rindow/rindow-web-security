<?php
namespace RindowTest\Web\Security\Authentication\RememberMeUtilityTest;

use PHPUnit\Framework\TestCase;
use Rindow\Web\Http\Message\ServerRequestFactory;
use Rindow\Web\Http\Message\TestModeEnvironment;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;
use Rindow\Web\Http\Cookie\GenericCookieContextFactory;

use Rindow\Security\Core\Authentication\UserDetails\UserManager\InMemoryUserDetailsManager;
use Rindow\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Security\Core\Authentication\Support\SecurityContext;
use Rindow\Security\Core\Authentication\Provider\RememberMeAuthenticationProvider;

use Rindow\Web\Security\Authentication\RememberMe\TokenBasedRememberMeServices;
use Rindow\Web\Security\Authentication\Support\RememberMeUtility;
use Rindow\Stdlib\Dict;

class TestLogger
{
    protected $log = array();
    public function debug($message)
    {
        $this->log[] = $message;
    }
    public function getLog()
    {
        return $this->log;
    }
}

class TestRememberMeAuthenticationProvider extends RememberMeAuthenticationProvider
{
    public function replaceKeyForTest($key)
    {
        $this->keyHash = sha1($key);
    }
}

class Test extends TestCase
{
    public function setup()
    {
    }

	public function getUsers()
	{
		$users = array(
            'foo' => array(
                'id' => 1,
                // 'password' => 'fooPass',
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
            'test' => array(
                'id' => 2,
                'password' => 'aaa',
                'roles' => array('USER'),
            ),
		);
		return $users;
	}

	public function getRequest($env)
	{
        $env->_SERVER['SERVER_NAME'] = 'localhost';
        $env->_SERVER['SCRIPT_NAME'] = '/subdir/index.php';
        $env->_SERVER['REQUEST_URI'] = '/subdir/deny';
        $env->_SERVER['REQUEST_METHOD'] = 'GET';
        $request = ServerRequestFactory::fromTestEnvironment($env);
        //var_dump($request);
        return $request;
	}

	public function getUtility()
	{
    	$userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $authenticationManager = new TestRememberMeAuthenticationProvider('test');
        $rememberMeServices = new TokenBasedRememberMeServices($userDetailsService,$authenticationManager);
        $securityContext = new SecurityContext(new Dict(),'key');
        $cookieContextFactory = new GenericCookieContextFactory();
        $utility = new RememberMeUtility($rememberMeServices,$securityContext,$cookieContextFactory,$authenticationManager);
        return array($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager);
	}

    public function setCookieEnv($response,$env)
    {
        $headers = $response->getHeader('Set-Cookie');
        $s = strpos($headers[0],'=');
        $name  = substr($headers[0], 0, $s);
        $value = substr($headers[0], $s+1);
        $s = strpos($value,';');
        $value = substr($value, 0,$s);

        $this->assertEquals('remember-me',$name);
        $env->_COOKIE['remember-me'] = $value;
    }

    public function testLoginSuccess()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');

        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);
        $response = new Response();
        $userAuthMgr = new DaoAuthenticationProvider($userDetailsService);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $userAuthMgr->authenticate($auth);
        $response = $utility->loginSuccess($request,$response,$auth);
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(1,$headers);
        $this->assertStringStartsWith('remember-me=',$headers[0]);
        $this->assertStringStartsNotWith('remember-me=deleted',$headers[0]);
    }

    public function testLoginFail()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');

        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);
        $response = new Response();
        $response = $utility->loginFail($request,$response);
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(1,$headers);
        $this->assertStringStartsWith('remember-me=deleted',$headers[0]);
    }

    public function testAutoLoginSuccessWithTokenBasedRememberMe()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');

        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);
        $response = new Response();
        $userAuthMgr = new DaoAuthenticationProvider($userDetailsService);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $userAuthMgr->authenticate($auth);
        $response = $utility->loginSuccess($request,$response,$auth);

        // Autologin
        $this->setCookieEnv($response,$env);

        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');

        $request = $this->getRequest($env);
        $response = new Response();

        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);

        $response = $utility->autoLogin($loggedin,$request,$response);
        $this->assertTrue($loggedin);
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(0,$headers);
        $auth = $securityContext->getAuthentication();
        $this->assertInstanceOf('Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken',$auth);
        $this->assertEquals('foo',$auth->getName());
        $this->assertEquals(array('ROLE_ADMIN'),$auth->getAuthorities());
    }

    public function testAutoLoginNoCookieWithTokenBasedRememberMe()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');

        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);
        $response = new Response();

        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);

        $response = $utility->autoLogin($loggedin,$request,$response);
        $this->assertFalse($loggedin);
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(0,$headers);
        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);
    }

    public function testAutoLoginExpiredWithTokenBasedRememberMe()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');
        $env = new TestModeEnvironment();
        $rememberMeServices->setConfig(array('lifetime'=>-60));
        $request = $this->getRequest($env);
        $response = new Response();
        $userAuthMgr = new DaoAuthenticationProvider($userDetailsService);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $userAuthMgr->authenticate($auth);
        $response = $utility->loginSuccess($request,$response,$auth);

        // Autologin
        $this->setCookieEnv($response,$env);

        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');

        $request = $this->getRequest($env);
        $response = new Response();

        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);

        $response = $utility->autoLogin($loggedin,$request,$response);
        $this->assertFalse($loggedin);
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(1,$headers);// cancel cookie
        $this->assertStringStartsWith('remember-me=deleted',$headers[0]);
        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);
    }


    //
    // "autherror" of RememberMeAuthProvider can not happen in "autologin"
    //
/*
    public function testAutoLoginAuthErrorWithTokenBasedRememberMe()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');
        $request = $this->getRequest();
        $response = new Response();
        $userAuthMgr = new DaoAuthenticationProvider($userDetailsService);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $userAuthMgr->authenticate($auth);
        $response = $utility->loginSuccess($request,$response,$auth);

        // Autologin
        $this->setCookieEnv($response,$env);

        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');
        $authenticationManager->replaceKeyForTest('xxx');

        $request = $this->getRequest();
        $response = new Response();

        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);

        $response = $utility->autoLogin($loggedin,$request,$response);
        $this->assertFalse($loggedin);
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(1,$headers);// cancel cookie
        $this->assertStringStartsWith('remember-me=deleted',$headers[0]);
        $auth = $securityContext->getAuthentication();
        $this->assertNull($auth);
    }
*/
    public function testLogout()
    {
        list($utility,$userDetailsService,$securityContext,$rememberMeServices,$authenticationManager)
            = $this->getUtility('token');
        $env = new TestModeEnvironment();

        $request = $this->getRequest($env);
        $response = new Response();
        $response = $utility->logout($request,$response,'/loginPath');
        $headers = $response->getHeader('Set-Cookie');
        $this->assertCount(1,$headers);
        $this->assertStringStartsWith('remember-me=deleted',$headers[0]);
        $this->assertContains('Path=/loginPath',$headers[0]);
    }
}

<?php
namespace RindowTest\Web\Security\Authentication\TokenBasedRememberMeServicesTest;

use PHPUnit\Framework\TestCase;
use Rindow\Web\Http\Message\ServerRequestFactory;
use Rindow\Web\Http\Message\TestModeEnvironment;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;
use Rindow\Web\Http\Cookie\GenericCookieManager;

use Rindow\Security\Core\Authentication\UserDetails\UserManager\InMemoryUserDetailsManager;
use Rindow\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Rindow\Security\Core\Authentication\Provider\RememberMeAuthenticationProvider;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Web\Security\Authentication\RememberMe\TokenBasedRememberMeServices;


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

    public function testLoginSuccess()
    {
    	$userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
    	$services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
    	$request = $this->getRequest($env);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $authProvider->authenticate($auth);
        $services->loginSuccess($request,$responseCookies,$auth);
        $now = time();
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        $cookieValue = $cookies['remember-me']->getValue();
        list($username,$expires,$signedCookie) = explode(':',base64_decode($cookieValue));
        $username = base64_decode($username);
        $this->assertEquals('foo',$username);
        $this->assertTrue((abs((30*24*3600)-($expires-$now))<2)?true:false); // 30 days
        $user = $userDetailsService->loadUserByUsername($username);
        $password = $user->getPassword();
        $hash = hash_hmac('sha256', $username.$password.$expires, 'test');
        $this->assertEquals($hash,$signedCookie);
        $this->assertTrue((abs((30*24*3600)-($cookies['remember-me']->getExpires()-$now))<2)?true:false); // 30 days
        $this->assertEquals('/subdir/deny',$cookies['remember-me']->getPath());
        $this->assertFalse($cookies['remember-me']->getSecure());
        $this->assertTrue($cookies['remember-me']->getHttponly());
    }

    public function testLoginFail()
    {
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $services->loginFail($request,$responseCookies);
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        $this->assertEquals('',$cookies['remember-me']->getValue());
    }

    public function testAutoLoginNoCookie()
    {
        // autologin        
        $env = new TestModeEnvironment();
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $auth = $services->autoLogin($request,$responseCookies);
        $this->assertNull($auth);
        $this->assertCount(0,$responseCookies->getAll());
    }

    public function testAutoLoginNormal()
    {
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $authProvider->authenticate($auth);
        $services->loginSuccess($request,$responseCookies,$auth);
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        // autologin
        $env = new TestModeEnvironment();
        $env->_COOKIE['remember-me'] = $cookies['remember-me']->getValue();
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $request = $this->getRequest($env);

        $auth = $services->autoLogin($request,$responseCookies);
        $this->assertInstanceOf('Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken',$auth);
        $this->assertEquals('foo',$auth->getName());
        $this->assertEquals(array('ROLE_ADMIN'),$auth->getAuthorities());
        $this->assertTrue($auth->isAuthenticated());
        $this->assertCount(0,$responseCookies->getAll());
    }

    public function testAutoLoginExpired()
    {
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $services->setConfig(array('lifetime' => -60));
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $authProvider->authenticate($auth);
        $services->loginSuccess($request,$responseCookies,$auth);
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        // autologin        
        $env = new TestModeEnvironment();
        $env->_COOKIE['remember-me'] = $cookies['remember-me']->getValue();
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $logger = new TestLogger();
        $services->setLogger($logger);
        $services->setDebug(true);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $request = $this->getRequest($env);

        $auth = $services->autoLogin($request,$responseCookies);
        $this->assertNull($auth);
        $this->assertCount(1,$responseCookies->getAll());
        $this->assertEquals('',$responseCookies->get('remember-me')->getValue());
        $log = $logger->getLog();
        $this->assertEquals(array('Rindow\\Web\\Security\\Authentication\\Exception\\InvalidCookieException: Cookie has expired'),$log);
    }

    public function testAutoLoginInvalidSigneture()
    {
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $authProvider->authenticate($auth);
        $services->loginSuccess($request,$responseCookies,$auth);
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        // autologin        
        $env = new TestModeEnvironment();
        $env->_COOKIE['remember-me'] = $cookies['remember-me']->getValue();
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $user = new User('foo','xxx',array('ROLE_ADMIN'));
        $userDetailsService->updateUser($user);

        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $logger = new TestLogger();
        $services->setLogger($logger);
        $services->setDebug(true);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $request = $this->getRequest($env);

        $auth = $services->autoLogin($request,$responseCookies);
        $this->assertNull($auth);
        $this->assertCount(1,$responseCookies->getAll());
        $this->assertEquals('',$responseCookies->get('remember-me')->getValue());
        $log = $logger->getLog();
        $this->assertEquals(array('Rindow\\Web\\Security\\Authentication\\Exception\\InvalidCookieException: Cookie contained invalid signature'),$log);
    }

    public function testAutoLoginUserNotFound()
    {
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $authProvider->authenticate($auth);
        $services->loginSuccess($request,$responseCookies,$auth);
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        // autologin        
        $env = new TestModeEnvironment();
        $env->_COOKIE['remember-me'] = $cookies['remember-me']->getValue();
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $userDetailsService->deleteUser('foo');

        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $logger = new TestLogger();
        $services->setLogger($logger);
        $services->setDebug(true);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $request = $this->getRequest($env);

        $auth = $services->autoLogin($request,$responseCookies);
        $this->assertNull($auth);
        $this->assertCount(1,$responseCookies->getAll());
        $this->assertEquals('',$responseCookies->get('remember-me')->getValue());
        $log = $logger->getLog();
        $this->assertEquals(array('Rindow\\Security\\Core\\Authentication\\Exception\\UsernameNotFoundException: foo'),$log);
    }

    public function testAutoLoginInvalidUserStatus()
    {
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $env = new TestModeEnvironment();
        $request = $this->getRequest($env);

        $auth = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $auth = $authProvider->authenticate($auth);
        $services->loginSuccess($request,$responseCookies,$auth);
        $cookies = $responseCookies->getAll();
        $this->assertCount(1,$cookies);

        // autologin        
        $env = new TestModeEnvironment();
        $env->_COOKIE['remember-me'] = $cookies['remember-me']->getValue();
        $userDetailsService = new InMemoryUserDetailsManager($this->getUsers());
        $oldUser = $userDetailsService->loadUserByUsername('foo');
        $user = new User('foo',$oldUser->getPassword(),array('ROLE_ADMIN'),1,false);
        $userDetailsService->updateUser($user);

        $authProvider = new DaoAuthenticationProvider($userDetailsService);
        $rememberMeAuthenticationProvider = new RememberMeAuthenticationProvider('secret');
        $services = new TokenBasedRememberMeServices($userDetailsService,$rememberMeAuthenticationProvider);
        $logger = new TestLogger();
        $services->setLogger($logger);
        $services->setDebug(true);
        $responseCookies = new GenericCookieManager();
        $services->setSecret('test');
        $request = $this->getRequest($env);

        $auth = $services->autoLogin($request,$responseCookies);
        $this->assertNull($auth);
        $this->assertCount(1,$responseCookies->getAll());
        $this->assertEquals('',$responseCookies->get('remember-me')->getValue());
        $log = $logger->getLog();
        $this->assertEquals(array('Rindow\\Security\\Core\\Authentication\\Exception\\DisabledException: User is disabled'),$log);
    }

}

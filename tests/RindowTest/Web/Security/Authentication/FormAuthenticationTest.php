<?php
namespace RindowTest\Web\Security\Authentication\FormAuthenticationTest;

use PHPUnit\Framework\TestCase;
use Rindow\Web\Http\Message\ServerRequestFactory;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;

use Interop\Lenient\Security\Authentication\AuthenticationManager;
use Rindow\Security\Core\Authentication\Support\AuthenticationTrustResolver;
use Rindow\Security\Core\Authentication\Support\SecurityContext;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authorization\Exception\AccessDeniedException;
use Rindow\Security\Core\Authorization\Exception\FullAuthenticationRequiredException;
use Rindow\Web\Security\Authentication\Middleware\BasicAuthentication;
use Rindow\Stdlib\Dict;
use Rindow\Container\ModuleManager;
use Rindow\Web\Security\Authentication\FormAuthModule;

class TestInvocator
{
    protected $exception;
    protected $securityContext;
    protected $principal;

    public function setException($exception)
    {
        $this->exception = $exception;
    }

    public function setSecurityContext($securityContext)
    {
        $this->securityContext = $securityContext;
    }

    public function __invoke($request,$response)
    {
        $auth = $this->securityContext->getAuthentication();
        if($auth==null)
            throw new \Exception('null authentication');
            
        $this->principal = $auth->getPrincipal();
        if($this->exception)
            throw $this->exception;
        return $response;
    }

    public function getPrincipal()
    {
        return $this->principal;
    }
}

class TestAuthenticationProviderManager implements AuthenticationManager
{
    public function authenticate(/*AuthenticationToken*/$token)
    {
        return $token;
    }
}

class MyHandler
{
    public function allowAction($request,$response,$args)
    {
        return $response;
    }

    public function denyAction($request,$response,$args)
    {
        throw new AccessDeniedException("Deny");
    }
}

class Test extends TestCase
{
    private $output;
    private $entryPoint;
    private $moduleManager;

    public function setUp()
    {
        $this->entryPoint = '/subdir/index.php';
        $this->config = null;
    }

    public function getConfig()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Security\Core\Module' => true,
                    'Rindow\Validation\Module'     => true,
                    'Rindow\Web\Mvc\Module'      => true,
                    'Rindow\Web\Http\Module'     => true,
                    'Rindow\Web\Router\Module'   => true,
                    'Rindow\Web\Session\Module'   => true,
                    'Rindow\Web\View\Module'     => true,
                    'Rindow\Web\Form\Module'     => true,
                    'Rindow\Web\Security\Authentication\FormAuthModule'=>true,
                ),
                'autorun' => 'Rindow\Web\Mvc\Module',
                'annotation_manager' => true,
                'enableCache' => false,
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService' => 'Rindow\\Security\\Core\\Authentication\\DefaultInMemoryUserDetailsManager',
                ),
                'components' => array(
                    __NAMESPACE__.'\\MyHandler' => array(
                        'class' => __NAMESPACE__.'\\MyHandler',
                    ),
                    'Rindow\\Web\\Security\\Authentication\\Form\\Controller\\LoginController' => array(
                        'properties' => array(
                            'loginFailMessages' => array('value'=>array(
                                'BadCredentialsException'=>'Invalid username or password.',
                                'DisabledException'      =>'DisabledException',
                                'LockedException'        =>'LockedException',
                                'AccountExpiredException'=>'AccountExpiredException',
                                'CredentialsExpiredException'=>'CredentialsExpiredException',
                            )),
                        ),
                    ),
                ),
            ),
            'web' => array(
                'mvc' => array(
                    'unittest' => true,
                ),
                'error_page_handler' => array(
                    'unittest' => true,
                ),
                'router' => array(
                    'routes' => array(
                        'allow' => array(
                            'path' => '/allow',
                            'type' => 'literal',
                            'handler' => array(
                                'class' => __NAMESPACE__.'\\MyHandler',
                                'method' => 'allowAction',
                            ),
                        ),
                        'deny' => array(
                            'path' => '/deny',
                            'type' => 'literal',
                            'handler' => array(
                                'class' => __NAMESPACE__.'\\MyHandler',
                                'method' => 'denyAction',
                            ),
                        ),
                        FormAuthModule::ROUTE_LOGIN => array(
                            'path' => '/login',
                        ),
                        FormAuthModule::ROUTE_LOGOUT => array(
                            'path' => '/logout',
                        ),
                    ),
                ),
                'form' => array(
                    'builders' => array(
                        'annotation' => false,
                    ),
                ),
            ),
            'security' => array(
                'secret' => 'THE SECRET',
                'authentication' => array(
                    'default' => array(
                        'users' => array(
                            'foo' => array(
                                'id' => 1,
                                // 'password' => 'fooPass',
                                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                                'roles'=>array('ADMIN'),
                            ),
                            'test' => array(
                                'password' => 'aaa',
                                'roles' => array('USER'),
                            ),
                            'disableduser' => array(
                                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                                'roles' => array('USER'),
                                'enabled' => false,
                            ),
                            'expireduser' => array(
                                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                                'roles' => array('USER'),
                                'accountNonExpired' => false,
                            ),
                            'lockeduser' => array(
                                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                                'roles' => array('USER'),
                                'accountNonLocked' => false,
                            ),
                            'credentialsexpireduser' => array(
                                // 'password' => 'fooPass',
                                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                                'roles' => array('USER'),
                                'credentialsNonExpired' => false,
                            ),
                        ),
                    ),
                ),
            ),
        );
        return $config;
    }

    public function dispatch($path,$method=null,$postValues=null,$cookies=null,$headers=null)
    {
        if(!$this->config)
            $this->config = $this->getConfig();
        $this->moduleManager = new ModuleManager($this->config);
        $env = $this->moduleManager->getServiceLocator()->get('Rindow\Web\Http\Message\TestModeEnvironment');
        $env->_SERVER['SERVER_NAME'] = 'localhost';
        $env->_SERVER['SCRIPT_NAME'] = $this->entryPoint;
        $env->_SERVER['REQUEST_URI'] = $path;
        $env->_SERVER['REQUEST_METHOD'] = $method ? strtoupper($method) : 'GET';
        $env->_COOKIE = $cookies;
        //if(isset($env->_POST)) {
        //    $keys = array_keys($env->_POST);
        //    foreach ($keys as $key) {
        //        unset($env->_POST[$key]);
        //    }
        //}
        if(strtoupper($method) == 'POST') {
            foreach ($postValues as $key => $value) {
                $env->_POST[$key] = $value;
            }
        }
        if($headers) {
            foreach ($headers as $key => $value) {
                $env->_SERVER['HTTP_'.strtoupper($key)] = $value;
            }
        }
        $this->moduleManager->getServiceLocator()->get('Rindow\Web\Mvc\DefaultApplication');
        $this->output = $this->moduleManager->run('Rindow\Web\Mvc\Module');
        return $this->output;
    }

    public function match($string)
    {
        return (strpos($this->output->getBody()->getContents(),$string)!==false);
    }

    public function extract($pattern)
    {
        $count = preg_match($pattern, $this->output->getBody()->getContents(), $matchs);
        if($count)
            return $matchs;
        else
            return false;
    }

    public function statusCode()
    {
        return $this->output->getStatusCode();
    }

    public function contents()
    {
        return $this->output->getBody()->getContents();
    }

    public function header($name,$index=0)
    {
        $header = $this->output->getHeader($name);
        if(!isset($header[$index]))
            return null;
        return $header[$index];
    }

    public function headers($name)
    {
        return $this->output->getHeader($name);
    }

    public function redirectPath()
    {
        $headers =  $this->output->getHeaders();
        if(!isset($headers['Location']))
            return null;

        if(is_string($headers['Location']))
            return $headers['Location'];
        else
            return $headers['Location'][0];
    }

    public function service($service)
    {
        return $this->moduleManager->getServiceLocator()->get($service);
    }

    public function buildRememberMeCookie($expires=null)
    {
        $algorithm = 'sha256';
        $username = 'foo';
        $password = 'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=';
        if($expires===null)
            $expires = time()+2592000; // 30 days = 30*24*3600
        else
            $expires = time()+$expires;
        $secret = 'THE SECRET';
        $signature = hash_hmac($algorithm,$username.$password.$expires,$secret);
        $value = base64_encode(base64_encode($username).':'.$expires.':'.$signature);
        return array('remember-me'=>$value);
    }

    public function testCreateFowardingHeaderOnModule()
    {
        $config = $this->getConfig();
        $moduleManager = new ModuleManager($config);
        $formAuthentication = $moduleManager->getServiceLocator()
            ->get('Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultCookieAuthentication');
        $securityContext = $moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');

        $env = $moduleManager->getServiceLocator()->get('Rindow\Web\Http\Message\TestModeEnvironment');
        $env->_SERVER['SERVER_NAME'] = 'localhost';
        $env->_SERVER['SCRIPT_NAME'] = '/subdir/index.php';
        $env->_SERVER['REQUEST_URI'] = '/subdir/deny';
        $env->_SERVER['REQUEST_METHOD'] = 'GET';
        $request = ServerRequestFactory::fromTestEnvironment($env);
        //var_dump($request);
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);
        $invocator->setException(new AccessDeniedException('access denied'));

        $response = $formAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array('Location'=>array('/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny')),$response->getHeaders());
        $this->assertEquals(302,$response->getStatusCode());
        $this->assertEquals('anonymous',$invocator->getPrincipal());
    }

    public function testCreateFowardingHeaderWithFullAuthOnModule()
    {
        $config = $this->getConfig();
        $moduleManager = new ModuleManager($config);
        $formAuthentication = $moduleManager->getServiceLocator()
            ->get('Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultCookieAuthentication');
        $securityContext = $moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');

        $env = $moduleManager->getServiceLocator()->get('Rindow\Web\Http\Message\TestModeEnvironment');
        $env->_SERVER['SERVER_NAME'] = 'localhost';
        $env->_SERVER['SCRIPT_NAME'] = '/subdir/index.php';
        $env->_SERVER['REQUEST_URI'] = '/subdir/deny';
        $env->_SERVER['REQUEST_METHOD'] = 'GET';
        $request = ServerRequestFactory::fromTestEnvironment($env);
        //var_dump($request);
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);
        $invocator->setException(new FullAuthenticationRequiredException('auth required'));

        $response = $formAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array('Location'=>array('/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny&fullauth=1')),$response->getHeaders());
        $this->assertEquals(302,$response->getStatusCode());
        $this->assertEquals('anonymous',$invocator->getPrincipal());
    }

    public function testCreateUserDetailTokenOnModule()
    {
        $config = $this->getConfig();
        $moduleManager = new ModuleManager($config);
        $contextStrage = $moduleManager->getServiceLocator()
            ->get('Rindow\\Web\\Security\\Authentication\\DefaultRememberMeContextStrage');
        $auth = new RememberMeAuthenticationToken('foo','foo',array('ROLE_USER'));
        $contextStrage->set('Rindow.Security.Authentication.DefaultSecurityContext.Authentication',$auth);
        $formAuthentication = $moduleManager->getServiceLocator()
            ->get('Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultCookieAuthentication');
        $securityContext = $moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');

        $env = $moduleManager->getServiceLocator()->get('Rindow\Web\Http\Message\TestModeEnvironment');
        $env->_SERVER['SERVER_NAME'] = 'localhost';
        $env->_SERVER['SCRIPT_NAME'] = '/subdir/index.php';
        $env->_SERVER['REQUEST_URI'] = '/subdir/deny';
        $env->_SERVER['REQUEST_METHOD'] = 'GET';
        $request = ServerRequestFactory::fromTestEnvironment($env);
        //var_dump($request);
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);

        $response = $formAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array(),$response->getHeaders());
        $this->assertEquals('foo',$invocator->getPrincipal());
    }

    public function testCreateFowardingHeaderOnMvc()
    {
        $this->dispatch('/subdir/deny');
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('/subdir/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny',$this->redirectPath());
    }

    public function testLoginForm()
    {
        $this->dispatch('/subdir/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny');
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        //var_dump($this->contents());
    }

    public function testLoginAndSetAuthentication()
    {
        $this->dispatch('/subdir/login','post',array('username'=>'foo','password'=>'fooPass','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('http://localhost/subdir/deny',$this->redirectPath());
    }

    public function testInvalidPassword()
    {
        $this->dispatch('/subdir/login','post',array('username'=>'foo','password'=>'invalidpassword','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" value="foo" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<small>Invalid username or password.</small>'));
        //var_dump($this->contents());
    }

    public function testAccountDisabled()
    {
        $this->dispatch('/subdir/login','post',array('username'=>'disableduser','password'=>'password','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" value="disableduser" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<small>DisabledException</small>'));
        //var_dump($this->contents());
    }

    public function testAccountExpired()
    {
        $this->dispatch('/subdir/login','post',array('username'=>'expireduser','password'=>'password','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" value="expireduser" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<small>AccountExpiredException</small>'));
        //var_dump($this->contents());
    }

    public function testAccountLocked()
    {
        $this->dispatch('/subdir/login','post',array('username'=>'lockeduser','password'=>'password','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" value="lockeduser" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<small>LockedException</small>'));
        //var_dump($this->contents());
    }

    public function testCredentialsExpiredWithoutUri()
    {
        $this->dispatch('/subdir/login','post',array('username'=>'credentialsexpireduser','password'=>'fooPass','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" value="credentialsexpireduser" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<small>CredentialsExpiredException</small>'));
        //var_dump($this->contents());
    }

    public function testCredentialsExpiredWithRedirectPath()
    {
        $config = $this->getConfig();
        $config = array_replace_recursive($config,array(
            'web' => array(
                'security' => array(
                    'credentialsExpiredRedirectPath' => '/users/changepassword',
                ),
            ),
        ));
        $this->config = $config;
        $this->dispatch('/subdir/login','post',array('username'=>'credentialsexpireduser','password'=>'fooPass','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('/subdir/users/changepassword?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny&username=credentialsexpireduser',$this->redirectPath());
        //var_dump($this->contents());
    }

    public function testLoginFormWithoutCookieOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;
        $this->dispatch('/subdir/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny');
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<input name="rememberMe[]" type="checkbox" value="1">'));
        $this->assertNull($this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken',
            $securityContext->getAuthentication());
        //var_dump($this->contents());
    }

    public function testLoginFormWithExpiresCookieOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $cookies = $this->buildRememberMeCookie(-3600);
        $this->dispatch('/subdir/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny',$method=null,$postValues=null,$cookies);
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<input name="rememberMe[]" type="checkbox" value="1">'));
        $this->assertStringStartsWith('remember-me=deleted', $this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken',
            $securityContext->getAuthentication());
        //var_dump($this->contents());
    }

    public function testLoginWithCookieOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $cookies = $this->buildRememberMeCookie();
        $this->dispatch('/subdir/login?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny',$method=null,$postValues=null,$cookies);
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('http://localhost/subdir/deny',$this->redirectPath());
        $this->assertNull($this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken',
            $securityContext->getAuthentication());
    }

    public function testLoginFormWithCookieButFullauthOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $cookies = $this->buildRememberMeCookie();
        $this->dispatch('/subdir/login?fullauth=1&redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fdeny',$method=null,$postValues=null,$cookies);
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<input name="rememberMe[]" type="checkbox" value="1">'));
        $this->assertNull($this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken',
            $securityContext->getAuthentication());
        //var_dump($this->contents());
    }

    public function testLoginWithChechBoxOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $this->dispatch('/subdir/login','post',array('username'=>'foo','password'=>'fooPass','redirectUri'=>'http://localhost/subdir/deny','rememberMe'=>1));
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('http://localhost/subdir/deny',$this->redirectPath());
        $this->assertStringStartsWith('remember-me=', $this->header('Set-Cookie'));
        $this->assertStringStartsNotWith('remember-me=deleted', $this->header('Set-Cookie'));
        $this->assertContains('Path=/subdir/login;', $this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken',
            $securityContext->getAuthentication());
    }

    public function testLoginWithoutChechBoxOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $this->dispatch('/subdir/login','post',array('username'=>'foo','password'=>'fooPass','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('http://localhost/subdir/deny',$this->redirectPath());
        $this->assertNull($this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken',
            $securityContext->getAuthentication());
    }

    public function testLoginFailWithoutChechBoxOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $this->dispatch('/subdir/login','post',array('username'=>'foo','password'=>'xxxx','redirectUri'=>'http://localhost/subdir/deny'));
        $this->assertEquals(200, $this->statusCode());
        $this->assertTrue($this->match('<form method="post" action="/subdir/login">'));
        $this->assertTrue($this->match('<input type="hidden" value="http://localhost/subdir/deny" name="redirectUri">'));
        $this->assertTrue($this->match('<input type="text" value="foo" name="username">'));
        $this->assertTrue($this->match('<input type="password" name="password">'));
        $this->assertTrue($this->match('<input name="rememberMe[]" type="checkbox" value="1">'));
        $this->assertTrue($this->match('Invalid username or password'));

        $this->assertStringStartsWith('remember-me=deleted', $this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken',
            $securityContext->getAuthentication());
    }

    public function testLogoutWithCookieOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $cookies = $this->buildRememberMeCookie();
        $this->dispatch('/subdir/logout?redirectUri=http%3A%2F%2Flocalhost%2Fsubdir%2Fhome',$method=null,$postValues=null,$cookies);
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('http://localhost/subdir/home',$this->redirectPath());
        $this->assertStringStartsWith('remember-me=deleted', $this->header('Set-Cookie'));

        $securityContext = $this->moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');
        $this->assertInstanceOf(
            'Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken',
            $securityContext->getAuthentication());
    }

    /**
     * @expectedException        Rindow\Web\Security\Authentication\Exception\RuntimeException
     * @expectedExceptionMessage redirectUri is empty
     * @expectedExceptionCode    1
     */
    public function testLoginWithoutRedirectPath()
    {
        // without redirect path
        $this->dispatch('/subdir/login','post',array('username'=>'foo','password'=>'fooPass'));
        $this->assertEquals(302, $this->statusCode());
        $this->assertEquals('http://localhost/subdir/deny',$this->redirectPath());
    }

    /**
     * @expectedException        Rindow\Web\Security\Authentication\Exception\RuntimeException
     * @expectedExceptionMessage redirectUri is empty
     * @expectedExceptionCode    2
     */
    public function testLoginWithoutRedirectPathWithCookieOnRenemberMeServices()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Security\Authentication\TokenBasedRememberMeModule' => true,
                ),
            ),
        );
        $config = array_replace_recursive($this->getConfig(),$config);
        $this->config = $config;

        $cookies = $this->buildRememberMeCookie();
        // without redirect path
        $this->dispatch('/subdir/login',$method=null,$postValues=null,$cookies);
    }

    public function testDenyJsonOnMvc()
    {
        $headers = array('Accept'=>'application/json');
        $this->dispatch('/subdir/deny',$method=null,$postValues=null,$cookies=null,$headers);
        $this->assertEquals(403, $this->statusCode());
        $this->assertEquals('{"error":{"message":"Authentication required."}}',$this->contents());
        $this->assertEquals('application/json',$this->header('Content-type'));
    }

    public function testDenyXmlOnMvc()
    {
        $headers = array('Accept'=>'application/xml');
        $this->dispatch('/subdir/deny',$method=null,$postValues=null,$cookies=null,$headers);
        $this->assertEquals(403, $this->statusCode());
        $this->assertEquals(
            '<?xml version="1.0" encoding="utf-8"?>'."\n".
            '<error><message>Authentication required.</message></error>'."\n",
            $this->contents());
        $this->assertEquals('application/xml',$this->header('Content-type'));
    }
}

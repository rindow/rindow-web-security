<?php
namespace RindowTest\Web\Security\Authentication\BasicAuthenticationTest;

use PHPUnit\Framework\TestCase;
use Rindow\Web\Http\Message\ServerRequest;
use Rindow\Web\Http\Message\Response;

use Interop\Lenient\Security\Authentication\AuthenticationManager;
use Rindow\Security\Core\Authentication\Support\AuthenticationTrustResolver;
use Rindow\Security\Core\Authentication\Support\SecurityContext;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authorization\Exception\AccessDeniedException;
use Rindow\Web\Security\Authentication\Middleware\BasicAuthentication;
use Rindow\Web\Security\Authentication\Support\WebAuthenticationUtils;
use Rindow\Stdlib\Dict;
use Rindow\Container\ModuleManager;

class TestInvocator
{
    protected $exception;
    protected $securityContext;
    protected $userPass;

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
        $this->userPass = $auth->getName().':'.$auth->getCredentials();
        if($this->exception)
            throw $this->exception;
        return $response;
    }

    public function getUserPass()
    {
        return $this->userPass;
    }
}

class TestAnonymousAuthenticationProvider implements AuthenticationManager
{
    public function authenticate(/*AuthenticationToken*/$token)
    {
        return $token;
    }
    public function createToken($principal=null,$authorities=null)
    {
        return new AnonymousAuthenticationToken('KEY','anonymous',array('ANONYMOUS'));
    }
}
class TestDaoAuthenticationProvider implements AuthenticationManager
{
    public function authenticate(/*AuthenticationToken*/$token)
    {
        return $token;
    }
    public function createToken($principal,$credentials)
    {
        return new UsernamePasswordAuthenticationToken($principal,$credentials);
    }
}

class Test extends TestCase
{
    public function setUp()
    {
    }

    public function getConfig()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Security\Core\Module' => true,
                    'Rindow\Web\Mvc\Module'      => true,
                    'Rindow\Web\Http\Module'     => true,
                    'Rindow\Web\Router\Module'   => true,
                    'Rindow\Web\Security\Authentication\BasicAuthModule'=>true,
                ),
                'enableCache' => false,
                'autorun' => 'Rindow\Web\Mvc\Module',
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService' => 'Rindow\\Security\\Core\\Authentication\\DefaultInMemoryUserDetailsManager',
                ),
                'components' => array(
                    'MyHandler' => array(
                        'class' => 'MyHandler',
                        'properties' => array(
                            'securityContext' => array('ref'=>'Rindow\Security\Core\Authentication\DefaultSecurityContext'),
                            'authenticationTrustResolver' => array('ref'=>'Rindow\Security\Core\Authentication\DefaultAuthenticationTrustResolver'),
                        ),
                    ),
                ),
            ),
            'web' => array(
                'router' => array(
                    'routes' => array(
                        'home' => array(
                            'path' => '/',
                            'type' => 'literal',
                            'handler' => array(
                                'callable' => 'MyHandler',
                            ),
                        ),
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
                        ),
                    ),
                ),
            ),
        );
        return $config;
    }

    public function testCreateAuthenticateHeader()
    {
        $securityContext = new SecurityContext(new Dict(),'fooKey');
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        $anonymousAuthenticationProvider = new TestAnonymousAuthenticationProvider();
        $usernamePasswordAuthenticationProvider = new TestDaoAuthenticationProvider();
        $basicAuthentication = new BasicAuthentication($securityContext,$authenticationTrustResolver,$anonymousAuthenticationProvider,$usernamePasswordAuthenticationProvider);

        $request = new ServerRequest();
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);
        $invocator->setException(new AccessDeniedException('access denied'));

        $response = $basicAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array('WWW-Authenticate'=>array('Basic')),$response->getHeaders());
        $this->assertEquals('anonymous:',$invocator->getUserPass());
    }

    public function testCreateUserDetailToken()
    {
        $securityContext = new SecurityContext(new Dict(),'fooKey');
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        $anonymousAuthenticationProvider = new TestAnonymousAuthenticationProvider();
        $usernamePasswordAuthenticationProvider = new TestDaoAuthenticationProvider();
        $basicAuthentication = new BasicAuthentication($securityContext,$authenticationTrustResolver,$anonymousAuthenticationProvider,$usernamePasswordAuthenticationProvider);

        $request = new ServerRequest();
        $user = 'foo';
        $password = 'fooPass';
        $request = $request->withHeader('Authorization','Basic '.base64_encode($user.':'.$password));
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);

        $response = $basicAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array(),$response->getHeaders());
        // *CAUTION* TestAuthenticationProviderManager does not erase the Credentials.
        $this->assertEquals('foo:fooPass',$invocator->getUserPass());
    }

    public function testCreateAuthenticateHeaderOnModule()
    {
        $config = $this->getConfig();
        $moduleManager = new ModuleManager($config);
        $basicAuthentication = $moduleManager->getServiceLocator()
            ->get('Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultBasicAuthentication');
        $securityContext = $moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');

        $request = new ServerRequest();
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);
        $invocator->setException(new AccessDeniedException('access denied'));

        $response = $basicAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array('WWW-Authenticate'=>array('Basic')),$response->getHeaders());
        $this->assertEquals('anonymous:',$invocator->getUserPass());
    }

    public function testCreateUserDetailTokenOnModule()
    {
        $config = $this->getConfig();
        $moduleManager = new ModuleManager($config);
        $basicAuthentication = $moduleManager->getServiceLocator()
            ->get('Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultBasicAuthentication');
        $securityContext = $moduleManager->getServiceLocator()
            ->get('Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext');

        $request = new ServerRequest();
        $user = 'foo';
        $password = 'fooPass';
        $request = $request->withHeader('Authorization','Basic '.base64_encode($user.':'.$password));
        $response = new Response();
        $invocator = new TestInvocator();
        $invocator->setSecurityContext($securityContext);

        $response = $basicAuthentication->__invoke($request,$response,$invocator);
        $this->assertEquals(array(),$response->getHeaders());
        // *CAUTION* DaoAuthenticationProvider erase the Credentials.
        $this->assertEquals('foo:',$invocator->getUserPass());
    }
}

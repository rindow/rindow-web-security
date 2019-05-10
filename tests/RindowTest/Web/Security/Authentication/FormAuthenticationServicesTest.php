<?php
namespace RindowTest\Web\Security\Authentication\FormAuthenticationServicesTest;

use PHPUnit\Framework\TestCase;
use Rindow\Web\Security\Authentication\FormAuthModule;
use Rindow\Container\ModuleManager;

class Test extends TestCase
{
    public function setUp()
    {
    }

    public function getContainer()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Web\Http\Module' => true,
                    'Rindow\Web\Mvc\Module' => true,
                    'Rindow\Web\Router\Module' => true,
                    'Rindow\Web\Security\Authentication\FormAuthModule' => true,
                ),
                'enableCache' => false,
            ),
            'web' => array(
		        'router' => array(
		            'routes' => array(
		                FormAuthModule::ROUTE_LOGIN => array(
		                    'path' => '/login',
		                ),
		                FormAuthModule::ROUTE_LOGOUT => array(
		                    'path' => '/logout',
		                ),
		            ),
	            ),
            ),
        );
        $mm = new ModuleManager($config);
        return $mm->getServiceLocator();
    }

    public function test()
    {
    	$container = $this->getContainer();
    	$urlGen = $container->get('Rindow\\Web\\Mvc\\DefaultUrlGenerator');
    	$info['route']['namespace'] = 'BooName';
    	$urlGen->setRouteInfo($info);
    	$this->assertEquals('BooName',$urlGen->currentNamespace());
    	$services = $container->get('Rindow\\Web\\Security\\Authentication\\DefaultFormAuthenticationServices');

    	$this->assertEquals('/logout?redirectUri=%2F',$services->getLogoutUrl());
    	$this->assertEquals('/logout?redirectUri=%2Ffoo',$services->getLogoutUrl('/foo'));
    	$this->assertEquals('/login?redirectUri=%2F',$services->getLoginUrl());
    	$this->assertEquals('/login?redirectUri=%2Ffoo',$services->getLoginUrl('/foo'));
    }
}
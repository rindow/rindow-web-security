<?php
namespace Rindow\Web\Security\Csrf\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

use Rindow\Web\Security\Csrf\Exception;

class CrossSiteAccessValidation extends AbstractCrossSiteAccessValidation
{
    protected $config;
    protected $attributeName;
    protected $ruleName;

    public function setConfig($config)
    {
        $this->config = $config;
    }

    public function setRuleName($ruleName)
    {
        $this->ruleName = $ruleName;
    }

    public function setAttributeName($attributeName)
    {
        $this->attributeName = $attributeName;
    }
    
    protected function getRequiredValidationConfig(ServerRequestInterface $request)
    {
        $attributeName = $this->attributeName;
        if($attributeName==null && interface_exists('Rindow\\Web\\Mvc\\HttpMessageAttribute')) {
            $attributeName = \Rindow\Web\Mvc\HttpMessageAttribute::ROUTING_INFORMATION;
        }
        if($attributeName==null)
            throw new Exception\DomainException('Name of request message attribute is not specified.');
        $ruleName = null;
        if($this->ruleName)
            $ruleName = $this->ruleName;
        if($ruleName==null) {
            $route = $request->getAttribute($attributeName);
            if(isset($route['view']))
                $ruleName = $route['view'];
        }
        if($ruleName==null) {
            $ruleName = 'default';
        }
        if(isset($this->config[$ruleName]))
            $config = $this->config[$ruleName];
        else
            $config = null;
        return $config;
    }
}
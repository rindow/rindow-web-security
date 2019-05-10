<?php
namespace Rindow\Web\Security\Csrf\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

class ForceXsrfTokenValidation extends AbstractCrossSiteAccessValidation
{
    protected $config;

    public function setConfig($config)
    {
        $this->config = $config;
    }
    
    protected function getRequiredValidationConfig(ServerRequestInterface $request)
    {
        if(isset($this->config['excludingPaths'])) {
            $uri = $request->getUri();
            if($uri) {
                $path = $uri->getPath();
                foreach($this->config['excludingPaths'] as $except => $switch) {
                    if(!$switch)
                        continue;
                    if(strpos($path, $except)===0)
                        return null;
                }
            }
        }
        $config = $this->config;
        if(!$config) {
            $config = array('forceActive'=>true);
        }
        return $config;
    }
}
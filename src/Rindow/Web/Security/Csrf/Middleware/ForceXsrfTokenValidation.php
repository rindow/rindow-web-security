<?php
namespace Rindow\Web\Security\Csrf\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

class ForceXsrfTokenValidation extends AbstractCrossSiteAccessValidation
{
    protected $config;
    protected $pathPrefixes;

    public function setConfig($config)
    {
        $this->config = $config;
    }

    public function setPathPrefixes($pathPrefixes)
    {
        $this->pathPrefixes = $pathPrefixes;
    }
    
    protected function getRequiredValidationConfig(ServerRequestInterface $request)
    {
        $uri = $request->getUri();
        if($uri) {
            $path = $uri->getPath();
            if(isset($this->config['excludingPaths'])) {
                foreach($this->config['excludingPaths'] as $except => $switch) {
                    if(!$switch)
                        continue;
                    if(strpos($path, $except)===0)
                        return null;
                }
            }
            if(isset($this->config['excludingPathsInNamespaces'])) {
                foreach($this->config['excludingPathsInNamespaces'] as $namespace => $paths) {
                    $prefix = '';
                    if(isset($this->pathPrefixes[$namespace])) {
                        $prefix = $this->pathPrefixes[$namespace];
                    }
                    foreach($paths as $except => $switch) {
                        if(!$switch)
                            continue;
                        if(strpos($path, $prefix.$except)===0)
                            return null;
                    }
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
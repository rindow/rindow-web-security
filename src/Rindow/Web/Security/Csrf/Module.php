<?php
namespace Rindow\Web\Security\Csrf;

class Module
{
    public function getConfig()
    {
        return array(
            'container' => array(
                'aliases' => array(
                    'Rindow\\Web\\Mvc\\DefaultForceCsrfTokenValidationMiddleware'=>'Rindow\\Web\\Security\\Csrf\\Middleware\\DefaultForceXsrfTokenValidationMiddleware',
                ),
                'components' => array(
                    'Rindow\\Web\\Security\\Csrf\\DefaultCsrfToken' => array(
                        'class' => 'Rindow\\Web\\Security\\Csrf\\CsrfToken',
                        'properties' => array(
                            'passPhrase' => array('config' => 'security::secret'),
                            'timeout' => array('config' => 'web::security::csrfTokenTimeout'),
                            'session' => array('ref' => 'Rindow\\Web\\Session\\DefaultSession'),
                        ),
                    ),
                    // Inject the CsrfToken to the Form module
                    'Rindow\\Web\\Form\\DefaultFormContextBuilder' => array(
                        'properties' => array(
                            'csrfToken' => array('ref' => 'Rindow\\Web\\Security\\Csrf\\DefaultCsrfToken'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Csrf\\DefaultCrossSiteAccessUtility' => array(
                        'class' => 'Rindow\\Web\\Security\\Csrf\\CrossSiteAccessUtility',
                        'properties' => array(
                            'csrfToken' => array('ref' => 'Rindow\\Web\\Security\\Csrf\\DefaultCsrfToken'),
                            'cookieContextFactory' => array('ref' => 'Rindow\\Web\\Mvc\\DefaultCookieContextFactory'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Csrf\\Middleware\\DefaultForceXsrfTokenValidationMiddleware' => array(
                        'class' => 'Rindow\\Web\\Security\\Csrf\\Middleware\\ForceXsrfTokenValidation',
                        'properties' => array(
                            'crossSiteAccess' => array('ref' => 'Rindow\\Web\\Security\\Csrf\\DefaultCrossSiteAccessUtility'),
                            'config' => array('config' => 'security::web::forceXsrfTokenValidation'),
                            'pathPrefixes' => array('config' => 'web::router::pathPrefixes'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Csrf\\Middleware\\DefaultSameOriginAccessValidation' => array(
                        'class' => 'Rindow\\Web\\Security\\Csrf\\Middleware\\CrossSiteAccessValidation',
                        'properties' => array(
                            'crossSiteAccess' => array('ref' => 'Rindow\\Web\\Security\\Csrf\\DefaultCrossSiteAccessUtility'),
                            'config' => array('config' => 'security::web::crossSiteAccessValidation'),
                            'ruleName' => array('value'=>'default'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Csrf\\Middleware\\DefaultCrossOriginAccessValidation' => array(
                        'class' => 'Rindow\\Web\\Security\\Csrf\\Middleware\\CrossSiteAccessValidation',
                        'properties' => array(
                            'crossSiteAccess' => array('ref' => 'Rindow\\Web\\Security\\Csrf\\DefaultCrossSiteAccessUtility'),
                            'config' => array('config' => 'security::web::crossSiteAccessValidation'),
                            'ruleName' => array('value'=>'public'),
                        ),
                    ),
                ),
            ),
            'web' => array(
                'dispatcher' => array(
                    'middlewares' => array(
                        'default' => array(
                            'csrf' => 'Rindow\\Web\\Security\\Csrf\\Middleware\\DefaultSameOriginAccessValidation',
                            'cors' => 'Rindow\\Web\\Security\\Csrf\\Middleware\\DefaultCrossOriginAccessValidation',
                        ),
                    ),
                ),
            ),
            'security' => array(
                'web' => array(
                    // for DefaultForceCsrfTokenValidationMiddleware setting
                    'forceXsrfTokenValidation' => array(
                        'xsrfHeaderNames' => array(
                            'X-XSRF-TOKEN'=>true,
                            'X-CSRF-TOKEN'=>true,
                        ),
                        // If you do not like to sprinkle on CSRF tokens, you should set 'false' this.
                        // When you want to use "angular2" or "axios", you can sprinkle the XSRF_TOKEN on cookie.
                        // But as with other frameworks, you should thoroughly consider whether it is safe to 
                        // unconditionally distribute csrf tokens on cookie without 'httpOnly'.
                        'xsrfCookieNames' => array(
                            'XSRF-TOKEN' => false,
                        ),
                        'xsrfCookiePath' => '/',
                        'csrfPostField' => 'csrf_token',

                        // If you do not want to include a specific path in validation, 
                        // you write paths of uri to "excludingPaths".
                        // Please note that the following path is uri in
                        // Psr\Http\Message\RequestInterface, not path on the framework.
                        //
                        // 'excludingPaths' => array(
                        //     '/path/path' => true,
                        // ),
                        //
                        // If you want to use excludingPaths in your module configs,
                        // You should use following setting. Because the URL path changes
                        // by 'web::router::pathPrefixes' configuration.
                        //
                        // 'excludingPathsInNamespaces' => array(
                        //     'Your\Web\Mvc\Path\Prefixes\Namespace' => array(
                        //         '/path/without/prefix' => true,
                        //     )
                        // ),
                    ),

                    // When setting individually with "csrf" middleware, please turn off 
                    // forced Validation by excludingPaths.
                    'crossSiteAccessValidation'=> array(
                        // for same origin
                        'default' => array(
                            'xsrfHeaderNames' => array(
                                'X-XSRF-TOKEN'=>true,
                                'X-CSRF-TOKEN'=>true,
                            ),
                            'xsrfCookieNames' => array(
                                'XSRF-TOKEN' => true,
                            ),
                            'xsrfCookiePath' => '/',
                        ),
                        // for cross origin resource share (public)
                        'public' => array(
                            'disableCsrfTokenValidation' => true,
                            'xsrfHeaderNames' => array(
                                'X-XSRF-TOKEN'=>false,
                                'X-CSRF-TOKEN'=>false,
                            ),
                            'xsrfCookieNames' => array(
                                'XSRF-TOKEN' => false,
                            ),
                            'corsAllowOrigins' => array(
                                '*' => true,
                            ),
                            'corsAllowMethods' => array(
                                'GET'=>true,
                                'POST'=>true,
                                'PUT'=>true,
                                'DELETE'=>true,
                                'OPTIONS'=>true,
                                'HEAD'=>true,
                            ),
                            'corsHeaders' => array(
                                'Origin'=>'*',
                                'Methods'=>'GET,POST,PUT,DELETE,OPTIONS,HEAD',
                                'Headers'=>'Content-Type, Authorization',
                                'Max-Age'=>'3628800',
                                // If you need...
                                // 'Credentials'=>'true',
                            ),
                        ),
                    ),
                ),
            ),
        );
    }
}

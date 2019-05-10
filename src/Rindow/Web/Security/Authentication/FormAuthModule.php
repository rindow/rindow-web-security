<?php
namespace Rindow\Web\Security\Authentication;

use Rindow\Web\Mvc\DefaultPipelinePriority;

class FormAuthModule
{
    //const ROUTE_HOME  = 'Rindow\\Web\\Security\\Authentication\\login/home';
    const ROUTE_LOGIN  = 'Rindow\\Web\\Security\\Authentication\\login/login';
    const ROUTE_LOGOUT = 'Rindow\\Web\\Security\\Authentication\\login/logout';

    public function getConfig()
    {
        return array(
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultContextStrage' => 'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeContextStrage',
                    //'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeServices' => 'remember_me_services',
                ),
                'components' => array(
                    'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeContextStrage' => array(
                        'class' => 'Rindow\\Web\\Session\\Container',
                        'factory' => 'Rindow\\Web\\Session\\Container::factory',
                        'factory_args' => array(
                            'session' => 'Rindow\\Web\\Session\\DefaultSession',
                        ),
                    ),
/*
                    'Rindow\\Web\\Security\\Authentication\\DefaultWebAuthenticationUtils' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\Support\\WebAuthenticationUtils',
                        'properties' => array(
                            'securityContext' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext'),
                            'authenticationProviderManager' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultProviderManager'),
                            'authenticationTrustResolver' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAuthenticationTrustResolver'),
                            'anonymousKey'  => array('config'=>'security::secret'),
                            'rememberMeKey' => array('config'=>'security::secret'),
                        ),
                    ),
*/
                    'Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultCookieAuthentication' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\Middleware\\CookieAuthentication',
                        'properties' => array(
                            'securityContext' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext'),
                            'authenticationTrustResolver' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAuthenticationTrustResolver'),
                            'anonymousAuthenticationProvider' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider'),
                            'loginUrl' => array('config'=>'web::router::routes::'.self::ROUTE_LOGIN.'::path'),
                            'urlGenerator' => array('ref'=>'Rindow\\Web\\Mvc\\DefaultUrlGenerator'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Authentication\\Form\\Controller\\LoginController' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\Form\\Controller\\LoginController',
                        'properties' => array(
                            'securityContext' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext'),
                            'usernamePasswordAuthenticationProvider' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider'),
                            'builder' => array('ref'=>'Rindow\\Web\\Form\\DefaultFormContextBuilder'),
                            'urlGenerator' => array('ref'=>'Rindow\\Web\\Mvc\\DefaultUrlGenerator'),
                            'redirector' => array('ref'=>'Rindow\\Web\\Mvc\\DefaultRedirector'),
                            'credentialsExpiredRedirectPath' => array('config'=>'web::security::credentialsExpiredRedirectPath'),
                            // Inject the flashBag if you need the flash message.
                            //'flashBag' => array('ref'=>'Rindow\\Web\\Session\\DefaultFlashBag'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Authentication\\DefaultTokenBasedRememberMeServices' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\RememberMe\\TokenBasedRememberMeServices',
                        'properties' => array(
                            'userDetailsService' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService'),
                            'rememberMeAuthenticationProvider' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultRememberMeAuthenticationProvider'),
                            'secret' => array('config'=>'security::secret'),
                            'config' => array('config'=>'security::authentication::default::rememberMeServices'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeUtility' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\Support\\RememberMeUtility',
                        'properties' => array(
                            'rememberMeServices' => array('ref'=>'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeServices'),
                            'securityContext' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext'),
                            'cookieContextFactory' => array('ref'=>'Rindow\\Web\\Mvc\\DefaultCookieContextFactory'),
                            'authenticationManager' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultProviderManager'),
                        ),
                    ),
                    'Rindow\\Web\\Security\\Authentication\\DefaultFormAuthenticationServices' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\Support\\FormAuthenticationServices',
                        'properties' => array(
                            'urlGenerator' => array('ref'=>'Rindow\\Web\\Mvc\\DefaultUrlGenerator'),
                        ),
                    ),
                    // ***************************************
                    // * Including Rindow\Web\Security\Csrf\Module
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
                    // *
                    // ***************************************
                ),
            ),
            'web' => array(
                'mvc' => array(
                    'middlewares' => array(
                        'default' => array(
                            'Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultCookieAuthentication' => DefaultPipelinePriority::BEFORE_ROUTER,
                        ),
                    ),
                ),
                'router' => array(
                    'routes' => array(
                        /*
                        self::ROUTE_HOME => array(
                            // Must inject your URI of Login Form
                            //'path' => '/Your_Login_Form_Uri',
                            'conditions' => array(
                                'method' => 'GET',
                            ),
                            'type' => 'literal',
                            'handler' => array(
                                'class' => __NAMESPACE__.'\\Form\\Controller\\LoginController',
                                'method' => 'indexAction',
                            ),
                            'namespace' => __NAMESPACE__,
                            'view' => 'login',
                            'middlewares' => array('view' => -1),
                        ),
                        */
                        self::ROUTE_LOGIN => array(
                            // Must inject your URI of Login Form
                            //'path' => '/Your_Login_Form_Uri',
                            //'conditions' => array(
                            //    'method' => 'POST',
                            //),
                            'type' => 'literal',
                            'handler' => array(
                                'class' => __NAMESPACE__.'\\Form\\Controller\\LoginController',
                                'method' => 'loginAction',
                            ),
                            'namespace' => __NAMESPACE__,
                            'view' => 'login',
                            'middlewares' => array('view' => -1),
                        ),
                        self::ROUTE_LOGOUT => array(
                            // Must inject your URI of Logout
                            //'path' => '/Your_Logout_Uri',
                            'type' => 'literal',
                            'handler' => array(
                                'class' => __NAMESPACE__.'\\Form\\Controller\\LoginController',
                                'method' => 'logoutAction',
                            ),
                            'namespace' => __NAMESPACE__,
                        ),
                    ),
                ),
                //'security' => array(
                //    'credentialsExpiredUri' => 'login_password_expired_uri',
                //),
                'view' => array(
                    'view_managers' => array(
                        __NAMESPACE__ => array(
                            'template_paths' => array(
                                __DIR__.'/Form/Resources/views',
                            ),
                        ),
                    ),
                ),
                'form' => array(
                    'builders' => array(
                        'array' => array(
                            'mapping' => array(
                                __NAMESPACE__.'\\Form\\Entity\\Login' => array(
                                    'attributes' => array(
                                        //'action'=>'/app/form',
                                        'method' => 'post',
                                    ),
                                    'properties' => array(
                                        'redirectUri' => array(
                                            'type'=>'hidden',
                                        ),
                                        'username' => array(
                                            'type'=>'text',
                                            'label'=> 'Username',
                                        ),
                                        'password' => array(
                                            'type'=>'password',
                                            'label'=> 'Password',
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            'validator' => array(
                'builders' => array(
                    'array' => array(
                        'mapping' => array(
                            __NAMESPACE__.'\\Form\\Entity\\Login' => array(
                                'properties' => array(
                                    'username' => array(
                                        'Length' => array(
                                            'min' => 3,
                                            'max' => 31,
                                        ),
                                        'NotBlank' => null,
                                        'Pattern' => array(
                                            'regexp'=>'^[A-Z0-9@_\.\-]+$',
                                            'flags'=>array('CASE_INSENSITIVE'),
                                            'message' => 'Invalid username or password',
                                        ),
                                    ),
                                    'password' => array(
                                        'Length' => array(
                                            'min' => 1,
                                            'max' => 31,
                                        ),
                                        'NotBlank' => null,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            'security' => array(
                'authentication' => array(
                    'default' => array(
                        'anonymous' => array(
                            'principal' => 'anonymous',
                            'authorities' => array('ANONYMOUS'=>true),
                        ),
                        'providers' => array(
                            'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider' => true,
                            'Rindow\\Security\\Core\\Authentication\\DefaultRememberMeAuthenticationProvider' => true,
                            'Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider' => true,
                        ),

                        // RememberMe services configuration
                        //   If you need to customize, you can set followings.
                        //'rememberMeServices' => array(
                        //    'cookieName' => 'remember-me',
                        //    'lifetime' => 2592000, // 30 days = 30*24*3600
                        //    'path' = null, // current path
                        //    'domain' = '',
                        //    'secure' = false,
                        //    'httponly' = true,
                        //),
                    ),
                ),
            ),
        );
    }
}

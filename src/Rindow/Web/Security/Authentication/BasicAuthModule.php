<?php
namespace Rindow\Web\Security\Authentication;

use Rindow\Web\Mvc\DefaultPipelinePriority;

class BasicAuthModule
{
    public function getConfig()
    {
        return array(
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultContextStrage' => 'Rindow\\Web\\Security\\Authentication\\DefaultContextStrage',
                ),
                'components' => array(
                    'Rindow\\Web\\Security\\Authentication\\DefaultContextStrage' => array(
                        'class' => 'Rindow\\Stdlib\\Dict',
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
                    'Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultBasicAuthentication' => array(
                        'class' => 'Rindow\\Web\\Security\\Authentication\\Middleware\\BasicAuthentication',
                        'properties' => array(
                            'securityContext' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext'),
                            'authenticationTrustResolver' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAuthenticationTrustResolver'),
                            'anonymousAuthenticationProvider' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider'),
                            'usernamePasswordAuthenticationProvider' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider'),
                        ),
                    ),
                ),
            ),
            'web' => array(
                'mvc' => array(
                    'middlewares' => array(
                        'default' => array(
                            'Rindow\\Web\\Security\\Authentication\\Middleware\\DefaultBasicAuthentication' => DefaultPipelinePriority::BEFORE_ROUTER,
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
                    ),
                ),
            ),
        );
    }
}

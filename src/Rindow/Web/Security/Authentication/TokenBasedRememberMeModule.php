<?php
namespace Rindow\Web\Security\Authentication;

class TokenBasedRememberMeModule
{
    public function getConfig()
    {
        return array(
            'container' => array(
                'aliases' => array(
                    'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeServices' => 'Rindow\\Web\\Security\\Authentication\\DefaultTokenBasedRememberMeServices',
                ),
                'components' => array(
                    'Rindow\\Web\\Security\\Authentication\\Form\\Controller\\LoginController' => array(
                        'properties' => array(
                            'rememberMeUtility' => array('ref'=>'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeUtility'),
                        ),
                    ),
                ),
            ),
            'web' => array(
                'form' => array(
                    'builders' => array(
                        'array' => array(
                            'mapping' => array(
                                __NAMESPACE__.'\\Form\\Entity\\Login' => array(
                                    'properties' => array(
                                        'rememberMe' => array(
                                            'type'=>'checkbox',
                                            'label'=> ' ',
                                            'options' => array(
                                                '1' => 'Remember me on this computer.',
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        );
    }
}
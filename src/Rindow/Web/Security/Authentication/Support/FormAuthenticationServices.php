<?php
namespace Rindow\Web\Security\Authentication\Support;

use Rindow\Web\Security\Authentication\FormAuthModule;

class FormAuthenticationServices
{
    protected $urlGenerator;

    public function setUrlGenerator($urlGenerator)
    {
        $this->urlGenerator = $urlGenerator;
    }

    public function getLogoutUrl($redirectUrl=null)
    {
        if($redirectUrl==null)
            $redirectUrl = '/';
        $query = array('redirectUri'=>strval($redirectUrl));
        $url = $this->urlGenerator->fromRoute(
            FormAuthModule::ROUTE_LOGOUT,
            null,
            array('query'=>$query,'namespace'=>'\\'));
        return $url;
    }

    public function getLoginUrl($redirectUrl=null)
    {
        if($redirectUrl==null)
            $redirectUrl = '/';
        $query = array('redirectUri'=>strval($redirectUrl));
        $url = $this->urlGenerator->fromRoute(
            FormAuthModule::ROUTE_LOGIN,
            null,
            array('query'=>$query,'namespace'=>'\\'));
        return $url;
    }
}
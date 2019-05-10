<?php
namespace Rindow\Web\Security\Authentication\Form\Controller;

use Interop\Lenient\Security\Authentication\Exception\BadCredentialsException;
use Interop\Lenient\Security\Authentication\Exception\DisabledException;
use Interop\Lenient\Security\Authentication\Exception\LockedException;
use Interop\Lenient\Security\Authentication\Exception\AccountExpiredException;
use Interop\Lenient\Security\Authentication\Exception\CredentialsExpiredException;
use Rindow\Security\Core\Authentication\Exception\ContainsRejectedAuthentication;

use Rindow\Web\Security\Authentication\Form\Entity\Login;
use Rindow\Web\Security\Authentication\Exception;

class LoginController
{
    protected $builder;
    protected $urlGenerator;
    protected $redirector;
    protected $rememberMeUtility;
    protected $securityContext;
    protected $usernamePasswordAuthenticationProvider;
    protected $credentialsExpiredRedirectPath;
    protected $loginFailMessages = array(
        'BadCredentialsException'=>'Invalid username or password.',
        'DisabledException'      =>'Invalid username or password.',
        'LockedException'        =>'Invalid username or password.',
        'AccountExpiredException'=>'Invalid username or password.',
        'CredentialsExpiredException'=>'Password age is expired.',
    );
    protected $flashBag;
    protected $logger;

    public function setBuilder($builder)
    {
        $this->builder = $builder;
    }

    public function setUrlGenerator($urlGenerator)
    {
        $this->urlGenerator = $urlGenerator;
    }

    public function setRedirector($redirector)
    {
        $this->redirector = $redirector;
    }

    public function setSecurityContext($securityContext)
    {
        $this->securityContext = $securityContext;
    }

    public function setUsernamePasswordAuthenticationProvider($usernamePasswordAuthenticationProvider)
    {
        $this->usernamePasswordAuthenticationProvider = $usernamePasswordAuthenticationProvider;
    }

    public function setRememberMeUtility($rememberMeUtility)
    {
        $this->rememberMeUtility = $rememberMeUtility;
    }

    public function setCredentialsExpiredRedirectPath($credentialsExpiredRedirectPath)
    {
        $this->credentialsExpiredRedirectPath = $credentialsExpiredRedirectPath;
    }

    public function setLoginFailMessages($loginFailMessages)
    {
        $this->loginFailMessages = $loginFailMessages;
    }

    public function setFlashBag($flashBag)
    {
        $this->flashBag = $flashBag;
    }

    public function setLogger($logger)
    {
        $this->logger = $logger;
    }
/*
    public function indexAction($request,$response,$args)
    {
        $entity = new Login();
        $query = $request->getQueryParams();
        if(isset($query['redirectUri']))
            $entity->redirectUri = $query['redirectUri'];
        $formctx = $this->builder->build($entity);
        return $this->renderLoginForm($formctx);
    }
*/
    public function loginAction($request,$response,$args)
    {
        $entity = new Login();
        $method = strtoupper($request->getMethod());
        if($method=='GET') {
            $query = $request->getQueryParams();
            if(isset($query['redirectUri']))
                $entity->redirectUri = $query['redirectUri'];
            if($this->rememberMeUtility && !isset($query['fullauth'])) {
                $response = $this->rememberMeUtility->autoLogin($loggedin,$request,$response);
                if($loggedin) {
                    if(empty($entity->redirectUri))
                        throw new Exception\RuntimeException('redirectUri is empty',2);/** WithoutRedirectPath RenemberMe **/
                    return $this->redirector->toUrl($response,$entity->redirectUri);
                }
            }
            $formctx = $this->builder->build($entity);
            return $this->renderLoginForm($formctx,$response);
        } else if($method=='POST'){
            ;
        } else {
            throw new Exception\DomainException('Invalid method type.');
        }
        $formctx = $this->builder->build($entity)
                ->setRequestToData($request->getParsedBody());
        if(!$formctx->isValid()) {
            return $this->renderLoginForm($formctx,$response);
        }
        try {
            $auth = $this->usernamePasswordAuthenticationProvider->createToken($entity->username,$entity->password);
            $auth = $this->usernamePasswordAuthenticationProvider->authenticate($auth);
        } catch(BadCredentialsException $e) {
            return $this->getLoginFailForm($formctx,$request,$response,
                $this->loginFailMessages['BadCredentialsException']);
        } catch(DisabledException $e) {
            return $this->getLoginFailForm($formctx,$request,$response,
                $this->loginFailMessages['DisabledException']);
        } catch(LockedException $e) {
            return $this->getLoginFailForm($formctx,$request,$response,
                $this->loginFailMessages['LockedException']);
        } catch(AccountExpiredException $e) {
            return $this->getLoginFailForm($formctx,$request,$response,
                $this->loginFailMessages['AccountExpiredException']);
        } catch(CredentialsExpiredException $e) {
            if($this->credentialsExpiredRedirectPath==null) {
                return $this->getLoginFailForm($formctx,$request,$response,
                    $this->loginFailMessages['CredentialsExpiredException']);
            }
            if($this->rememberMeUtility) {
                $response = $this->rememberMeUtility->loginFail($request,$response);
            }
            if($e instanceof ContainsRejectedAuthentication) {
                $auth = $e->getAuthentication();
                if($auth)
                    $this->securityContext->setAuthentication($auth);
            }
            if($this->flashBag) {
                $this->flashBag->add('notice','Password renewal deadline passed. Please update your password.');
            }
            $options = array('query'=>array('redirectUri'=>$entity->redirectUri,'username'=>$entity->username));
            $response = $this->redirector->toPath($response,$this->credentialsExpiredRedirectPath,$options);
            return $response;
        } catch(\Exception $e) {
            throw $e;
        }
        $this->securityContext->setAuthentication($auth);
        if($this->rememberMeUtility && isset($entity->rememberMe) && $entity->rememberMe) {
            $response = $this->rememberMeUtility->loginSuccess($request,$response,$auth);
        }
        if(empty($entity->redirectUri))
           throw new Exception\RuntimeException('redirectUri is empty', 1);/** WithoutRedirectPath NonRenemberMe **/
        $response = $this->redirector->toUrl($response,$entity->redirectUri);
        return $response;
    }

    protected function getLoginFailForm($formctx,$request,$response,$message=null)
    {
        if($message==null)
            $message = 'Invalid username or password';
        if($this->rememberMeUtility) {
            $response = $this->rememberMeUtility->loginFail($request,$response);
        }
        $variables = $this->renderLoginForm($formctx,$response);
        $variables['form']['password']->value = '';
        $variables['form']['password']->errors[] = $message;
        return $variables;
    }

    public function renderLoginForm($formctx,$response)
    {
        $formctx->setAttribute('action',$this->urlGenerator->fromRoute('login/login'));
        return array('form'=>$formctx->getForm(),'%response'=>$response);
    }

    public function logoutAction($request,$response,$args)
    {
        $this->securityContext->setAuthentication(null);
        if($this->rememberMeUtility) {
            $path = $this->urlGenerator->fromRoute('login/login');
            $response = $this->rememberMeUtility->logout($request,$response,$path);
        }
        $query = $request->getQueryParams();
        if(isset($query['redirectUri']))
            $redirectUri = $query['redirectUri'];
        else
            $redirectUri = '/';

        if($this->flashBag) {
            $this->flashBag->add('notice','Logged out.');
        }
        $response = $this->redirector->toUrl($response,$redirectUri);
        return $response;
    }
}
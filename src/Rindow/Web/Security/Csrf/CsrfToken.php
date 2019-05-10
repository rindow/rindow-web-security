<?php
namespace Rindow\Web\Security\Csrf;

use Interop\Lenient\Security\Web\CsrfToken as CsrfTokenInterface;

class CsrfToken implements CsrfTokenInterface
{
    protected $passPhrase;
    protected $session;
    protected $timeout = 3600;

    public function __construct($passPhrase=null,$session=null,$timeout=null)
    {
        if($passPhrase)
            $this->setPassPhrase($passPhrase);
        if($session)
            $this->setSession($session);
        if($timeout)
            $this->timeout = $timeout;
    }

    public function setPassPhrase($passPhrase)
    {
        $this->passPhrase = $passPhrase;
    }

    public function setSession($session)
    {
        $this->session = $session;
    }

    public function setTimeout($timeout=null)
    {
        if($timeout)
            $this->timeout = $timeout;
    }

    public function generateToken()
    {
        return $this->doGenerateToken();
    }

    public function doGenerateToken($time=null)
    {
        if($this->session==null)
            throw new Exception\DomainException('Session container is not specified.');
        if($this->passPhrase==null)
            throw new Exception\DomainException('Need the "secret" value in security configuration.');

        $sessionId = $this->session->getId();
        if($time==null)
            $time = time();
        $token = sha1($this->passPhrase.$sessionId.$time).':'.$time;
        return $token;
    }

    public function getTokenTimestamp($token)
    {
        $parts = explode(':', $token);
        if(isset($parts[1]))
            return $parts[1];
        else
            return 0;
    }

    public function isValid($token)
    {
        if(!is_string($token))
            throw new Exception\CsrfException('Invalid token type.');
        $tokenTimestamp = $this->getTokenTimestamp($token);
        if($this->doGenerateToken($tokenTimestamp)!==$token) {
            throw new Exception\CsrfException('Illegal form access.');
        }
        if(time() - $tokenTimestamp > $this->timeout) {
            throw new Exception\CsrfException('Session timeout.');
        }
        return true;
    }
}

<?php
namespace RindowTest\Web\Security\Csrf\CsrfTokenTest;

use PHPUnit\Framework\TestCase;
use Rindow\Web\Security\Csrf\CsrfToken;
use Interop\Lenient\Security\Web\Exception\CsrfException;

class TestSession
{
    public $id;
    public function getId()
    {
        return $this->id;
    }
}

class Test extends TestCase
{
    public function testSuccess()
    {
        $session = new TestSession();
        $session->id = 'some_session_id';
        $passPhrase = 'passPhrase';
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=null);

        $token = $csrfToken->generateToken();
        $this->assertNotNull($token);

        $passPhrase = 'passPhrase';
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=null);
        $this->assertTrue($csrfToken->isValid($token));
    }

    public function testInvalidToken()
    {
        $session = new TestSession();
        $session->id = 'some_session_id';
        $passPhrase = 'passPhrase';
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=null);
        try {
            $this->assertFalse($csrfToken->isValid('invalid:token'));
            $this->assertTrue(false);
        } catch(CsrfException $e) {
            $this->assertEquals('Illegal form access.',$e->getMessage());
        }
    }

    public function testTimeout()
    {
        $session = new TestSession();
        $session->id = 'some_session_id';
        $passPhrase = 'passPhrase';
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=-1);
        $token = $csrfToken->generateToken();

        try {
            $this->assertFalse($csrfToken->isValid($token));
            $this->assertTrue(false);
        } catch(CsrfException $e) {
            $this->assertEquals('Session timeout.',$e->getMessage());
        }
    }

    public function testOtherSession()
    {
        $session = new TestSession();
        $session->id = 'some_session_id';
        $passPhrase = 'passPhrase';
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=-1);
        $token = $csrfToken->generateToken();

        $session = new TestSession();
        $session->id = 'other_session_id';
        $passPhrase = 'passPhrase';
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=-1);

        try {
            $this->assertFalse($csrfToken->isValid($token));
            $this->assertTrue(false);
        } catch(CsrfException $e) {
            $this->assertEquals('Illegal form access.',$e->getMessage());
        }
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\DomainException
     * @expectedExceptionMessage Need the "secret" value in security configuration.
     */
    public function testNonPassPhrase()
    {
        $session = new TestSession();
        $session->id = 'some_session_id';
        $passPhrase = null;
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=-1);
        $token = $csrfToken->generateToken();

        try {
            $csrfToken->isValid($token);
            $this->assertTrue(false);
        } catch(CsrfException $e) {
            $this->assertTrue(false);
        }
    }

    /**
     * @expectedException        Rindow\Web\Security\Csrf\Exception\DomainException
     * @expectedExceptionMessage Session container is not specified.
     */
    public function testNonSessionContainer()
    {
        $session = null;
        $passPhrase = null;
        $csrfToken = new CsrfToken($passPhrase,$session,$timeout=-1);
        $token = $csrfToken->generateToken();
        $this->assertTrue(false);
    }
}

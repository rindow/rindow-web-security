<?php
namespace Rindow\Web\Security\Authentication\Form\Entity;

use Rindow\Stdlib\Entity\AbstractEntity;

class Login extends AbstractEntity
{
	public $username;
	public $password;
	public $rememberMe;
	public $redirectUri;
}
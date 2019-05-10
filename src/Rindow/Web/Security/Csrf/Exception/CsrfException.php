<?php
namespace Rindow\Web\Security\Csrf\Exception;

use Interop\Lenient\Security\Web\Exception\CsrfException as CsrfExceptionInterface;

class CsrfException extends RuntimeException implements CsrfExceptionInterface
{}
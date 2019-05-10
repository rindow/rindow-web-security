<?php
date_default_timezone_set('UTC');
include_once __DIR__.'/../vendor/autoload.php';
putenv('UNITTEST=1');

if(!class_exists('PHPUnit\Framework\TestCase')) {
    include __DIR__.'/travis/patch55.php';
}

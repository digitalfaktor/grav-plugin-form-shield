<?php

use Grav\Common\Cache;

class FormshieldInstall
{
    public static function postInstall(): string
    {
        Cache::clearCache('cache-only');

        return 'Form Shield: cleared cached form definitions.';
    }

    public static function postUpdate(): string
    {
        return self::postInstall();
    }
}

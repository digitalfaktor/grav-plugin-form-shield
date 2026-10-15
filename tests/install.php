<?php

// Standalone installer-hook checks: php tests/install.php
namespace Grav\Common {
    class Cache {
        public static array $calls = [];
        public static function clearCache($type = 'standard') {
            self::$calls[] = $type;
            return [];
        }
    }
}
namespace {
    require dirname(__DIR__) . '/install.php';

    // Grav strips punctuation from ucfirst('form-shield') . 'Install'.
    $class = preg_replace('/[^a-zA-Z0-9]+/', '', ucfirst('form-shield') . 'Install');
    foreach (['postInstall', 'postUpdate'] as $method) {
        \Grav\Common\Cache::$calls = [];
        $message = $class::$method();
        if (\Grav\Common\Cache::$calls !== ['cache-only'] || !is_string($message)) {
            throw new \RuntimeException('Failed: ' . $method);
        }
        echo "PASS: $method clears the Grav cache\n";
    }
}

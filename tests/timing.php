<?php

// Standalone regression checks: php tests/timing.php
namespace Grav\Common\Data {
    class ValidationException extends \RuntimeException {}
}
namespace Grav\Common {
    class Plugin {
        public $grav;
        public $config;
    }
    class Security {
        public static function getNonceKey() { return 'test-key'; }
    }
}
namespace Grav\Plugin\Form {
    class Form {
        public function __construct(private array $submitted, private string $initializedToken) {}
        public function getValues() { return new \TestValues($this->submitted); }
        public function value($name) { return $this->initializedToken; }
        public function getPage() { return new class {
            public function route() { return '/contact'; }
        }; }
        public function getUniqueId() { return 'test-form'; }
    }
}
namespace {
    class TestValues {
        public function __construct(private array $values) {}
        public function get($key, $default = null) { return $this->values[$key] ?? $default; }
    }
    require dirname(__DIR__) . '/form-shield.php';
    $plugin = new \Grav\Plugin\FormShieldPlugin();
    $plugin->config = new TestValues([]);
    $log = new class {
        public array $messages = [];
        public function warning($message) { $this->messages[] = $message; }
    };
    $plugin->grav = ['log' => $log, 'language' => new class {
        public function translate($key) { return $key; }
    }];
    $token = static function ($timestamp, $route = '/contact') {
        return $timestamp . '.' . hash_hmac('sha256', $timestamp . '|' . $route, 'test-key');
    };
    $old = $token(time() - 30);
    $fresh = $token(time());
    $cases = [
        'normal submission' => [['data' => ['form_shield_time' => $old]], null],
        'flat submission' => [['form_shield_time' => $old], null],
        'missing hidden field' => [['data' => ['email' => 'test@example.com']], 'invalid timing token'],
        'empty submission' => [[], 'invalid timing token'],
        'empty hidden field' => [['data' => ['form_shield_time' => '']], 'invalid timing token'],
        'malformed token' => [['data' => ['form_shield_time' => []]], 'invalid timing token'],
        'fast submission' => [['data' => ['form_shield_time' => $fresh]], 'submitted too quickly'],
        'expired token' => [['data' => ['form_shield_time' => $token(time() - 7300)]], 'invalid timing token'],
        'wrong route' => [['data' => ['form_shield_time' => $token(time() - 30, '/other')]], 'invalid timing token'],
    ];
    $validate = new \ReflectionMethod($plugin, 'validateMinimumSubmissionTime');
    foreach ($cases as $name => [$submitted, $expected]) {
        $log->messages = [];
        try {
            $validate->invoke($plugin, new \Grav\Plugin\Form\Form($submitted, $fresh));
            $actual = null;
        } catch (\Grav\Common\Data\ValidationException $exception) {
            $actual = $log->messages[0] ?? '';
        }
        if ($expected === null ? $actual !== null : ($actual === null || !str_contains($actual, $expected))) {
            throw new \RuntimeException('Failed: ' . $name);
        }
        echo "PASS: $name\n";
    }
}

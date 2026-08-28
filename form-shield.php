<?php

namespace Grav\Plugin;

use Grav\Common\Data\ValidationException;
use Grav\Common\Plugin;
use Grav\Common\Security;
use Grav\Common\Uri;
use Grav\Plugin\Form\Form;
use RocketTheme\Toolbox\Event\Event;

class FormShieldPlugin extends Plugin
{
    private const CAPTCHA_FIELD = 'form_shield_captcha';
    private const TIME_FIELD = 'form_shield_time';

    private array $failedForms = [];

    public static function getSubscribedEvents(): array
    {
        return [
            'onPluginsInitialized' => ['onPluginsInitialized', 0],
        ];
    }

    public function onPluginsInitialized(): void
    {
        if ($this->isAdmin()) {
            return;
        }

        $this->enable([
            'onFormPageHeaderProcessed' => ['onFormPageHeaderProcessed', 100],
            'onFormValidationProcessed' => ['onFormValidationProcessed', 100],
            'onFormValidationError' => ['onFormValidationError', 100],
        ]);
    }

    public function onFormPageHeaderProcessed(Event $event): void
    {
        if ($this->isAdminRequest()) {
            return;
        }

        $page = $event['page'];
        $route = $page->route();
        if (!is_string($route) || $route === '' || !$this->isRouteProtected($route)) {
            return;
        }

        $header = $event['header'];
        if (is_array($header->form ?? null)) {
            $header->form = $this->protectForm($header->form, $route);
        }

        $forms = $header->forms ?? null;
        if (is_array($forms)) {
            foreach ($forms as $name => $form) {
                if (is_array($form)) {
                    $forms[$name] = $this->protectForm($form, $route);
                }
            }

            $header->forms = $forms;
        }
    }

    private function protectForm(array $form, string $route): array
    {
        $form['fields'] = is_array($form['fields'] ?? null) ? $form['fields'] : [];
        if ($this->configValue('honeypot.enabled', true) && !$this->hasFieldOfType($form['fields'], ['honeypot'])) {
            $form['fields'][] = [
                'name' => $this->honeypotFieldName(),
                'type' => 'honeypot',
                'label' => $this->translate('HONEYPOT_LABEL'),
                'validate' => ['required' => false],
            ];
        }

        if ($this->configValue('time_check.enabled', true) && !$this->hasFieldNamed($form['fields'], self::TIME_FIELD)) {
            $form['fields'][] = [
                'name' => self::TIME_FIELD,
                'type' => 'hidden',
                'default' => $this->createTimeToken($route),
            ];
        }

        if ($this->configValue('captcha.enabled', true)) {
            if (!$this->hasFieldOfType($form['fields'], ['captcha', 'cap', 'basic-captcha', 'recaptcha', 'turnstile'])) {
                if (!class_exists('Grav\\Plugin\\Form\\Captcha\\CapProvider')) {
                    $this->grav['log']->error('Form Shield requires the Cap captcha provider from Form plugin 9.1.23 or newer.');
                    return $form;
                }

                $form['fields'][] = [
                    'name' => self::CAPTCHA_FIELD,
                    'type' => 'captcha',
                    'provider' => 'cap',
                    'mode' => $this->configValue('captcha.mode', 'invisible'),
                    'captcha_not_validated' => $this->translate('CAPTCHA_FAILURE'),
                    'form_shield' => true,
                ];
            }

            $process = is_array($form['process'] ?? null) ? $form['process'] : [];
            if (!$this->hasCaptchaAction($process)) {
                $form['process'] = ['captcha' => true] + $process;
            }
        }

        return $form;
    }

    public function onFormValidationProcessed(Event $event): void
    {
        $form = $event['form'];
        if (!$form instanceof Form || !$this->isFormProtected($form)) {
            return;
        }

        $this->validateMinimumSubmissionTime($form);
        $this->validateRateLimit($form);
    }

    public function onFormValidationError(Event $event): void
    {
        $form = $event['form'];
        if (!$form instanceof Form || !$this->isFormProtected($form)) {
            return;
        }

        $isShieldFailure = isset($this->failedForms[$form->getUniqueId()])
            || $this->isShieldCaptchaFailure($form, $event['provider'] ?? null);
        if (!$isShieldFailure) {
            return;
        }

        unset($this->failedForms[$form->getUniqueId()]);

        if ($this->configValue('failure_response.mode', 'message') === 'silent') {
            $event['message'] = '';
            $event['messages'] = [];
            $form->status = 'error';
            $form->message = '';
            $form->messages = [];

            return;
        }

        $message = $this->failureMessage();
        $event['message'] = $message;
        $event['messages'] = [];
        $form->status = 'error';
        $form->message = $message;
        $form->messages = [];
    }

    private function validateMinimumSubmissionTime(Form $form): void
    {
        if (!$this->configValue('time_check.enabled', true)) {
            return;
        }

        $token = $form->value(self::TIME_FIELD);
        if (!is_string($token) || preg_match('/^(\d{10})\.([a-f0-9]{64})$/', $token, $matches) !== 1) {
            $this->grav['log']->warning('Form Shield rejected an invalid timing token.');
            $this->rejectSubmission($form);
        }

        $issuedAt = (int)$matches[1];
        $signature = $matches[2];
        $route = $form->getPage()->route();
        $now = time();
        $maximumAge = max(60, (int)$this->configValue('time_check.maximum_age_seconds', 7200));
        $expected = $this->signTimeToken((string)$issuedAt, $route);

        if ($issuedAt > $now || $issuedAt < $now - $maximumAge || !hash_equals($expected, $signature)) {
            $this->grav['log']->warning('Form Shield rejected an invalid timing token.');
            $this->rejectSubmission($form);
        }

        $minimumSeconds = max(0, (int)$this->configValue('time_check.minimum_seconds', 5));
        if ($now - $issuedAt < $minimumSeconds) {
            $this->grav['log']->warning('Form Shield rejected a form submitted too quickly.');
            $this->rejectSubmission($form);
        }
    }

    private function validateRateLimit(Form $form): void
    {
        if (!$this->configValue('rate_limit.enabled', true)) {
            return;
        }

        $ipAddress = Uri::ip();
        if ($ipAddress === 'UNKNOWN') {
            return;
        }

        $windowSeconds = max(60, (int)$this->configValue('rate_limit.window_seconds', 600));
        $maximumAttempts = max(1, (int)$this->configValue('rate_limit.maximum_attempts', 3));
        $cache = $this->grav['cache']->getSimpleCache();
        $cacheKey = 'form-shield-rate-' . hash('sha256', $ipAddress);
        $now = time();
        $attempts = $cache->get($cacheKey, []);
        $attempts = is_array($attempts) ? $attempts : [];
        $attempts = array_values(array_filter($attempts, static function ($timestamp) use ($now, $windowSeconds): bool {
            return is_int($timestamp) && $timestamp > $now - $windowSeconds;
        }));

        if (count($attempts) >= $maximumAttempts) {
            $cache->set($cacheKey, $attempts, $windowSeconds);
            $this->grav['log']->warning('Form Shield rejected a rate-limited form submission.');
            $this->rejectSubmission($form);
        }

        $attempts[] = $now;
        $cache->set($cacheKey, $attempts, $windowSeconds);
    }

    private function rejectSubmission(Form $form): void
    {
        $this->failedForms[$form->getUniqueId()] = true;

        throw new ValidationException($this->failureMessage());
    }

    private function failureMessage(): string
    {
        $message = trim((string)$this->configValue('failure_response.message', ''));

        return $message !== '' ? $message : $this->translate('FAILURE_MESSAGE');
    }

    private function isFormProtected(Form $form): bool
    {
        try {
            return $this->isRouteProtected($form->getPage()->route());
        } catch (\LogicException $exception) {
            return false;
        }
    }

    private function isAdminRequest(): bool
    {
        if ($this->isAdmin()) {
            return true;
        }

        $admin2Route = trim((string)$this->grav['config']->get('plugins.admin2.route', ''), '/');
        if ($admin2Route === '') {
            return false;
        }

        // Admin2 serves its SPA before the API proxy is registered.
        $route = trim($this->grav['uri']->route(), '/');

        return $route === $admin2Route || str_starts_with($route, $admin2Route . '/');
    }

    private function isRouteProtected(string $route): bool
    {
        $routes = $this->configValue('routes', []);
        if ($routes === null || $routes === [] || $routes === '') {
            return true;
        }

        if (is_string($routes)) {
            $routes = [$routes];
        }

        if (!is_array($routes)) {
            return false;
        }

        $normalizedRoute = $this->normalizeRoute($route);
        foreach ($routes as $configuredRoute) {
            if (!is_string($configuredRoute)) {
                continue;
            }

            if (trim($configuredRoute) === '*' || $this->normalizeRoute($configuredRoute) === $normalizedRoute) {
                return true;
            }
        }

        return false;
    }

    private function hasFieldOfType(array $fields, array $types): bool
    {
        foreach ($fields as $field) {
            if (!is_array($field)) {
                continue;
            }

            if (in_array($field['type'] ?? null, $types, true)) {
                return true;
            }
        }

        return false;
    }

    private function hasFieldNamed(array $fields, string $name): bool
    {
        foreach ($fields as $field) {
            if (is_array($field) && ($field['name'] ?? null) === $name) {
                return true;
            }
        }

        return false;
    }

    private function isShieldCaptchaFailure(Form $form, $provider): bool
    {
        if ($provider !== 'cap') {
            return false;
        }

        foreach ($form->fields() as $field) {
            if (($field['name'] ?? null) === self::CAPTCHA_FIELD && ($field['form_shield'] ?? false) === true) {
                return true;
            }
        }

        return false;
    }

    private function hasCaptchaAction(array $process): bool
    {
        foreach ($process as $action => $params) {
            if (is_int($action) && is_array($params)) {
                $action = array_key_first($params);
            }

            if (in_array($action, ['captcha', 'cap', 'basic-captcha', 'turnstile'], true)) {
                return true;
            }
        }

        return false;
    }

    private function createTimeToken(string $route): string
    {
        $issuedAt = (string)time();

        return $issuedAt . '.' . $this->signTimeToken($issuedAt, $route);
    }

    private function signTimeToken(string $issuedAt, string $route): string
    {
        return hash_hmac('sha256', $issuedAt . '|' . $this->normalizeRoute($route), Security::getNonceKey());
    }

    private function honeypotFieldName(): string
    {
        return 'form_shield_' . substr(hash_hmac('sha256', 'honeypot', Security::getNonceKey()), 0, 12);
    }

    private function translate(string $key): string
    {
        return $this->grav['language']->translate('PLUGIN_FORM_SHIELD.' . $key);
    }

    private function normalizeRoute(string $route): string
    {
        $route = '/' . trim($route, '/');

        return $route === '/' ? $route : rtrim($route, '/');
    }

    private function configValue(string $path, $default = null)
    {
        return $this->config->get('plugins.form-shield.' . $path, $default);
    }
}

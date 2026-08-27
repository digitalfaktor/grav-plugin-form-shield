<?php

namespace Grav\Plugin;

use Grav\Common\Data\ValidationException;
use Grav\Common\Plugin;
use Grav\Plugin\Form\Form;
use RocketTheme\Toolbox\Event\Event;

class FormShieldPlugin extends Plugin
{
    private const SESSION_KEY = 'form_shield_started';

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
            'onFormInitialized' => ['onFormInitialized', 0],
            'onFormValidationProcessed' => ['onFormValidationProcessed', 100],
            'onFormValidationError' => ['onFormValidationError', 100],
        ]);
    }

    public function onFormPageHeaderProcessed(Event $event): void
    {
        $page = $event['page'];
        $route = $page->route();
        if (!is_string($route) || $route === '' || !$this->isRouteProtected($route)) {
            return;
        }

        $header = $event['header'];
        if (is_array($header->form ?? null)) {
            $header->form = $this->protectForm($header->form);
        }

        $forms = $header->forms ?? null;
        if (is_array($forms)) {
            foreach ($forms as $name => $form) {
                if (is_array($form)) {
                    $forms[$name] = $this->protectForm($form);
                }
            }

            $header->forms = $forms;
        }
    }

    private function protectForm(array $form): array
    {
        $form['fields'] = is_array($form['fields'] ?? null) ? $form['fields'] : [];
        if ($this->configValue('honeypot.enabled', true) && !$this->hasFieldOfType($form['fields'], ['honeypot'])) {
            $form['fields'][] = [
                'name' => 'form_shield_website',
                'type' => 'honeypot',
                'label' => 'Website',
                'validate' => ['required' => false],
            ];
        }

        if ($this->configValue('captcha.enabled', true)) {
            if (!$this->hasFieldOfType($form['fields'], ['captcha', 'cap', 'basic-captcha', 'recaptcha', 'turnstile'])) {
                if (!class_exists('Grav\\Plugin\\Form\\Captcha\\CapProvider')) {
                    $this->grav['log']->error('Form Shield requires the Cap captcha provider from Form plugin 9.1.23 or newer.');
                    return $form;
                }

                $form['fields'][] = [
                    'name' => 'form_shield_captcha',
                    'type' => 'captcha',
                    'provider' => 'cap',
                    'mode' => $this->configValue('captcha.mode', 'invisible'),
                    'captcha_not_validated' => 'The security check could not be completed. Please try again.',
                ];
            }

            $process = is_array($form['process'] ?? null) ? $form['process'] : [];
            if (!$this->hasCaptchaAction($process)) {
                $form['process'] = ['captcha' => true] + $process;
            }
        }

        return $form;
    }

    public function onFormInitialized(Event $event): void
    {
        if (!$this->configValue('time_check.enabled', true) || $this->isFormSubmission()) {
            return;
        }

        $form = $event['form'];
        if (!$form instanceof Form || !$this->isFormProtected($form)) {
            return;
        }

        $entries = $this->getStartedForms();
        $now = time();
        $maximumAge = max(60, (int)$this->configValue('time_check.maximum_age_seconds', 7200));

        foreach ($entries as $id => $startedAt) {
            if (!is_int($startedAt) || $startedAt < $now - $maximumAge) {
                unset($entries[$id]);
            }
        }

        $entries[$form->getUniqueId()] = $now;
        $this->grav['session']->{self::SESSION_KEY} = $entries;
    }

    public function onFormValidationProcessed(Event $event): void
    {
        $form = $event['form'];
        if (!$form instanceof Form || !$this->isFormProtected($form)) {
            return;
        }

        $this->validateHoneypot($form);
        $this->validateMinimumSubmissionTime($form);
        $this->validateRateLimit($form);
    }

    public function onFormValidationError(Event $event): void
    {
        $form = $event['form'];
        if (!$form instanceof Form || !$this->isFormProtected($form)) {
            return;
        }

        $isCapFailure = ($event['provider'] ?? null) === 'cap';
        $isShieldFailure = isset($this->failedForms[$form->getUniqueId()]) || $isCapFailure;
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

    private function validateHoneypot(Form $form): void
    {
        foreach ($form->fields() as $field) {
            if (($field['type'] ?? null) === 'honeypot' && !empty($form->value($field['name']))) {
                $this->rejectSubmission($form);
            }
        }
    }

    private function validateMinimumSubmissionTime(Form $form): void
    {
        if (!$this->configValue('time_check.enabled', true)) {
            return;
        }

        $entries = $this->getStartedForms();
        $startedAt = $entries[$form->getUniqueId()] ?? null;
        unset($entries[$form->getUniqueId()]);
        $this->grav['session']->{self::SESSION_KEY} = $entries;

        if (!is_int($startedAt)) {
            return;
        }

        $minimumSeconds = max(0, (int)$this->configValue('time_check.minimum_seconds', 5));
        if (time() - $startedAt < $minimumSeconds) {
            $this->grav['log']->warning('Form Shield rejected a form submitted too quickly.');
            $this->rejectSubmission($form);
        }
    }

    private function validateRateLimit(Form $form): void
    {
        if (!$this->configValue('rate_limit.enabled', true)) {
            return;
        }

        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!is_string($ipAddress) || $ipAddress === '') {
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
        $attempts[] = $now;
        $cache->set($cacheKey, $attempts, $windowSeconds);

        if (count($attempts) > $maximumAttempts) {
            $this->grav['log']->warning('Form Shield rejected a rate-limited form submission.');
            $this->rejectSubmission($form);
        }
    }

    private function rejectSubmission(Form $form): void
    {
        $this->failedForms[$form->getUniqueId()] = true;

        throw new ValidationException($this->failureMessage());
    }

    private function failureMessage(): string
    {
        return (string)$this->configValue(
            'failure_response.message',
            'We could not process your submission. Please try again.'
        );
    }

    private function isFormProtected(Form $form): bool
    {
        try {
            return $this->isRouteProtected($form->getPage()->route());
        } catch (\LogicException $exception) {
            return false;
        }
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

    private function getStartedForms(): array
    {
        $entries = $this->grav['session']->{self::SESSION_KEY} ?? [];

        return is_array($entries) ? $entries : [];
    }

    private function isFormSubmission(): bool
    {
        return !empty($_POST['form-nonce']);
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

<?php declare(strict_types=1);

namespace LockoutTest;

use CommonTest\AbstractHttpControllerTestCase;

/**
 * Tests for the config form of the module.
 *
 * The module page has its own csrf token, checked by the core, and the config
 * form of the module has another one, checked by the module.
 */
class ConfigFormTest extends AbstractHttpControllerTestCase
{
    protected array $managedSettings = [
        'lockout_allowed_retries',
        'lockout_lockout_duration',
        'lockout_allowed_lockouts',
        'lockout_long_duration',
        'lockout_valid_duration',
        'lockout_whitelist',
        'lockout_lockout_notify',
        'lockout_notify_email_after',
        'lockout_lockouts',
        'lockout_lockouts_total',
        'lockout_logs',
    ];

    protected array $savedSettings = [];

    public function setUp(): void
    {
        parent::setUp();
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        foreach ($this->managedSettings as $key) {
            $this->savedSettings[$key] = $settings->get($key);
        }
    }

    public function tearDown(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        foreach ($this->savedSettings as $key => $value) {
            $settings->set($key, $value);
        }
        parent::tearDown();
    }

    /**
     * Post the config form of the module.
     *
     * @param array $data Settings to post.
     * @param bool $withCsrf Add a valid token for the form of the module.
     */
    protected function postConfig(array $data, bool $withCsrf = true): void
    {
        // Each dispatch resets the application and its session, so the tokens
        // are created after the reset, then the request is run directly.
        $this->reset();
        $this->getApplication();
        $this->loginAsAdmin();
        $data['module_Lockout_configure_csrf'] = (new \Laminas\Form\Element\Csrf('module_Lockout_configure_csrf'))->getValue();
        if ($withCsrf) {
            $data['csrf'] = (new \Laminas\Form\Element\Csrf('csrf'))->getValue();
        }
        $this->url('/admin/module/configure?id=Lockout', 'POST', $data);
        $this->getApplication()->run();
    }

    protected function defaultPost(): array
    {
        return [
            'lockout_allowed_retries' => '5',
            'lockout_lockout_duration' => '1200',
            'lockout_allowed_lockouts' => '4',
            'lockout_long_duration' => '86400',
            'lockout_valid_duration' => '43200',
            'lockout_whitelist' => '',
            'lockout_notify_email_after' => '4',
        ];
    }

    protected function settings()
    {
        return $this->getApplication()->getServiceManager()->get('Omeka\Settings');
    }

    public function testConfigFormRendersCsrfToken(): void
    {
        $this->dispatch('/admin/module/configure?id=Lockout');
        $this->assertResponseStatusCode(200);
        $this->assertQuery('input[type="hidden"][name="csrf"]');
        $this->assertQuery('input[name="lockout_allowed_retries"]');
    }

    /**
     * The reset checkboxes are not displayed when there is nothing to reset and
     * an unchecked multicheckbox is not submitted: the form is still saved.
     */
    public function testSaveWithoutOptionalFields(): void
    {
        $data = $this->defaultPost();
        $data['lockout_allowed_retries'] = '7';
        $this->postConfig($data);

        $this->assertResponseStatusCode(302);
        $this->assertSame(7, $this->settings()->get('lockout_allowed_retries'));
        $this->assertSame([], $this->settings()->get('lockout_lockout_notify'));
    }

    public function testSaveNotificationsAndWhitelist(): void
    {
        $data = $this->defaultPost();
        $data['lockout_lockout_notify'] = ['log', 'email'];
        $data['lockout_whitelist'] = "192.0.2.1\n\n2001:db8::1\n";
        $this->postConfig($data);

        $this->assertResponseStatusCode(302);
        $this->assertSame(['log', 'email'], $this->settings()->get('lockout_lockout_notify'));
        $this->assertSame(['192.0.2.1', '2001:db8::1'], array_values($this->settings()->get('lockout_whitelist')));
    }

    public function testResetCheckboxesClearData(): void
    {
        $this->settings()->set('lockout_lockouts_total', 3);
        $this->settings()->set('lockout_logs', ['192.0.2.1' => ['admin' => 2]]);

        $data = $this->defaultPost();
        $data['lockout_clear_total_lockouts'] = '1';
        $data['lockout_clear_logs'] = '1';
        $this->postConfig($data);

        $this->assertResponseStatusCode(302);
        $this->assertSame(0, $this->settings()->get('lockout_lockouts_total'));
        $this->assertSame([], $this->settings()->get('lockout_logs'));
    }

    /**
     * The token of the core page is valid, but not the one of the module form.
     */
    public function testSaveWithoutModuleCsrfIsRefused(): void
    {
        $this->settings()->set('lockout_allowed_retries', 5);

        $data = $this->defaultPost();
        $data['lockout_allowed_retries'] = '9';
        $this->postConfig($data, false);

        $this->assertResponseStatusCode(200);
        $this->assertSame(5, $this->settings()->get('lockout_allowed_retries'));
    }
}

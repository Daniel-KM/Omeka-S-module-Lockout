<?php declare(strict_types=1);

namespace LockoutTest\Controller;

use CommonTest\AbstractHttpControllerTestCase;

/**
 * Tests for the Lockout login controller.
 *
 * Covers regression of DivisionByZeroError when lockout settings are 0.
 */
class LoginControllerTest extends AbstractHttpControllerTestCase
{
    /**
     * Login routes are public.
     */
    protected bool $requiresLogin = false;

    /**
     * Settings to restore after each test.
     */
    protected array $savedSettings = [];

    protected array $managedSettings = [
        'lockout_allowed_retries',
        'lockout_allowed_lockouts',
        'lockout_notify_email_after',
        'lockout_valid_duration',
        'lockout_lockout_duration',
        'lockout_long_duration',
        'lockout_retries',
        'lockout_valids',
        'lockout_lockouts',
        'lockout_lockouts_total',
        'lockout_logs',
        'lockout_whitelist',
        'lockout_trusted_proxies',
    ];

    /**
     * $_SERVER keys touched by tests, to be restored in tearDown.
     */
    protected array $savedServer = [];

    public function setUp(): void
    {
        parent::setUp();
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        foreach ($this->managedSettings as $key) {
            $this->savedSettings[$key] = $settings->get($key);
        }
        // Always start with a clean retry/valid/lockout state.
        $settings->set('lockout_retries', []);
        $settings->set('lockout_valids', []);
        $settings->set('lockout_lockouts', []);

        foreach (['REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR'] as $key) {
            $this->savedServer[$key] = $_SERVER[$key] ?? null;
        }
    }

    public function tearDown(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        foreach ($this->savedSettings as $key => $value) {
            $settings->set($key, $value);
        }
        foreach ($this->savedServer as $key => $value) {
            if ($value === null) {
                unset($_SERVER[$key]);
            } else {
                $_SERVER[$key] = $value;
            }
        }
        parent::tearDown();
    }

    /**
     * GET /login renders the login form via the Lockout controller.
     */
    public function testLoginRouteUsesLockoutController(): void
    {
        $this->dispatch('/login');
        // Lockout overrides the Omeka login controller via the service manager,
        // so the route name stays 'Omeka\Controller\Login' but the instantiated
        // class is the Lockout one.
        $this->assertControllerName('omeka\controller\login');
        $this->assertActionName('login');
        $this->assertResponseStatusCode(200);

        $controllers = $this->getApplication()->getServiceManager()
            ->get('ControllerManager');
        $controller = $controllers->get('Omeka\Controller\Login');
        $this->assertInstanceOf(\Lockout\Controller\LoginController::class, $controller);
    }

    /**
     * Invalid credentials with default settings must not trigger a fatal error.
     */
    public function testInvalidCredentialsWithDefaultSettings(): void
    {
        $this->dispatch('/login', 'POST', [
            'email' => 'unknown@example.com',
            'password' => 'wrong-password',
        ]);
        $this->assertResponseStatusCode(200);
    }

    /**
     * Regression: lockout_allowed_retries = 0 used to throw DivisionByZeroError
     * in updateLockout() and warnRemainingAttempts().
     */
    public function testInvalidCredentialsDoesNotDivideByZeroOnAllowedRetries(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        $settings->set('lockout_allowed_retries', 0);

        $this->dispatch('/login', 'POST', [
            'email' => 'unknown@example.com',
            'password' => 'wrong-password',
        ]);
        $this->assertResponseStatusCode(200);
    }

    /**
     * Regression: lockout_notify_email_after = 0 used to throw
     * DivisionByZeroError when a notification check was performed.
     */
    public function testInvalidCredentialsDoesNotDivideByZeroOnNotifyAfter(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        $settings->set('lockout_allowed_retries', 0);
        $settings->set('lockout_notify_email_after', 0);
        $settings->set('lockout_retries', ['127.0.0.1' => 1]);
        $settings->set('lockout_valids', ['127.0.0.1' => time() + 3600]);

        $this->dispatch('/login', 'POST', [
            'email' => 'unknown@example.com',
            'password' => 'wrong-password',
        ]);
        $this->assertResponseStatusCode(200);
    }

    /**
     * Repeated invalid attempts must not trigger a fatal error and must
     * eventually lock the form.
     */
    public function testRepeatedInvalidCredentials(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        $allowed = (int) $settings->get('lockout_allowed_retries') ?: 4;

        for ($i = 0; $i < $allowed + 1; $i++) {
            $this->reset(true);
            $this->dispatch('/login', 'POST', [
                'email' => 'unknown@example.com',
                'password' => 'wrong-password',
            ]);
            $this->assertResponseStatusCode(200);
        }
    }

    /**
     * Regression: triggering an actual lockout used to fail with "Cannot
     * increment array" when lockout_lockouts_total drifted to a non-scalar
     * value in storage.
     */
    public function testLockoutTriggerIncrementsTotalCounter(): void
    {
        $services = $this->getApplication()->getServiceManager();
        $settings = $services->get('Omeka\Settings');
        $_SERVER['REMOTE_ADDR'] = '10.0.0.42';

        // Drift scenario: counter stored as array in DB (upgrade from older
        // versions or corruption). The controller must recover, not crash.
        $settings->set('lockout_lockouts_total', []);
        $settings->set('lockout_allowed_retries', 2);
        $settings->set('lockout_retries', ['10.0.0.42' => 1]);
        $settings->set('lockout_valids', ['10.0.0.42' => time() + 3600]);

        $controllers = $services->get('ControllerManager');
        /** @var \Lockout\Controller\LoginController $controller */
        $controller = $controllers->get('Omeka\Controller\Login');

        $ref = new \ReflectionMethod($controller, 'updateLockout');
        $ref->setAccessible(true);
        $ref->invoke($controller, 'attacker@example.com');

        $this->assertSame(1, (int) $settings->get('lockout_lockouts_total'));
    }

    /**
     * Regression: whitelisted IPs were previously locked out by the inverted
     * isLockout() check. Even with an active lockout entry in DB, a whitelisted
     * IP must NOT see the form disabled.
     */
    public function testWhitelistedIpIsNotLockedOut(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        $settings->set('lockout_whitelist', ['127.0.0.1']);
        $settings->set('lockout_lockouts', ['127.0.0.1' => time() + 3600]);

        $this->dispatch('/login');
        $this->assertResponseStatusCode(200);
        // Form must be enabled.
        $this->assertNotQuery('input[name="email"][disabled]');
    }

    /**
     * Regression: forgot-password was not rate-limited, allowing email
     * enumeration and unbounded mail dispatch.
     */
    public function testForgotPasswordIsRateLimited(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $_SERVER['REMOTE_ADDR'] = $ip;
        $settings->set('lockout_lockouts', [$ip => time() + 3600]);

        $this->dispatch('/forgot-password');
        // Locked out: must redirect to login.
        $this->assertResponseStatusCode(302);
    }

    /**
     * Regression: X-Forwarded-For must NOT be honored unless REMOTE_ADDR is in
     * the trusted proxies list.
     */
    public function testProxyHeaderIgnoredWithoutTrustedProxy(): void
    {
        $settings = $this->getApplication()->getServiceManager()->get('Omeka\Settings');
        $settings->set('lockout_trusted_proxies', []);
        // Lock out a fake "client" IP that comes only from the header.
        $settings->set('lockout_lockouts', ['1.2.3.4' => time() + 3600]);

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4';

        $this->dispatch('/login');
        // Must not be locked out: header was ignored.
        $this->assertNotQuery('input[name="email"][disabled]');

        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    }
}

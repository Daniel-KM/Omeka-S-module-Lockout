<?php declare(strict_types=1);

namespace Lockout\Controller;

use Laminas\Session\Container;
use Laminas\View\Model\ViewModel;
use Omeka\Controller\LoginController as OmekaLoginController;
use Omeka\Form\LoginForm;

class LoginController extends OmekaLoginController
{
    const DIRECT_ADDR = 'REMOTE_ADDR';
    const PROXY_ADDR = 'HTTP_X_FORWARDED_FOR';

    /**
     * Manage the login.
     *
     * Slightly adapted from the parent class.
     *
     * {@inheritDoc}
     * @see \Omeka\Controller\LoginController::loginAction()
     */
    public function loginAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->redirect()->toRoute('admin');
        }

        $this->cleanupLockout();

        $form = $this->getForm(LoginForm::class);

        if ($this->isLockout()) {
            $this->disableForm($form);
        } elseif ($this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form->setData($data);
            if ($form->isValid()) {
                // Create a new session, avoiding the warning in case of error.
                // Avoid warning: session_regenerate_id(): Session object destruction
                // failed when session save handler has issues.
                // See /vendor/laminas/laminas-session/src/SessionManager.php on line 337.
                $sessionManager = Container::getDefaultManager();
                @$sessionManager->regenerateId();
                $validatedData = $form->getData();
                $adapter = $this->auth->getAdapter();
                $adapter->setIdentity($validatedData['email']);
                $adapter->setCredential($validatedData['password']);
                $result = $this->auth->authenticate();
                if ($result->isValid()) {
                    $this->messenger()->addSuccess('Successfully logged in'); // @translate
                    $eventManager = $this->getEventManager();
                    $eventManager->trigger('user.login', $this->auth->getIdentity());
                    $session = $sessionManager->getStorage();
                    $this->resetLockout();
                    if ($redirectUrl = $session->offsetGet('redirect_url')) {
                        return $this->redirect()->toUrl($redirectUrl);
                    }
                    return $this->redirect()->toRoute('admin');
                }
                $this->messenger()->addError('Email or password is invalid'); // @translate
                $this->updateLockout($validatedData['email']);
                $result = $this->checkLimitLogin();
                if ($result === false) {
                    $this->disableForm($form);
                } elseif ($result !== true) {
                    $this->messenger()->addWarning($result);
                }
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        $view = new ViewModel;
        $view->setTemplate('omeka/login/login');
        $view->setVariable('form', $form);
        return $view;
    }

    public function createPasswordAction()
    {
        $result = parent::createPasswordAction();
        if (is_object($result) && $result instanceof ViewModel) {
            $result->setTemplate('omeka/login/create-password');
        }
        return $result;
    }

    public function forgotPasswordAction()
    {
        $result = parent::forgotPasswordAction();
        if (is_object($result) && $result instanceof ViewModel) {
            $result->setTemplate('omeka/login/forgot-password');
        }
        return $result;
    }

    /**
     * Clean up old lockouts and retries, and save supplied arrays.
     *
     * @param array $retries
     * @param array $lockouts
     * @param array $valids
     */
    protected function cleanupLockout(?array $retries = null, ?array $lockouts = null, ?array $valids = null): void
    {
        /**
         * @var \Omeka\Mvc\Controller\Plugin\Settings $settings
         */
        $settings = $this->settings();

        $now = time();
        if ($lockouts === null) {
            $lockouts = $settings->get('lockout_lockouts', []);
        }

        // Remove old lockouts.
        foreach ($lockouts as $ip => $lockout) {
            if ($lockout < $now) {
                unset($lockouts[$ip]);
            }
        }
        $settings->set('lockout_lockouts', $lockouts);

        // Remove retries that are no longer valid.
        if ($valids === null) {
            $valids = $settings->get('lockout_valids', []);
        }
        if ($retries === null) {
            $retries = $settings->get('lockout_retries', []);
        }
        if (!is_array($valids) || !is_array($retries)) {
            return;
        }

        foreach ($valids as $ip => $lockout) {
            if ($lockout < $now) {
                unset($valids[$ip]);
                unset($retries[$ip]);
            }
        }

        // Go through retries directly, if for some reason they've gone out of sync.
        foreach (array_keys($retries) as $ip) {
            if (!isset($valids[$ip])) {
                unset($retries[$ip]);
            }
        }

        $settings->set('lockout_valids', $valids);
        $settings->set('lockout_retries', $retries);
    }

    /**
     * Check if the ip is lockout.
     *
     * @return bool
     */
    protected function isLockout()
    {
        $ip = $this->getAddress();
        if ($this->isIpWhitelisted($ip)) {
            return true;
        }

        // Lockout active?
        $lockouts = $this->settings()->get('lockout_lockouts', []);
        return is_array($lockouts)
            && isset($lockouts[$ip])
            && time() < $lockouts[$ip];
    }

    /**
     * Reset the lockout for an ip (no check is done).
     *
     * @param string $ip
     */
    protected function resetLockout(): void
    {
        $ip = $this->getAddress();
        $lockouts = $this->settings()->get('lockout_lockouts', []);
        unset($lockouts[$ip]);
    }

    /**
     * Update the lockout for an ip when failed attempt.
     *
     * It increases the number of retries if needed, reset the valid value.
     * It sets up lockout if number of retries are above threshold.
     *
     * A note on whitelist: retries and statistics are still counted and
     * notifications done as usual, but no lockout is done.
     *
     * @param string $user
     */
    protected function updateLockout($user): void
    {
        /**
         * @var \Omeka\Mvc\Controller\Plugin\Settings $settings
         */
        $settings = $this->settings();

        $now = time();
        $ip = $this->getAddress();

        // If currently locked-out, do not add to retries.
        $lockouts = $settings->get('lockout_lockouts', []);
        if (is_array($lockouts) && isset($lockouts[$ip]) && $now < $lockouts[$ip]) {
            return;
        }

        // Get the arrays with retries and retries-valid information.
        $valids = $settings->get('lockout_valids', []);
        $retries = $settings->get('lockout_retries', []);

        // Check validity and increment retries.
        if (isset($retries[$ip]) && isset($valids[$ip]) && $now < $valids[$ip]) {
            ++$retries[$ip];
        } else {
            $retries[$ip] = 1;
        }
        $valids[$ip] = $now + $this->settingInt('lockout_valid_duration', 43200);

        // Lockout?
        $allowedRetries = $this->settingInt('lockout_allowed_retries', 4);
        if ($retries[$ip] % $allowedRetries !== 0) {
            // Not lockout (yet!). Do housecleaning (which also saves
            // retry/valid values).
            $this->cleanupLockout($retries, null, $valids);
            return;
        }

        // Lockout!.
        $whitelisted = $this->isIpWhitelisted($ip);
        $retriesLong = $allowedRetries * $this->settingInt('lockout_allowed_lockouts', 4);

        // Note that retries and statistics are still counted and notifications
        // done as usual for whitelisted ips , but no lockout is done.
        if ($whitelisted) {
            if ($retries[$ip] >= $retriesLong) {
                unset($retries[$ip]);
                unset($valids[$ip]);
            }
        } else {
            // Setup lockout, reset retries as needed.
            if ($retries[$ip] >= $retriesLong) {
                // Long lockout.
                $lockouts[$ip] = $now + $this->settingInt('lockout_long_duration', 86400);
                unset($retries[$ip]);
                unset($valids[$ip]);
            } else {
                // Normal lockout.
                $lockouts[$ip] = $now + $this->settingInt('lockout_lockout_duration', 1200);
            }
        }

        // Do housecleaning and save values.
        $this->cleanupLockout($retries, $lockouts, $valids);

        // Do any notification.
        $this->notifyLockout($user);

        // Increase statistics.
        $total = $settings->get('lockout_lockouts_total', 0);
        $settings->set('lockout_lockouts_total', ++$total);
    }

    /**
     * Check if IP is whitelisted.
     *
     * @param string $ip
     * @return bool
     */
    protected function isIpWhitelisted($ip = null)
    {
        if ($ip === null) {
            $ip = $this->getAddress();
        }
        return in_array($ip, (array) $this->settings()->get('lockout_whitelist', []), true);
    }

    /**
     * Read an integer setting with a strictly positive fallback.
     *
     * Lockout durations and counters are used in modulos and as time offsets; a
     * stored 0/null would silently break the algorithm.
     */
    protected function settingInt(string $name, int $default): int
    {
        $value = (int) $this->settings()->get($name);
        return $value > 0 ? $value : $default;
    }

    /**
     * Get correct remote address.
     *
     * When the proxy type is requested, the X-Forwarded-For header is only
     * trusted if REMOTE_ADDR appears in the configured trusted proxies list.
     * Otherwise, the direct address is used. This prevents IP spoofing when the
     * server is directly exposed to the Internet.
     *
     * @param string $typeName Direct address or proxy address.
     * @return string
     */
    protected function getAddress($typeName = '')
    {
        $type = $typeName;
        if (empty($type)) {
            $type = self::DIRECT_ADDR;
        }

        $directAddr = $_SERVER[self::DIRECT_ADDR] ?? '';

        if ($type === self::PROXY_ADDR) {
            $trustedProxies = $this->settings()->get('lockout_trusted_proxies', []);
            if (!is_array($trustedProxies) || !in_array($directAddr, $trustedProxies, true)) {
                return $directAddr;
            }
            $forwarded = $_SERVER[self::PROXY_ADDR] ?? '';
            if ($forwarded === '') {
                return $directAddr;
            }
            // X-Forwarded-For is a comma-separated list; the leftmost
            // non-trusted entry is the original client.
            $chain = array_map('trim', explode(',', $forwarded));
            foreach ($chain as $candidate) {
                if ($candidate !== ''
                    && filter_var($candidate, FILTER_VALIDATE_IP)
                    && !in_array($candidate, $trustedProxies, true)
                ) {
                    return $candidate;
                }
            }
            return $directAddr;
        }

        if (isset($_SERVER[$type])) {
            return $_SERVER[$type];
        }

        // Default fallback (no header for the requested type).
        return $directAddr;
    }

    /**
     * Return current (error) message to show, if any.
     *
     * @return string|bool If string, this is a warning. If true, login is
     * allowed, else login is forbidden.
     */
    protected function checkLimitLogin()
    {
        if ($this->isIpWhitelisted()) {
            return true;
        }

        if ($this->isLockout()) {
            return false;
        }

        return $this->warnRemainingAttempts();
    }

    /**
     * Add a warning for the retries remaining.
     */
    protected function warnRemainingAttempts()
    {
        /**
         * @var \Omeka\Mvc\Controller\Plugin\Settings $settings
         */
        $settings = $this->settings();

        $now = time();
        $ip = $this->getAddress();

        $retries = $settings->get('lockout_retries');
        $valids = $settings->get('lockout_valids');

        // Should we show retries remaining?
        // No retries at all.
        if (!is_array($retries) || !is_array($valids)) {
            return '';
        }
        // No valid retries.
        if (!isset($retries[$ip]) || !isset($valids[$ip]) || $now > $valids[$ip]) {
            return '';
        }
        $allowedRetries = $this->settingInt('lockout_allowed_retries', 4);
        // Already been locked out for these retries.
        if (($retries[$ip] % $allowedRetries) == 0) {
            return '';
        }

        $remaining = max(
            $allowedRetries - ($retries[$ip] % $allowedRetries),
            0);

        $message = $remaining <= 1
            ? sprintf('%d attempt remaining.', $remaining) // @translate
            : sprintf('%d attempts remaining.', $remaining); // @translate

        return $message;
    }

    /**
     * Construct informative error message.
     *
     * @return string
     */
    protected function errorMsg()
    {
        $now = time();
        $ip = $this->getAddress();
        $settings = $this->settings();
        $lockouts = $settings->get('lockout_lockouts', []);

        $msg = 'Error: Too many failed login attempts.'; // @translate
        $msg .= ' ';

        // Huh? No timeout active?
        if (!is_array($lockouts) || !isset($lockouts[$ip]) || $now >= $lockouts[$ip]) {
            $msg .= 'Please try again later.'; // @translate
        } else {
            $when = ceil(($lockouts[$ip] - $now) / 60);
            if ($when > 60) {
                $when = ceil($when / 60);
                $msg .= $when <= 1
                    ? sprintf('Please try again in %d hour.', $when) // @translate
                    : sprintf('Please try again in %d hours.', $when); // @translate
            } else {
                $msg .= $when <= 1
                    ? sprintf('Please try again in %d minute.', $when) // @translate
                    : sprintf('Please try again in %d minutes.', $when); // @translate
            }
        }

        return $msg;
    }

    /**
     * Disable the elemens of the login form.
     *
     * @param LoginForm $form
     */
    protected function disableForm(LoginForm $form): void
    {
        $this->messenger()->addError($this->errorMsg());
        foreach (['email', 'password', 'submit'] as $element) {
            $form->get($element)->setAttributes(['disabled' => 'disabled']);
        }
    }

    /**
     * Handle notification in event of lockout.
     *
     * @param string $user
     */
    protected function notifyLockout($user): void
    {
        $args = $this->settings()->get('lockout_lockout_notify', []);
        if (empty($args)) {
            return;
        }

        foreach ($args as $mode) {
            switch ($mode) {
                case 'log':
                    $this->notifyLog($user);
                    break;
                case 'email':
                    $this->notifyEmail($user);
                    break;
            }
        }
    }

    /**
     * Logging of lockout.
     *
     * @param string $user
     */
    protected function notifyLog($user): void
    {
        /**
         * @var \Omeka\Mvc\Controller\Plugin\Settings $settings
         */
        $settings = $this->settings();

        $ip = $this->getAddress();

        $logs = $settings->get('lockout_logs', []);

        if (isset($logs[$ip][$user])) {
            ++$logs[$ip][$user];
        } else {
            $logs[$ip][$user] = 1;
        }

        $settings->set('lockout_logs', $logs);
    }

    /**
     * Email notification of lockout to admin.
     *
     * @param string $user
     */
    protected function notifyEmail($user): void
    {
        /**
         * @var \Omeka\Mvc\Controller\Plugin\Settings $settings
         */
        $settings = $this->settings();

        $ip = $this->getAddress();
        $whitelisted = $this->isIpWhitelisted($ip);

        $retries = $settings->get('lockout_retries', []);

        $allowedRetries = $this->settingInt('lockout_allowed_retries', 4);
        $notifyAfter = $this->settingInt('lockout_notify_email_after', 1);

        // Check if we are at the right number to do notification.
        if (isset($retries[$ip])
            && (
                intdiv($retries[$ip], $allowedRetries) % $notifyAfter
            ) != 0
        ) {
            return;
        }

        // Format message. First current lockout duration. Longer lockout.
        if (! isset($retries[$ip])) {
            $allowedLockouts = $this->settingInt('lockout_allowed_lockouts', 4);
            $count = $allowedRetries * $allowedLockouts;
            $lockouts = $allowedLockouts;
            $time = (int) round($this->settingInt('lockout_long_duration', 86400) / 3600);
            $when = $time <= 1
                ? sprintf('%d hour', $time) // @translate
                : sprintf('%d hours', $time); // @translate
        }
        // Normal lockout.
        else {
            $count = $retries[$ip];
            $lockouts = intdiv($count, $allowedRetries);
            $time = (int) round($this->settingInt('lockout_lockout_duration', 1200) / 60);
            $when = $time <= 1
                ? sprintf('%d minute', $time) // @translate
                : sprintf('%d minutes', $time); // @translate
        }

        $site = @$_SERVER['SERVER_NAME'] ?: sprintf('Server (%s)', @$_SERVER['SERVER_ADDR']); // @translate
        if ($whitelisted) {
            $subject = sprintf('[%s] Failed login attempts from whitelisted IP.', $site); // @translate
        } else {
            $subject = sprintf('[%s] Too many failed login attempts.', $site); // @translate
        }

        $body = sprintf('%d failed login attempts (%d lockout(s)) from IP: %s.', // @translate
            $count, $lockouts, $ip) . "\r\n\r\n";
        if (empty($user)) {
            $body .= sprintf('Last user attempted: %s.', $user) // @translate
                . "\r\n\r\n";
        }
        if ($whitelisted) {
            $body .= sprintf('IP was NOT blocked because of whitelist.'); // @translate
        } else {
            $body .= sprintf('IP was blocked for %s.', $when); // @translate
        }

        /**
         * Admin email is the default sender in Omeka Mailer, but it can be
         * replaced by a no-reply sender via module EasyAdmin.
         *
         * The method $mailer->createMessage() does not allow to by-pass default
         * options, in particular "from".
         *
         * @see \Omeka\Service\MailerFactory::__invoke()
         *
         * @var \Omeka\Stdlib\Mailer $mailer
         * @var \Omeka\Mvc\Controller\Plugin\Settings $settings
         *
         * @todo Use \Common\Mvc\Controller\Plugin\SendEmail.
         */

        $adminEmail = $settings->get('administrator_email');
        $adminName = $settings->get('administrator_name')
            ?: $settings->get('easyadmin_administrator_name');

        $senderEmail = $settings->get('easyadmin_no_reply_email');
        if ($senderEmail) {
            $senderName = $settings->get('easyadmin_no_reply_name');
        } else {
            $senderEmail = $adminEmail;
            $senderName = $adminName;
        }

        $mailer = $this->mailer();
        $message = $mailer->createMessage();
        $message
            // Use (string), not null, for quick process (avoid to parse email).
            ->setFrom($senderEmail, (string) $senderName)
            ->addTo($adminEmail, (string) $adminName)
            ->setSubject($subject)
            ->setBody($body);
        $mailer->send($message);
    }
}

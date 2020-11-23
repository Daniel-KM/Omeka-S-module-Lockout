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
     * Have we shown our stuff?
     *
     * @var bool
     */
    private $myErrorShown = false;

    /**
     * Started this pageload?
     *
     * @var bool
     */
    private $justLockedout = false;

    /**
     * User and password non empty.
     *
     * @var bool
     */
    private $hasCredentials = false;

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
                $sessionManager = Container::getDefaultManager();
                $sessionManager->regenerateId();
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
    protected function cleanupLockout(array $retries = null, array $lockouts = null, array $valids = null): void
    {
        $now = time();
        if (is_null($lockouts)) {
            $lockouts = $this->settings()->get('lockout_lockouts', []);
        }

        // Remove old lockouts.
        foreach ($lockouts as $ip => $lockout) {
            if ($lockout < $now) {
                unset($lockouts[$ip]);
            }
        }
        $this->settings()->set('lockout_lockouts', $lockouts);

        // Remove retries that are no longer valid.
        if (is_null($valids)) {
            $valids = $this->settings()->get('lockout_valids', []);
        }
        if (is_null($retries)) {
            $retries = $this->settings()->get('lockout_retries', []);
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
        foreach ($retries as $ip => $retry) {
            if (!isset($valids[$ip])) {
                unset($retries[$ip]);
            }
        }

        $this->settings()->set('lockout_valids', $valids);
        $this->settings()->set('lockout_retries', $retries);
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
        $now = time();
        $ip = $this->getAddress();

        // If currently locked-out, do not add to retries.
        $lockouts = $this->settings()->get('lockout_lockouts', []);
        if (is_array($lockouts) && isset($lockouts[$ip]) && $now < $lockouts[$ip]) {
            return;
        }

        // Get the arrays with retries and retries-valid information.
        $valids = $this->settings()->get('lockout_valids', []);
        $retries = $this->settings()->get('lockout_retries', []);

        // Check validity and increment retries.
        if (isset($retries[$ip]) && isset($valids[$ip]) && $now < $valids[$ip]) {
            ++$retries[$ip];
        } else {
            $retries[$ip] = 1;
        }
        $valids[$ip] = $now + $this->settings()->get('lockout_valid_duration');

        // Lockout?
        $allowedRetries = $this->settings()->get('lockout_allowed_retries');
        if ($retries[$ip] % $allowedRetries !== 0) {
            // Not lockout (yet!).
            // Do housecleaning (which also saves retry/valid values).
            $this->cleanupLockout($retries, null, $valids);
            return;
        }

        // Lockout!.
        $whitelisted = $this->isIpWhitelisted($ip);
        $retriesLong = $allowedRetries * $this->settings()->get('lockout_allowed_lockouts');

        // Note that retries and statistics are still counted and notifications
        // done as usual for whitelisted ips , but no lockout is done.
        if ($whitelisted) {
            if ($retries[$ip] >= $retriesLong) {
                unset($retries[$ip]);
                unset($valids[$ip]);
            }
        } else {
            $this->justLockedout = true;

            // Setup lockout, reset retries as needed.
            if ($retries[$ip] >= $retriesLong) {
                // Long lockout.
                $lockouts[$ip] = $now + $this->settings()->get('lockout_long_duration');
                unset($retries[$ip]);
                unset($valids[$ip]);
            } else {
                // Normal lockout.
                $lockouts[$ip] = $now + $this->settings()->get('lockout_lockout_duration');
            }
        }

        // Do housecleaning and save values.
        $this->cleanupLockout($retries, $lockouts, $valids);

        // Do any notification.
        $this->notifyLockout($user);

        // Increase statistics.
        $total = $this->settings()->get('lockout_lockouts_total', 0);
        $this->settings()->set('lockout_lockouts_total', ++$total);
    }

    /**
     * Check if IP is whitelisted.
     *
     * @param string $ip
     * @return bool
     */
    protected function isIpWhitelisted($ip = null)
    {
        if (is_null($ip)) {
            $ip = $this->getAddress();
        }
        return in_array($ip, $this->settings()->get('lockout_whitelist', []));
    }

    /**
     * Get correct remote address.
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

        if (isset($_SERVER[$type])) {
            return $_SERVER[$type];
        }

        // Not found. Did we get proxy type from option?
        // If so, try to fall back to direct address.
        if (empty($type_name) && $type == self::PROXY_ADDR && isset($_SERVER[self::DIRECT_ADDR])) {
            // NOTE: Even though we fall back to direct address -- meaning you
            // can get a mostly working plugin when set to PROXY mode while in
            // fact directly connected to Internet it is not safe!
            //
            // Client can itself send HTTP_X_FORWARDED_FOR header fooling us
            // regarding which IP should be banned.
            return $_SERVER[self::DIRECT_ADDR];
        }

        return '';
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
        $now = time();
        $ip = $this->getAddress();
        $retries = $this->settings()->get('lockout_retries');
        $valids = $this->settings()->get('lockout_valids');

        // Should we show retries remaining?
        // No retries at all.
        if (!is_array($retries) || !is_array($valids)) {
            return '';
        }
        // No valid retries.
        if (!isset($retries[$ip]) || !isset($valids[$ip]) || $now > $valids[$ip]) {
            return '';
        }
        // Already been locked out for these retries.
        if (($retries[$ip] % $this->settings()->get('lockout_allowed_retries')) == 0) {
            return '';
        }

        $remaining = max(
            $this->settings()->get('lockout_allowed_retries')
                - ($retries[$ip] % $this->settings()->get('lockout_allowed_retries')),
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
        $lockouts = $this->settings()->get('lockout_lockouts', []);

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
        $ip = $this->getAddress();
        $logs = $this->settings()->get('lockout_logs', []);

        if (isset($logs[$ip][$user])) {
            ++$logs[$ip][$user];
        } else {
            $logs[$ip][$user] = 1;
        }

        $this->settings()->set('lockout_logs', $logs);
    }

    /**
     * Email notification of lockout to admin.
     *
     * @param string $user
     */
    protected function notifyEmail($user): void
    {
        $ip = $this->getAddress();
        $whitelisted = $this->isIpWhitelisted($ip);

        $retries = $this->settings()->get('lockout_retries', []);

        // Check if we are at the right number to do notification.
        if (isset($retries[$ip])
            && (
                ($retries[$ip] / $this->settings()->get('lockout_allowed_retries', 1))
                    % $this->settings()->get('lockout_notify_email_after', 1)
            ) != 0
        ) {
            return;
        }

        // Format message. First current lockout duration.
        // Longer lockout.
        if (! isset($retries[$ip])) {
            $count = $this->settings()->get('lockout_allowed_retries')
                * $this->settings()->get('lockout_allowed_lockouts');
            $lockouts = $this->settings()->get('lockout_allowed_lockouts');
            $time = round($this->settings()->get('lockout_long_duration') / 3600);
            $when = $time <= 1
                ? sprintf('%d hour', $time) // @translate
                : sprintf('%d hours', $time); // @translate
        }
        // Normal lockout.
        else {
            $count = $retries[$ip];
            $lockouts = floor($count / $this->settings()->get('lockout_allowed_retries'));
            $time = round($this->settings()->get('lockout_lockout_duration') / 60);
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

        $adminEmail = $this->settings()->get('administrator_email');

        $mailer = $this->mailer();
        $message = $mailer->createMessage();
        $message
            ->addTo($adminEmail)
            ->setSubject($subject)
            ->setBody($body);
        $mailer->send($message);
    }

    /*
     * Unported or useless methods or cookies management.
     * See properties too.
     *
     * @todo Port or remove (probably remove all).
     */

    /**
     * Get options and setup filters & actions.
     */
    protected function lockout_setup(): void
    {
        // Filters and actions.
        add_action('wp_login_failed', 'lockout_failed');
        if (lockout_option('cookies')) {
            lockout_handle_cookies();
            add_action('auth_cookie_bad_username', 'lockout_failed_cookie');

            global $wp_version;

            if (version_compare($wp_version, '3.0', '>=')) {
                add_action('auth_cookie_bad_hash', 'lockout_failed_cookie_hash');
                add_action('auth_cookie_valid', 'lockout_valid_cookie', 10, 2);
            } else {
                add_action('auth_cookie_bad_hash', 'lockout_failed_cookie');
            }
        }
        add_filter('wp_authenticate_user', 'lockout_wp_authenticate_user', 99999, 2);
        add_filter('shake_error_codes', 'lockout_failure_shake');
        add_action('login_head', 'lockout_add_error_message');
        add_action('login_errors', 'lockout_fixup_error_messages');
        add_action('admin_menu', 'lockout_admin_menu');

        // This action should really be changed to the 'authenticate' filter as
        // it will probably be deprecated. That is however only available in
        // later versions of WP.
        add_action('wp_authenticate', 'lockout_track_credentials', 10, 2);
    }

    /**
     * Filter: allow login attempt? (called from wp_authenticate()).
     */
    protected function lockout_wp_authenticate_user($user, $password)
    {
        if (is_wp_error($user) || is_lockout_ok()) {
            return $user;
        }

        $this->my_error_shown = true;

        $this->messenger()->addError('Too many retries.'); // @translate
        // $error = new WP_Error();
        // // This error should be the same as in "shake it" filter below.
        // $error->add('too_many_retries', lockout_error_msg());
        // return $error;
    }

    /**
     * Filter: add this failure to login page "Shake it!".
     */
    protected function lockout_failure_shake($error_codes): void
    {
        $this->messenger()->addError('Too many retries.'); // @translate
        // $error_codes[] = 'too_many_retries';
        // return $error_codes;
    }

    /**
     * Must be called in plugin_loaded (really early) to make sure we do not allow
     * auth cookies while locked out.
     */
    protected function lockout_handle_cookies(): void
    {
        if (is_lockout_ok()) {
            return;
        }

        lockout_clear_auth_cookie();
    }

    /**
     * Action: failed cookie login hash
     *
     * Make sure same invalid cookie doesn't get counted more than once.
     *
     * Requires WordPress version 3.0.0, previous versions use lockout_failed_cookie()
     */
    protected function lockout_failed_cookie_hash($cookie_elements): void
    {
        lockout_clear_auth_cookie();

        // Under some conditions an invalid auth cookie will be used multiple
        // times, which results in multiple failed attempts from that one
        // cookie.
        //
        // Unfortunately I've not been able to replicate this consistently and
        // thus have not been able to make sure what the exact cause is.
        //
        // Probably it is because a reload of for example the admin dashboard
        // might result in multiple requests from the browser before the invalid
        // cookie can be cleard.
        //
        // Handle this by only counting the first attempt when the exact same
        // cookie is attempted for a user.
        extract($cookie_elements, EXTR_OVERWRITE);

        // Check if cookie is for a valid user
        $user = get_userdatabylogin($username);
        if (! $user) {
            // "shouldn't happen" for this action
            lockout_failed($username);
            return;
        }

        $previous_cookie = get_user_meta($user->ID, 'lockout_previous_cookie', true);
        if ($previous_cookie && $previous_cookie == $cookie_elements) {
            // Identical cookies, ignore this attempt
            return;
        }

        // Store cookie
        if ($previous_cookie) {
            update_user_meta($user->ID, 'lockout_previous_cookie', $cookie_elements);
        } else {
            add_user_meta($user->ID, 'lockout_previous_cookie', $cookie_elements, true);
        }

        lockout_failed($username);
    }

    /**
     * Action: successful cookie login.
     *
     * Clear any stored user_meta.
     *
     * Requires WordPress version 3.0.0, not used in previous versions
     */
    protected function lockout_valid_cookie($cookie_elements, $user): void
    {
        // As all meta values get cached on user load this should not require
        // any extra work for the common case of no stored value.
        if (get_user_meta($user->ID, 'lockout_previous_cookie')) {
            delete_user_meta($user->ID, 'lockout_previous_cookie');
        }
    }

    /**
     * Action: failed cookie login (calls lockout_failed()).
     */
    protected function lockout_failed_cookie($cookie_elements): void
    {
        lockout_clear_auth_cookie();

        // Invalid username gets counted every time.
        lockout_failed($cookie_elements['username']);
    }

    /**
     * Make sure auth cookie really get cleared (for this session too).
     */
    protected function lockout_clear_auth_cookie(): void
    {
        wp_clear_auth_cookie();

        if (! empty($_COOKIE[AUTH_COOKIE])) {
            $_COOKIE[AUTH_COOKIE] = '';
        }
        if (! empty($_COOKIE[SECURE_AUTH_COOKIE])) {
            $_COOKIE[SECURE_AUTH_COOKIE] = '';
        }
        if (! empty($_COOKIE[LOGGED_IN_COOKIE])) {
            $_COOKIE[LOGGED_IN_COOKIE] = '';
        }
    }

    /**
     * Should we show errors and messages on this page?.
     */
    protected function should_lockout_show_msg()
    {
        if (isset($_GET['key'])) {
            // Reset password.
            return false;
        }

        $action = $_REQUEST['action'] ?? '';

        return $action != 'lostpassword'
            && $action != 'retrievepassword'
            && $action != 'resetpass'
            && $action != 'rp'
            && $action != 'register';
    }

    /**
     * Fix up the error message before showing it.
     */
    protected function lockout_fixup_error_messages($content)
    {
        if (! should_lockout_show_msg()) {
            return $content;
        }

        // During lockout we do not want to show any other error messages (like
        // unknown user or empty password).
        if (! is_lockout_ok() && ! $this->just_lockedout) {
            return lockout_error_msg();
        }

        // We want to filter the messages 'Invalid username' and
        // 'Invalid password' as that is an information leak regarding user
        // account names (prior to WP 2.9?).
        //
        // Also, if more than one error message, put an extra <br /> tag between
        // them.
        $msgs = explode("<br/>\n", $content);

        if (strlen(end($msgs)) == 0) {
            // Remove last entry empty string.
            array_pop($msgs);
        }

        $count = count($msgs);
        $my_warn_count = $this->my_error_shown ? 1 : 0;

        if ($this->nonempty_credentials && $count > $my_warn_count) {
            // Replace error message, including ours if necessary.
            $content = '<strong>ERROR</strong>: Incorrect username or password.' // @translate
                . "<br/>\n";
            if ($this->my_error_shown) {
                $content .= "<br/>\n" . lockout_get_message() . "<br/>\n";
            }
            return $content;
        } elseif ($count <= 1) {
            return $content;
        }

        $new = '';
        while ($count -- > 0) {
            $new .= array_shift($msgs) . "<br/>\n";
            if ($count > 0) {
                $new .= "<br/>\n";
            }
        }

        return $new;
    }

    /**
     * Add a message to login page when necessary.
     */
    protected function lockout_add_error_message(): void
    {
        if (! should_lockout_show_msg() || $this->my_error_shown) {
            return;
        }

        $msg = lockout_get_message();

        if ($msg) {
            $this->my_error_shown = true;
            $this->messenger()->addError($msg);
        }

        return;
    }

    /**
     * Keep track of if user or password are empty, to filter errors correctly
     */
    protected function lockout_track_credentials($user, $password): void
    {
        $this->hasCredentials = !empty($user) && !empty($password);
    }
}

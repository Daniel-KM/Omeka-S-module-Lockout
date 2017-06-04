<?php
namespace LimitLoginAttempts;

/*
 * Copyright Johan Eenfeldt, 2008-2012
 * Copyright Daniel Berthereau, 2017
 *
 * Licenced under the GNU GPL:
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

use LimitLoginAttempts\Form\Config as ConfigForm;
use Omeka\Module\AbstractModule;
use Omeka\Stdlib\ErrorStore;
use Zend\EventManager\Event;
use Zend\EventManager\SharedEventManagerInterface;
use Zend\Mvc\Controller\AbstractController;
use Zend\Mvc\MvcEvent;
use Zend\ServiceManager\ServiceLocatorInterface;
use Zend\View\Renderer\PhpRenderer;

/**
 * Limit Login Attempts
 *
 * Limit rate of login attempts, including by way of cookies, for each IP.
 *
 * @copyright Johan Eenfeldt, 2008-2012
 * @copyright Daniel Berthereau, 2017
 * @license Gnu/Gpl v3
 */
class Module extends AbstractModule
{
    const DIRECT_ADDR = 'REMOTE_ADDR';
    const PROXY_ADDR = 'HTTP_X_FORWARDED_FOR';

    /**
     * Settings and their default values.
     *
     * @var array
     */
    protected $settings = [
        // Are we behind a proxy?
        'limit_login_client_type' => self::DIRECT_ADDR,

        // Lock out after this many tries.
        'limit_login_allowed_retries' => 4,
        // Lock out for this many seconds (default is 20 minutes).
        'limit_login_lockout_duration' => 1200,
        // Long lock out after this many lockouts.
        'limit_login_allowed_lockouts' => 4,
        // Long lock out for this many seconds (default is 24 hours).
        'limit_login_long_duration' => 86400,
        // Reset failed attempts after this many seconds (defaul is 12 hours).
        'limit_login_valid_duration' => 43200,

        // Also limit malformed/forged cookies?
        'limit_login_cookies' => true,
        // Notify on lockout. Values: '', 'log' and/or 'email'.
        'limit_login_lockout_notify' => ['log'],
        // If notify by email, do so after this number of lockouts.
        'limit_login_notify_email_after' => 4,

        // Total lockouts.
        'limit_login_lockouts_total' => 0,
        // Current lockouts.
        'limit_login_lockouts' => [],
        // Logs.
        'limit_login_logged' => [],
    ];

    /**
     * Have we shown our stuff?
     *
     * @var bool
     */
    private $limit_login_my_error_shown = false;

    /**
     * Started this pageload?
     *
     * @var bool
     */
    private $limit_login_just_lockedout = false;

    /**
     * User and pwd nonempty.
     *
     * @var bool
     */
    private $limit_login_nonempty_credentials = false;

    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function install(ServiceLocatorInterface $serviceLocator)
    {
        $settings = $serviceLocator->get('Omeka\Settings');
        foreach ($this->settings as $name => $value) {
            $settings->set($name, $value);
        }
    }

    public function uninstall(ServiceLocatorInterface $serviceLocator)
    {
        $settings = $serviceLocator->get('Omeka\Settings');
        foreach ($this->settings as $name => $value) {
            $settings->delete($name);
        }
    }

    public function getConfigForm(PhpRenderer $renderer)
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');
        $formElementManager = $services->get('FormElementManager');

        // TODO $this->limit_login_cleanup();

        $formData = [];
        foreach ($this->settings as $name => $value) {
            $formData[$name] = $settings->get($name);
        }

        $form = $formElementManager->get(ConfigForm::class);
        $form->init();
        $form->setData($formData);

        $clientTypeGuess = $this->guessProxy();
        if ($clientTypeGuess== self::DIRECT_ADDR) {
            $clientTypeMessage = sprintf('It appears the site is reached directly (from your IP: %s)', // @translate
                '<strong>' . $this->getAddress(self::DIRECT_ADDR) . '</strong>');
        } else {
            $clientTypeMessage = sprintf('It appears the site is reached through a proxy server (proxy IP: %s, your IP: %s)', // @translate
                '<strong>' . $this->getAddress(self::PROXY_ADDR) . '</strong>',
                '<strong>' . $this->getAddress(self::DIRECT_ADDR) . '</strong>');
        }

        // Allow to display fieldsets in config form.
        $vars = [];
        $vars['form'] = $form;

        $vars['lockout_total'] = $settings->get('limit_login_lockout_total', 0);
        $vars['lockouts'] = $settings->get('llimit_login_lockouts', []);
        $vars['client_type_message'] = $clientTypeMessage;
        $vars['client_type_warning'] = $clientTypeGuess != $settings->get('limit_login_client_type', $this->settings['limit_login_client_type']);
        $vars['log'] = $settings->get('limit_login_logged', []);

        return $renderer->render('limit-login-attempts/module/config.phtml', $vars);
    }

    public function handleConfigForm(AbstractController $controller)
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        $params = $controller->getRequest()->getPost();

        // $form = new ConfigForm;
        // $form->init();
        // $form->setData($params);
        // if (!$form->isValid()) {
        //     $controller->messenger()->addErrors($form->getMessages());
        //     return false;
        // }

        if (!empty($params['limit_login_clear_total_lockouts'])) {
            $params['limit_login_lockouts_total'] = 0;
            $controller->messenger()->addSuccess('Reset lockout count'); // @translate
        }

        if (!empty($params['limit_login_clear_current_lockouts'])) {
            $params['limit_login_lockouts_total'] = [];
            $controller->messenger()->addSuccess('Cleared current lockouts'); // @translate
        }

        if (!empty($params['limit_login_clear_log'])) {
            $params['limit_login_logged'] = [];
            $controller->messenger()->addSuccess('Cleared IP log'); // @translate
        }

        // Clean params.
        $params['limit_login_allowed_retries'] = (int) $params['limit_login_allowed_retries'];
        $params['limit_login_lockout_duration'] = (int) $params['limit_login_lockout_duration'];
        $params['limit_login_valid_duration'] = (int) $params['limit_login_valid_duration'];
        $params['limit_login_allowed_lockouts'] = (int) $params['limit_login_allowed_lockouts'];
        $params['limit_login_long_duration'] = (int) $params['limit_login_long_duration'];
        $params['limit_login_cookies'] = (bool) $params['limit_login_cookies'];
        $params['limit_login_notify_email_after'] = (int) $params['limit_login_notify_email_after'];
        $params['limit_login_notify_email_after'] = (int) $params['limit_login_notify_email_after'];
        $params['limit_login_lockout_notify'] = array_intersect($params['limit_login_lockout_notify'], ['log', 'email']);
        if (!in_array($params['limit_login_client_type'], [self::DIRECT_ADDR, self::PROXY_ADDR])) {
            $params['limit_login_client_type'] = self::DIRECT_ADDR;
        }

        foreach ($params as $name => $value) {
            if (isset($this->settings[$name])) {
                $settings->set($name, $value);
            }
        }
    }

    /**
     * Get options and setup filters & actions.
     */
    function limit_login_setup()
    {
        // Filters and actions.
        add_action('wp_login_failed', 'limit_login_failed');
        if (limit_login_option('cookies')) {
            limit_login_handle_cookies();
            add_action('auth_cookie_bad_username', 'limit_login_failed_cookie');

            global $wp_version;

            if (version_compare($wp_version, '3.0', '>=')) {
                add_action('auth_cookie_bad_hash', 'limit_login_failed_cookie_hash');
                add_action('auth_cookie_valid', 'limit_login_valid_cookie', 10, 2);
            } else {
                add_action('auth_cookie_bad_hash', 'limit_login_failed_cookie');
            }
        }
        add_filter('wp_authenticate_user', 'limit_login_wp_authenticate_user', 99999, 2);
        add_filter('shake_error_codes', 'limit_login_failure_shake');
        add_action('login_head', 'limit_login_add_error_message');
        add_action('login_errors', 'limit_login_fixup_error_messages');

        // This action should really be changed to the 'authenticate' filter as
        // it will probably be deprecated. That is however only available in
        // later versions of WP.
        add_action('wp_authenticate', 'limit_login_track_credentials', 10, 2);
    }

    /**
     * Get correct remote address.
     */
    function getAddress($typeName = '')
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
     * Check if IP is whitelisted.
     *
     * This function allow external ip whitelisting using a filter. Note that it can
     * be called multiple times during the login process.
     *
     * Note that retries and statistics are still counted and notifications
     * done as usual for whitelisted ips , but no lockout is done.
     *
     * Example:
     * function my_ip_whitelist($allow, $ip) {
     * return ($ip == 'my-ip') ? true : $allow;
     * }
     * add_filter('limit_login_whitelist_ip', 'my_ip_whitelist', 10, 2);
     */
    function is_limit_login_ip_whitelisted($ip = null)
    {
        if (is_null($ip)) {
            $ip = limit_login_get_address();
        }
        $whitelisted = apply_filters('limit_login_whitelist_ip', false, $ip);

        return ($whitelisted === true);
    }

    /**
     * Check if it is ok to login.
     */
    function is_limit_login_ok()
    {
        $ip = limit_login_get_address();

        // Check external whitelist filter.
        if (is_limit_login_ip_whitelisted($ip)) {
            return true;
        }

        // lockout active?
        $lockouts = get_option('limit_login_lockouts');
        return (! is_array($lockouts) || ! isset($lockouts[$ip]) || time() >= $lockouts[$ip]);
    }

    /**
     * Filter: allow login attempt? (called from wp_authenticate()).
     */
    function limit_login_wp_authenticate_user($user, $password)
    {
        if (is_wp_error($user) || is_limit_login_ok()) {
            return $user;
        }

        global $limit_login_my_error_shown;
        $limit_login_my_error_shown = true;

        $error = new WP_Error();
        // This error should be the same as in "shake it" filter below.
        $error->add('too_many_retries', limit_login_error_msg());
        return $error;
    }

    /**
     * Filter: add this failure to login page "Shake it!".
     */
    function limit_login_failure_shake($error_codes)
    {
        $error_codes[] = 'too_many_retries';
        return $error_codes;
    }

    /**
     * Must be called in plugin_loaded (really early) to make sure we do not allow
     * auth cookies while locked out.
     */
    function limit_login_handle_cookies()
    {
        if (is_limit_login_ok()) {
            return;
        }

        limit_login_clear_auth_cookie();
    }

    /**
     * Action: failed cookie login hash
     *
     * Make sure same invalid cookie doesn't get counted more than once.
     *
     * Requires WordPress version 3.0.0, previous versions use limit_login_failed_cookie()
     */
    function limit_login_failed_cookie_hash($cookie_elements)
    {
        limit_login_clear_auth_cookie();

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
            limit_login_failed($username);
            return;
        }

        $previous_cookie = get_user_meta($user->ID, 'limit_login_previous_cookie', true);
        if ($previous_cookie && $previous_cookie == $cookie_elements) {
            // Identical cookies, ignore this attempt
            return;
        }

        // Store cookie
        if ($previous_cookie) {
            update_user_meta($user->ID, 'limit_login_previous_cookie', $cookie_elements);
        } else {
            add_user_meta($user->ID, 'limit_login_previous_cookie', $cookie_elements, true);
        }

        limit_login_failed($username);
    }

    /**
     * Action: successful cookie login.
     *
     * Clear any stored user_meta.
     *
     * Requires WordPress version 3.0.0, not used in previous versions
     */
    function limit_login_valid_cookie($cookie_elements, $user)
    {
        // As all meta values get cached on user load this should not require
        // any extra work for the common case of no stored value.
        if (get_user_meta($user->ID, 'limit_login_previous_cookie')) {
            delete_user_meta($user->ID, 'limit_login_previous_cookie');
        }
    }

    /**
     * Action: failed cookie login (calls limit_login_failed()).
     */
    function limit_login_failed_cookie($cookie_elements)
    {
        limit_login_clear_auth_cookie();

        // Invalid username gets counted every time.
        limit_login_failed($cookie_elements['username']);
    }

    /**
     * Make sure auth cookie really get cleared (for this session too).
     */
    function limit_login_clear_auth_cookie()
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
     * Action when login attempt failed.
     *
     * Increase nr of retries (if necessary). Reset valid value. Setup
     * lockout if nr of retries are above threshold. And more!
     *
     * A note on external whitelist: retries and statistics are still counted and
     * notifications done as usual, but no lockout is done.
     */
    function limit_login_failed($username)
    {
        $ip = limit_login_get_address();

        // if currently locked-out, do not add to retries.
        $lockouts = get_option('limit_login_lockouts');
        if (! is_array($lockouts)) {
            $lockouts = [];
        }
        if (isset($lockouts[$ip]) && time() < $lockouts[$ip]) {
            return;
        }

        // Get the arrays with retries and retries-valid information.
        $retries = get_option('limit_login_retries');
        $valid = get_option('limit_login_retries_valid');
        if (! is_array($retries)) {
            $retries = [];
            add_option('limit_login_retries', $retries, '', 'no');
        }
        if (! is_array($valid)) {
            $valid = [];
            add_option('limit_login_retries_valid', $valid, '', 'no');
        }

        // Check validity and add one to retries.
        if (isset($retries[$ip]) && isset($valid[$ip]) && time() < $valid[$ip]) {
            $retries[$ip] ++;
        } else {
            $retries[$ip] = 1;
        }
        $valid[$ip] = time() + limit_login_option('valid_duration');

        // lockout?
        if ($retries[$ip] % limit_login_option('allowed_retries') != 0) {
            // Not lockout (yet!)
            // Do housecleaning (which also saves retry/valid values).
            limit_login_cleanup($retries, null, $valid);
            return;
        }

        // lockout!.

        $whitelisted = is_limit_login_ip_whitelisted($ip);

        $retries_long = limit_login_option('allowed_retries') * limit_login_option('allowed_lockouts');

        // Note that retries and statistics are still counted and notifications
        // done as usual for whitelisted ips , but no lockout is done.
        if ($whitelisted) {
            if ($retries[$ip] >= $retries_long) {
                unset($retries[$ip]);
                unset($valid[$ip]);
            }
        } else {
            global $limit_login_just_lockedout;
            $limit_login_just_lockedout = true;

            // Setup lockout, reset retries as needed.
            if ($retries[$ip] >= $retries_long) {
                /* long lockout */
                $lockouts[$ip] = time() + limit_login_option('long_duration');
                unset($retries[$ip]);
                unset($valid[$ip]);
            } else {
                // normal lockout
                $lockouts[$ip] = time() + limit_login_option('lockout_duration');
            }
        }

        // Do housecleaning and save values.
        limit_login_cleanup($retries, $lockouts, $valid);

        // Do any notification.
        limit_login_notify($username);

        // Increase statistics.
        $total = get_option('limit_login_lockouts_total');
        if ($total === false || ! is_numeric($total)) {
            add_option('limit_login_lockouts_total', 1, '', 'no');
        } else {
            update_option('limit_login_lockouts_total', $total + 1);
        }
    }

    /**
     * Clean up old lockouts and retries, and save supplied arrays.
     */
    function limit_login_cleanup($retries = null, $lockouts = null, $valid = null)
    {
        $now = time();
        $lockouts = ! is_null($lockouts) ? $lockouts : get_option('limit_login_lockouts');

        // Remove old lockouts.
        if (is_array($lockouts)) {
            foreach ($lockouts as $ip => $lockout) {
                if ($lockout < $now) {
                    unset($lockouts[$ip]);
                }
            }
            update_option('limit_login_lockouts', $lockouts);
        }

        // Remove retries that are no longer valid.
        $valid = ! is_null($valid) ? $valid : get_option('limit_login_retries_valid');
        $retries = ! is_null($retries) ? $retries : get_option('limit_login_retries');
        if (! is_array($valid) || ! is_array($retries)) {
            return;
        }

        foreach ($valid as $ip => $lockout) {
            if ($lockout < $now) {
                unset($valid[$ip]);
                unset($retries[$ip]);
            }
        }

        // Go through retries directly, if for some reason they've gone out of sync.
        foreach ($retries as $ip => $retry) {
            if (! isset($valid[$ip])) {
                unset($retries[$ip]);
            }
        }

        update_option('limit_login_retries', $retries);
        update_option('limit_login_retries_valid', $valid);
    }

    /**
     * Is this WP Multisite?
     */
    function is_limit_login_multisite()
    {
        return function_exists('get_site_option') && function_exists('is_multisite') && is_multisite();
    }

    /**
     * Email notification of lockout to admin (if configured)
     */
    function limit_login_notify_email($user)
    {
        $ip = limit_login_get_address();
        $whitelisted = is_limit_login_ip_whitelisted($ip);

        $retries = get_option('limit_login_retries');
        if (! is_array($retries)) {
            $retries = [];
        }

        // Check if we are at the right nr to do notification.
        if (isset($retries[$ip]) && (($retries[$ip] / limit_login_option('allowed_retries')) % limit_login_option('notify_email_after')) != 0) {
            return;
        }

        // Format message. First current lockout duration.
        if (! isset($retries[$ip])) {
            // Longer lockout.
            $count = limit_login_option('allowed_retries') * limit_login_option('allowed_lockouts');
            $lockouts = limit_login_option('allowed_lockouts');
            $time = round(limit_login_option('long_duration') / 3600);
            $when = sprintf(_n('%d hour', '%d hours', $time, 'limit-login-attempts'), $time);
        } else {
            // Normal lockout.
            $count = $retries[$ip];
            $lockouts = floor($count / limit_login_option('allowed_retries'));
            $time = round(limit_login_option('lockout_duration') / 60);
            $when = sprintf(_n('%d minute', '%d minutes', $time, 'limit-login-attempts'), $time);
        }

        $blogname = is_limit_login_multisite() ? get_site_option('site_name') : get_option('blogname');

        if ($whitelisted) {
            $subject = sprintf(__("[%s] Failed login attempts from whitelisted IP", 'limit-login-attempts'), $blogname);
        } else {
            $subject = sprintf(__("[%s] Too many failed login attempts", 'limit-login-attempts'), $blogname);
        }

        $message = sprintf(__("%d failed login attempts (%d lockout(s)) from IP: %s", 'limit-login-attempts') . "\r\n\r\n", $count, $lockouts, $ip);
        if ($user != '') {
            $message .= sprintf(__("Last user attempted: %s", 'limit-login-attempts') . "\r\n\r\n", $user);
        }
        if ($whitelisted) {
            $message .= __("IP was NOT blocked because of external whitelist.", 'limit-login-attempts');
        } else {
            $message .= sprintf(__("IP was blocked for %s", 'limit-login-attempts'), $when);
        }

        $admin_email = is_limit_login_multisite() ? get_site_option('admin_email') : get_option('admin_email');

        @wp_mail($admin_email, $subject, $message);
    }

    /**
     * Logging of lockout (if configured).
     */
    function limit_login_notify_log($user)
    {
        $log = $option = get_option('limit_login_logged');
        if (! is_array($log)) {
            $log = [];
        }
        $ip = limit_login_get_address();

        // Can be written much simpler, if you do not mind php warnings.
        if (isset($log[$ip])) {
            if (isset($log[$ip][$user])) {
                $log[$ip][$user] ++;
            } else {
                $log[$ip][$user] = 1;
            }
        } else {
            $log[$ip] = [
                $user => 1,
            ];
        }

        if ($option === false) {
            // No autoload.
            add_option('limit_login_logged', $log, '', 'no');
        } else {
            update_option('limit_login_logged', $log);
        }
    }

    /**
     * Handle notification in event of lockout.
     */
    function limit_login_notify($user)
    {
        $args = explode(',', limit_login_option('lockout_notify'));

        if (empty($args)) {
            return;
        }

        foreach ($args as $mode) {
            switch (trim($mode)) {
                case 'email':
                    limit_login_notify_email($user);
                    break;
                case 'log':
                    limit_login_notify_log($user);
                    break;
            }
        }
    }

    /**
     * Construct informative error message.
     */
    function limit_login_error_msg()
    {
        $ip = limit_login_get_address();
        $lockouts = get_option('limit_login_lockouts');

        $msg = __('<strong>ERROR</strong>: Too many failed login attempts.', 'limit-login-attempts') . ' ';

        if (! is_array($lockouts) || ! isset($lockouts[$ip]) || time() >= $lockouts[$ip]) {
            // Huh? No timeout active?
            $msg .= __('Please try again later.', 'limit-login-attempts');
            return $msg;
        }

        $when = ceil(($lockouts[$ip] - time()) / 60);
        if ($when > 60) {
            $when = ceil($when / 60);
            $msg .= sprintf(_n('Please try again in %d hour.', 'Please try again in %d hours.', $when, 'limit-login-attempts'), $when);
        } else {
            $msg .= sprintf(_n('Please try again in %d minute.', 'Please try again in %d minutes.', $when, 'limit-login-attempts'), $when);
        }

        return $msg;
    }

    /**
     * Construct retries remaining message.
     */
    function limit_login_retries_remaining_msg()
    {
        $ip = limit_login_get_address();
        $retries = get_option('limit_login_retries');
        $valid = get_option('limit_login_retries_valid');

        // Should we show retries remaining?

        if (! is_array($retries) || ! is_array($valid)) {
            // No retries at all.
            return '';
        }
        if (! isset($retries[$ip]) || ! isset($valid[$ip]) || time() > $valid[$ip]) {
            // No: no valid retries.
            return '';
        }
        if (($retries[$ip] % limit_login_option('allowed_retries')) == 0) {
            // No: already been locked out for these retries.
            return '';
        }

        $remaining = max((limit_login_option('allowed_retries') - ($retries[$ip] % limit_login_option('allowed_retries'))), 0);
        return sprintf(_n("<strong>%d</strong> attempt remaining.", "<strong>%d</strong> attempts remaining.", $remaining, 'limit-login-attempts'), $remaining);
    }

    /**
     * Return current (error) message to show, if any
     */
    function limit_login_get_message()
    {
        // Check external whitelist.
        if (is_limit_login_ip_whitelisted()) {
            return '';
        }

        // Is lockout in effect?
        if (! is_limit_login_ok()) {
            return limit_login_error_msg();
        }

        return limit_login_retries_remaining_msg();
    }

    /**
     * Should we show errors and messages on this page?.
     */
    function should_limit_login_show_msg()
    {
        if (isset($_GET['key'])) {
            // reset password.
            return false;
        }

        $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';

        return ($action != 'lostpassword' && $action != 'retrievepassword' && $action != 'resetpass' && $action != 'rp' && $action != 'register');
    }

    /**
     * Fix up the error message before showing it.
     */
    function limit_login_fixup_error_messages($content)
    {
        global $limit_login_just_lockedout, $limit_login_nonempty_credentials, $limit_login_my_error_shown;

        if (! should_limit_login_show_msg()) {
            return $content;
        }

        // During lockout we do not want to show any other error messages (like
        // unknown user or empty password).
        if (! is_limit_login_ok() && ! $limit_login_just_lockedout) {
            return limit_login_error_msg();
        }

        // We want to filter the messages 'Invalid username' and
        // 'Invalid password' as that is an information leak regarding user
        // account names (prior to WP 2.9?).
        //
        // Also, if more than one error message, put an extra <br /> tag between
        // them.
        $msgs = explode("<br />\n", $content);

        if (strlen(end($msgs)) == 0) {
            // Remove last entry empty string.
            array_pop($msgs);
        }

        $count = count($msgs);
        $my_warn_count = $limit_login_my_error_shown ? 1 : 0;

        if ($limit_login_nonempty_credentials && $count > $my_warn_count) {
            // Replace error message, including ours if necessary.
            $content = __('<strong>ERROR</strong>: Incorrect username or password.', 'limit-login-attempts') . "<br />\n";
            if ($limit_login_my_error_shown) {
                $content .= "<br />\n" . limit_login_get_message() . "<br />\n";
            }
            return $content;
        } elseif ($count <= 1) {
            return $content;
        }

        $new = '';
        while ($count -- > 0) {
            $new .= array_shift($msgs) . "<br />\n";
            if ($count > 0) {
                $new .= "<br />\n";
            }
        }

        return $new;
    }

    /**
     * Add a message to login page when necessary.
     */
    function limit_login_add_error_message()
    {
        global $error, $limit_login_my_error_shown;

        if (! should_limit_login_show_msg() || $limit_login_my_error_shown) {
            return;
        }

        $msg = limit_login_get_message();

        if ($msg != '') {
            $limit_login_my_error_shown = true;
            $error .= $msg;
        }

        return;
    }

    /**
     * Keep track of if user or password are empty, to filter errors correctly
     */
    function limit_login_track_credentials($user, $password)
    {
        global $limit_login_nonempty_credentials;

        $limit_login_nonempty_credentials = (! empty($user) && ! empty($password));
    }

    /**
     * Make a guess if we are behind a proxy or not.
     */
    function guessProxy()
    {
        return isset($_SERVER[self::PROXY_ADDR])
            ? self::PROXY_ADDR
            : self::DIRECT_ADDR;
    }
}

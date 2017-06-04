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
use Zend\Mvc\Controller\AbstractController;
use Zend\ServiceManager\ServiceLocatorInterface;
use Zend\View\Renderer\PhpRenderer;

/**
 * Limit Login Attempts
 *
 * Limit rate of login attempts for each IP to avoid brute-force attacks.
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
        // Whitelist of ips.
        'limit_login_whitelist' => [],
        // Notify on lockout. Values: '', 'log' and/or 'email'.
        'limit_login_lockout_notify' => ['log'],
        // If notify by email, do so after this number of lockouts.
        'limit_login_notify_email_after' => 4,

        // Current lockouts.
        'limit_login_lockouts' => [],
        'limit_login_valids' => [],
        'limit_login_retries' => [],
        // Total lockouts.
        'limit_login_lockouts_total' => 0,
        // Logs.
        'limit_login_logs' => [],
    ];

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

        $formData = [];
        foreach ($this->settings as $name => $value) {
            $formData[$name] = $settings->get($name);
        }
        $formData['limit_login_whitelist'] = implode("\n", $formData['limit_login_whitelist']);

        $form = $formElementManager->get(ConfigForm::class);
        $form->init();
        $form->setData($formData);

        $clientTypeGuess = $this->guessProxy();
        if ($clientTypeGuess == self::DIRECT_ADDR) {
            $clientTypeMessage = sprintf('It appears the site is reached directly (from your IP: %s).', // @translate
                '<strong>' . $this->getAddress(self::DIRECT_ADDR) . '</strong>');
        } else {
            $clientTypeMessage = sprintf('It appears the site is reached through a proxy server (proxy IP: %s, your IP: %s).', // @translate
                '<strong>' . $this->getAddress(self::PROXY_ADDR) . '</strong>',
                '<strong>' . $this->getAddress(self::DIRECT_ADDR) . '</strong>');
        }

        // Allow to display fieldsets in config form.
        $vars = [];
        $vars['form'] = $form;

        $vars['lockout_total'] = $settings->get('limit_login_lockouts_total', 0);
        $vars['lockouts'] = $settings->get('limit_login_lockouts', []);
        $vars['client_type_message'] = $clientTypeMessage;
        $vars['client_type_warning'] = $clientTypeGuess != $settings->get('limit_login_client_type', $this->settings['limit_login_client_type']);
        $vars['logs'] = $settings->get('limit_login_logs', []);

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
            $controller->messenger()->addSuccess('Reset lockout count.'); // @translate
        }

        if (!empty($params['limit_login_clear_current_lockouts'])) {
            $params['limit_login_lockouts_total'] = [];
            $controller->messenger()->addSuccess('Cleared current lockouts.'); // @translate
        }

        if (!empty($params['limit_login_clear_logs'])) {
            $params['limit_login_logs'] = [];
            $controller->messenger()->addSuccess('Cleared IP log.'); // @translate
        }

        // Clean params.
        $params['limit_login_allowed_retries'] = (int) $params['limit_login_allowed_retries'];
        $params['limit_login_lockout_duration'] = (int) $params['limit_login_lockout_duration'];
        $params['limit_login_valid_duration'] = (int) $params['limit_login_valid_duration'];
        $params['limit_login_allowed_lockouts'] = (int) $params['limit_login_allowed_lockouts'];
        $params['limit_login_long_duration'] = (int) $params['limit_login_long_duration'];
        $params['limit_login_cookies'] = (bool) $params['limit_login_cookies'];
        $params['limit_login_notify_email_after'] = (int) $params['limit_login_notify_email_after'];
        $params['limit_login_lockout_notify'] = array_intersect($params['limit_login_lockout_notify'], ['log', 'email']);
        $params['limit_login_whitelist'] = array_filter(array_map('trim', explode("\n", $params['limit_login_whitelist'])));
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
     * Get correct remote address.
     *
     * @param $typeName Direct address or proxy address.
     * @return string
     */
    public function getAddress($typeName = '')
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
     * Make a guess if we are behind a proxy or not.
     */
    public function guessProxy()
    {
        return isset($_SERVER[self::PROXY_ADDR])
            ? self::PROXY_ADDR
            : self::DIRECT_ADDR;
    }
}

<?php
namespace Lockout;

/*
 * Copyright Johan Eenfeldt, 2008-2012
 * Copyright Daniel Berthereau, 2017-2018
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

use Lockout\Form\Config as ConfigForm;
use Omeka\Module\AbstractModule;
use Zend\Mvc\Controller\AbstractController;
use Zend\ServiceManager\ServiceLocatorInterface;
use Zend\View\Renderer\PhpRenderer;

/**
 * Lockout
 *
 * Limit rate of login attempts for each IP to avoid brute-force attacks.
 *
 * @copyright Johan Eenfeldt, 2008-2012
 * @copyright Daniel Berthereau, 2017-2018
 * @license Gnu/Gpl v3
 */
class Module extends AbstractModule
{
    const DIRECT_ADDR = 'REMOTE_ADDR';
    const PROXY_ADDR = 'HTTP_X_FORWARDED_FOR';

    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function install(ServiceLocatorInterface $serviceLocator)
    {
        $this->manageSettings($serviceLocator->get('Omeka\Settings'), 'install');
    }

    public function uninstall(ServiceLocatorInterface $serviceLocator)
    {
        $this->manageSettings($serviceLocator->get('Omeka\Settings'), 'uninstall');
    }

    protected function manageSettings($settings, $process, $key = 'config')
    {
        $config = require __DIR__ . '/config/module.config.php';
        $defaultSettings = $config[strtolower(__NAMESPACE__)][$key];
        foreach ($defaultSettings as $name => $value) {
            switch ($process) {
                case 'install':
                    $settings->set($name, $value);
                    break;
                case 'uninstall':
                    $settings->delete($name);
                    break;
            }
        }
    }

    public function getConfigForm(PhpRenderer $renderer)
    {
        $services = $this->getServiceLocator();
        $config = $services->get('Config');
        $settings = $services->get('Omeka\Settings');
        $form = $services->get('FormElementManager')->get(ConfigForm::class);

        $data = [];
        $defaultSettings = $config[strtolower(__NAMESPACE__)]['config'];
        foreach ($defaultSettings as $name => $value) {
            $data[$name] = $settings->get($name, $value);
        }
        $data['lockout_whitelist'] = implode("\n", $data['lockout_whitelist']);

        $form->init();
        $form->setData($data);

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

        $vars['lockout_total'] = $settings->get('lockout_lockouts_total', 0);
        $vars['lockouts'] = $settings->get('lockout_lockouts', []);
        $vars['client_type_message'] = $clientTypeMessage;
        $vars['client_type_warning'] = $clientTypeGuess != $settings->get('lockout_client_type', $defaultSettings['lockout_client_type']);
        $vars['logs'] = $settings->get('lockout_logs', []);

        return $renderer->render('lockout/module/config', $vars);
    }

    public function handleConfigForm(AbstractController $controller)
    {
        $services = $this->getServiceLocator();
        $config = $services->get('Config');
        $settings = $services->get('Omeka\Settings');

        $params = $controller->getRequest()->getPost();

        $form = $services->get('FormElementManager')->get(ConfigForm::class);
        $form->init();
        $form->setData($params);
        if (!$form->isValid()) {
            $controller->messenger()->addErrors($form->getMessages());
            return false;
        }

        // TODO Move the post-checks into the form.

        if (!empty($params['lockout_clear_current_lockouts'])) {
            $params['lockout_lockouts'] = [];
            $controller->messenger()->addSuccess('Cleared current lockouts.'); // @translate
        }

        if (!empty($params['lockout_clear_total_lockouts'])) {
            $params['lockout_lockouts_total'] = 0;
            $controller->messenger()->addSuccess('Reset lockout count.'); // @translate
        }

        if (!empty($params['lockout_clear_logs'])) {
            $params['lockout_logs'] = [];
            $controller->messenger()->addSuccess('Cleared IP log.'); // @translate
        }

        // Clean params.
        $params['lockout_allowed_retries'] = (int) $params['lockout_allowed_retries'];
        $params['lockout_lockout_duration'] = (int) $params['lockout_lockout_duration'];
        $params['lockout_valid_duration'] = (int) $params['lockout_valid_duration'];
        $params['lockout_allowed_lockouts'] = (int) $params['lockout_allowed_lockouts'];
        $params['lockout_long_duration'] = (int) $params['lockout_long_duration'];
        $params['lockout_cookies'] = (bool) $params['lockout_cookies'];
        $params['lockout_notify_email_after'] = (int) $params['lockout_notify_email_after'];
        $params['lockout_lockout_notify'] = array_intersect($params['lockout_lockout_notify'], ['log', 'email']);
        $params['lockout_whitelist'] = array_filter(array_map('trim', explode("\n", $params['lockout_whitelist'])));
        if (!in_array($params['lockout_client_type'], [self::DIRECT_ADDR, self::PROXY_ADDR])) {
            $params['lockout_client_type'] = self::DIRECT_ADDR;
        }

        $defaultSettings = $config[strtolower(__NAMESPACE__)]['config'];
        foreach ($params as $name => $value) {
            if (array_key_exists($name, $defaultSettings)) {
                $settings->set($name, $value);
            }
        }
    }

    /**
     * Get correct remote address.
     *
     * @param string $typeName Direct address or proxy address.
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

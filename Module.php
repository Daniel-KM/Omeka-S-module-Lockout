<?php declare(strict_types=1);

namespace Lockout;

/*
 * Copyright Johan Eenfeldt, 2008-2012
 * Copyright Daniel Berthereau, 2017-2026
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

use Laminas\Mvc\Controller\AbstractController;
use Laminas\ServiceManager\ServiceLocatorInterface;
use Laminas\View\Renderer\PhpRenderer;
use Lockout\Form\ConfigForm;
use Omeka\Module\AbstractModule;

/**
 * Lockout
 *
 * Limit rate of login attempts for each IP to avoid brute-force attacks.
 *
 * @copyright Johan Eenfeldt, 2008-2012
 * @copyright Daniel Berthereau, 2017-2023
 * @license Gnu/Gpl v3
 */
class Module extends AbstractModule
{
    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function install(ServiceLocatorInterface $serviceLocator): void
    {
        $this->manageSettings($serviceLocator->get('Omeka\Settings'), 'install');
    }

    public function uninstall(ServiceLocatorInterface $serviceLocator): void
    {
        $this->manageSettings($serviceLocator->get('Omeka\Settings'), 'uninstall');
    }

    public function upgrade($oldVersion, $newVersion, ServiceLocatorInterface $serviceLocator): void
    {
        $filepath = __DIR__ . '/data/scripts/upgrade.php';
        $services = $serviceLocator;
        require_once $filepath;
    }

    protected function manageSettings($settings, $process, $key = 'config'): void
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
        $data['lockout_trusted_proxies'] = implode("\n", $data['lockout_trusted_proxies'] ?? []);

        $form->init();
        $form->setData($data);

        // Same resolution than the login controller.
        $clientIp = $services->get('Omeka\ClientIp');
        $trusted = $clientIp::normalizeTrustedProxies($data['lockout_trusted_proxies']);
        $detected = $clientIp->detect(null, $trusted ?: null);

        // Allow to display fieldsets in config form.
        $vars = [];
        $vars['form'] = $form;

        $vars['lockout_total'] = $settings->get('lockout_lockouts_total', 0);
        $vars['lockouts'] = $settings->get('lockout_lockouts', []);
        $vars['client_ip'] = $clientIp->getIp(null, $trusted ?: null, true);
        $vars['proxy_untrusted'] = $detected['status'] === 'untrusted' ? $detected['peer'] : null;
        $vars['logs'] = $settings->get('lockout_logs', []);

        return $renderer->render('lockout/module/config-form', $vars);
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
        $params['lockout_trusted_proxies'] = $services->get('Omeka\ClientIp')::normalizeTrustedProxies($params['lockout_trusted_proxies'] ?? '');

        $defaultSettings = $config[strtolower(__NAMESPACE__)]['config'];
        foreach ($params as $name => $value) {
            if (array_key_exists($name, $defaultSettings)) {
                $settings->set($name, $value);
            }
        }
    }
}

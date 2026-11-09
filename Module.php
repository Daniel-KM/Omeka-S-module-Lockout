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

// Common may be installed but not registered in autoloader, in particular
// during upgrade. So dynamically register all classes of the module.
if (!defined('COMMON_PSR4_FALLBACK')) {
    foreach ([
        OMEKA_PATH . '/modules/Common/src',
        OMEKA_PATH . '/composer-addons/modules/Common/src',
        dirname(__DIR__) . '/Common/src',
    ] as $commonSrc) {
        if (file_exists($commonSrc . '/TraitModule.php')) {
            define('COMMON_PSR4_FALLBACK', $commonSrc);
            spl_autoload_register(static function ($class): void {
                if (str_starts_with($class, 'Common\\')) {
                    $file = COMMON_PSR4_FALLBACK . '/' . strtr(substr($class, 7), '\\', '/') . '.php';
                    if (file_exists($file)) {
                        require_once $file;
                    }
                }
            });
            break;
        }
    }
}

use Common\TraitModule;
use Laminas\Mvc\Controller\AbstractController;
use Laminas\View\Renderer\PhpRenderer;
use Omeka\Module\AbstractModule;

/**
 * Lockout
 *
 * Limit rate of login attempts for each IP to avoid brute-force attacks.
 *
 * @copyright Johan Eenfeldt, 2008-2012
 * @copyright Daniel Berthereau, 2017-2026
 * @license Gnu/Gpl v3
 */
class Module extends AbstractModule
{
    use TraitModule;

    const NAMESPACE = __NAMESPACE__;

    protected function preInstall(): void
    {
        $services = $this->getServiceLocator();
        $translator = $services->get('MvcTranslator');

        if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.96')) {
            $message = new \Omeka\Stdlib\Message(
                $translator->translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
                'Common', '3.4.96'
            );
            throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $message);
        }
    }

    /**
     * Display the current lockouts and the log with the options.
     */
    public function getConfigForm(PhpRenderer $renderer)
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        if ($this->invalidConfigForm) {
            $form = $this->invalidConfigForm;
        } else {
            $this->initDataToPopulate($settings, 'config');
            $form = $services->get('FormElementManager')->get(Form\ConfigForm::class);
            $form->init();
            $form->setData($this->prepareDataToPopulate($settings, 'config'));
        }
        $form->prepare();

        // Same resolution than the login controller. The service is missing
        // while the module Common is not upgraded.
        $clientIp = $services->has('Omeka\ClientIp') ? $services->get('Omeka\ClientIp') : null;
        $detected = $clientIp ? $clientIp->detect() : ['status' => 'direct'];

        $this->appendConfigApplyAsset($renderer);

        return $renderer->render('lockout/module/config-form', [
            'form' => $form,
            'lockout_total' => $settings->get('lockout_lockouts_total', 0),
            'lockouts' => $settings->get('lockout_lockouts', []),
            'client_ip' => $clientIp ? $clientIp->getIp(null, null, true) : (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
            'proxy_untrusted' => $detected['status'] === 'untrusted' ? $detected['peer'] : null,
            'logs' => $settings->get('lockout_logs', []),
        ]);
    }

    /**
     * Save the options, then process the resets, that are not settings.
     */
    public function handleConfigForm(AbstractController $controller)
    {
        if (!$this->handleConfigFormAuto($controller)) {
            return false;
        }

        $settings = $this->getServiceLocator()->get('Omeka\Settings');
        $post = $controller->getRequest()->getPost();
        if (!empty($post['lockout_clear_current_lockouts'])) {
            $settings->set('lockout_lockouts', []);
            $controller->messenger()->addSuccess('Cleared current lockouts.'); // @translate
        }
        if (!empty($post['lockout_clear_total_lockouts'])) {
            $settings->set('lockout_lockouts_total', 0);
            $controller->messenger()->addSuccess('Reset lockout count.'); // @translate
        }
        if (!empty($post['lockout_clear_logs'])) {
            $settings->set('lockout_logs', []);
            $controller->messenger()->addSuccess('Cleared IP log.'); // @translate
        }

        $this->redirectToConfigFormOnApply($controller);
        return true;
    }
}

<?php declare(strict_types=1);

namespace Lockout;

use Laminas\ServiceManager\ServiceLocatorInterface;

/**
 * @var Module $this
 * @var ServiceLocatorInterface $services
 */

/** @var \Omeka\Settings\Settings $settings */
$settings = $services->get('Omeka\Settings');
$messenger = $services->get('ControllerPluginManager')->get('messenger');
$translator = $services->get('MvcTranslator');

if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.96')) {
    $message = new \Omeka\Stdlib\Message(
        $translator->translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
        'Common', '3.4.96'
    );
    $messenger->addError($message);
    throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $translator->translate('Missing requirement. Unable to upgrade.')); // @translate
}

// The client type is replaced by the trusted proxies: the proxy headers are
// read only when the request comes from a trusted proxy.
$settings->delete('lockout_client_type');

// Sanitize numeric settings: stored 0/null silently broke the algorithm before
// the runtime fallbacks were added. Re-seed defaults when empty.
$durationDefaults = [
    'lockout_allowed_retries' => 4,
    'lockout_allowed_lockouts' => 4,
    'lockout_lockout_duration' => 1200,
    'lockout_long_duration' => 86400,
    'lockout_valid_duration' => 43200,
    'lockout_notify_email_after' => 4,
];
foreach ($durationDefaults as $name => $default) {
    $value = (int) $settings->get($name);
    if ($value <= 0) {
        $settings->set($name, $default);
    }
}

// Drop pre-existing lockout_logs entries that are unbounded blobs from older
// versions to avoid carrying the DoS surface forward.
$logs = $settings->get('lockout_logs');
if (is_array($logs) && count($logs) > 1000) {
    $settings->set('lockout_logs', array_slice($logs, -1000, null, true));
}

// The trusted proxies are managed in the main settings (module Common): merge
// the list of the module into it.
$moduleTrustedProxies = $settings->get('lockout_trusted_proxies');
if ($moduleTrustedProxies !== null) {
    $trustedProxies = array_values(array_unique(array_filter(array_merge(
        (array) ($settings->get('trusted_proxies') ?: []),
        is_array($moduleTrustedProxies) ? $moduleTrustedProxies : preg_split('/[\s,;]+/', (string) $moduleTrustedProxies)
    ))));
    $settings->set('trusted_proxies', $trustedProxies);
    $settings->delete('lockout_trusted_proxies');
    if ($trustedProxies) {
        $messenger->addWarning(new \Omeka\Stdlib\Message(
            'The trusted reverse proxies are now managed in the security section of the main settings and apply to all modules, including the ones that grant rights or lock out by ip. Check that each one is a reverse proxy of the server: %s.', // @translate
            implode(', ', $trustedProxies)
        ));
    }
}

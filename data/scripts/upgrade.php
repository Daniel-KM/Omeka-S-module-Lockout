<?php declare(strict_types=1);

namespace Lockout;

use Laminas\ServiceManager\ServiceLocatorInterface;

/**
 * @var ServiceLocatorInterface $services
 */

/** @var \Omeka\Settings\Settings $settings */
$settings = $services->get('Omeka\Settings');

// Initialize new settings introduced in 3.4.8.
if ($settings->get('lockout_trusted_proxies') === null) {
    $settings->set('lockout_trusted_proxies', []);
}

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

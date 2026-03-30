<?php declare(strict_types=1);

namespace Lockout\Job;

use Omeka\Job\AbstractJob;

/**
 * Purge stale lockout state.
 *
 * Runs cleanupLockout-equivalent logic and additionally clears entries from
 * lockout_logs that target IPs that have been inactive for a configurable
 * number of days. Schedule via EasyAdmin or any cron runner.
 */
class CleanupLockout extends AbstractJob
{
    public function perform(): void
    {
        $services = $this->getServiceLocator();
        /** @var \Omeka\Settings\Settings $settings */
        $settings = $services->get('Omeka\Settings');
        /** @var \Laminas\Log\Logger $logger */
        $logger = $services->get('Omeka\Logger');
        /** @var \Doctrine\DBAL\Connection $connection */
        $connection = $services->get('Omeka\Connection');

        // Serialize against concurrent failed logins which also mutate these
        // rows; we hold a row-level lock for the whole job body.
        $lockNames = ['lockout_lockouts', 'lockout_valids', 'lockout_retries', 'lockout_logs'];
        foreach ($lockNames as $name) {
            $connection->executeStatement(
                'INSERT IGNORE INTO setting (id, value) VALUES (?, ?)',
                [$name, '[]']
            );
        }
        $connection->beginTransaction();
        try {
            $placeholders = implode(',', array_fill(0, count($lockNames), '?'));
            $connection->executeQuery(
                "SELECT id FROM setting WHERE id IN ($placeholders) FOR UPDATE",
                $lockNames
            );
            $this->runCleanup($settings, $logger);
            $connection->commit();
        } catch (\Throwable $e) {
            if ($connection->isTransactionActive()) {
                $connection->rollBack();
            }
            throw $e;
        }
    }

    protected function runCleanup($settings, $logger): void
    {
        $now = time();

        // Lockouts.
        $originalLockouts = $settings->get('lockout_lockouts', []) ?: [];
        $lockouts = $originalLockouts;
        $lockoutsBefore = count($lockouts);
        foreach ($lockouts as $ip => $expiry) {
            if ($expiry <= $now) {
                unset($lockouts[$ip]);
            }
        }
        if ($lockouts !== $originalLockouts) {
            $settings->set('lockout_lockouts', $lockouts);
        }

        // Retries / valids.
        $originalValids = $settings->get('lockout_valids', []) ?: [];
        $originalRetries = $settings->get('lockout_retries', []) ?: [];
        $valids = $originalValids;
        $retries = $originalRetries;
        $retriesBefore = count($retries);
        foreach ($valids as $ip => $expiry) {
            if ($expiry <= $now) {
                unset($valids[$ip]);
                unset($retries[$ip]);
            }
        }
        foreach (array_keys($retries) as $ip) {
            if (!isset($valids[$ip])) {
                unset($retries[$ip]);
            }
        }
        if ($valids !== $originalValids) {
            $settings->set('lockout_valids', $valids);
        }
        if ($retries !== $originalRetries) {
            $settings->set('lockout_retries', $retries);
        }

        // Logs: drop entries for IPs that no longer have any active retry or
        // lockout. Bound the total size as a defensive cap.
        $originalLogs = $settings->get('lockout_logs', []) ?: [];
        $logs = $originalLogs;
        $logsBefore = count($logs);
        foreach (array_keys($logs) as $ip) {
            if (!isset($retries[$ip]) && !isset($lockouts[$ip])) {
                unset($logs[$ip]);
            }
        }
        $maxIps = (int) $this->getArg('max_log_ips', 1000);
        if ($maxIps > 0 && count($logs) > $maxIps) {
            $logs = array_slice($logs, -$maxIps, null, true);
        }
        if ($logs !== $originalLogs) {
            $settings->set('lockout_logs', $logs);
        }

        $logger->info(sprintf(
            'Lockout cleanup: lockouts %d → %d, retries %d → %d, logs %d → %d', // @translate
            $lockoutsBefore,
            count($lockouts),
            $retriesBefore,
            count($retries),
            $logsBefore,
            count($logs)
        ));
    }
}

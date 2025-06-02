<?php declare(strict_types=1);

namespace Lockout;

return [
    'view_manager' => [
        'template_path_stack' => [
            dirname(__DIR__) . '/view',
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
        ],
    ],
    'controllers' => [
        'factories' => [
            // Override the standard Omeka login controller.
            'Omeka\Controller\Login' => Service\Controller\LoginControllerFactory::class,
        ],
    ],
    'translator' => [
        'translation_file_patterns' => [
            [
                'type' => 'gettext',
                'base_dir' => dirname(__DIR__) . '/language',
                'pattern' => '%s.mo',
                'text_domain' => null,
            ],
        ],
    ],
    'lockout' => [
        'config' => [
            // Are we behind a proxy?
            'lockout_client_type' => self::DIRECT_ADDR,

            // Lock out after this many tries.
            'lockout_allowed_retries' => 4,
            // Lock out for this many seconds (default is 20 minutes).
            'lockout_lockout_duration' => 1200,
            // Long lock out after this many lockouts.
            'lockout_allowed_lockouts' => 4,
            // Long lock out for this many seconds (default is 24 hours).
            'lockout_long_duration' => 86400,
            // Reset failed attempts after this many seconds (defaul is 12 hours).
            'lockout_valid_duration' => 43200,

            // Also limit malformed/forged cookies?
            'lockout_cookies' => true,
            // Whitelist of ips.
            'lockout_whitelist' => [],
            // Notify on lockout. Values: '', 'log' and/or 'email'.
            'lockout_lockout_notify' => ['log'],
            // If notify by email, do so after this number of lockouts.
            'lockout_notify_email_after' => 4,

            // Current lockouts.
            'lockout_lockouts' => [],
            'lockout_valids' => [],
            'lockout_retries' => [],
            // Total lockouts.
            'lockout_lockouts_total' => 0,
            // Logs.
            'lockout_logs' => [],
        ],
    ],
];

<?php
namespace LimitLoginAttempts;

return [
    'view_manager' => [
        'template_path_stack' => [
            OMEKA_PATH . '/modules/LimitLoginAttempts/view',
        ],
    ],
    'form_elements' => [
        'invokables' => [
            'LimitLoginAttempts\Form\Config' => Form\Config::class,
        ],
    ],
    'translator' => [
        'translation_file_patterns' => [
            [
                'type' => 'gettext',
                'base_dir' => __DIR__ . '/../language',
                'pattern' => '%s.mo',
                'text_domain' => null,
            ],
        ],
    ],
];

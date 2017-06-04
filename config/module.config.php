<?php
namespace Lockout;

return [
    'view_manager' => [
        'template_path_stack' => [
            OMEKA_PATH . '/modules/Lockout/view',
        ],
    ],
    'controllers' => [
        'factories' => [
            // Override the standard Omeka login controller.
            'Omeka\Controller\Login' => Service\Controller\LoginControllerFactory::class,
        ],
    ],
    'form_elements' => [
        'invokables' => [
            'Lockout\Form\Config' => Form\Config::class,
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

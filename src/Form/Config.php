<?php
namespace LimitLoginAttempts\Form;

use Zend\Form\Form;

class Config extends Form
{
    public function init()
    {
        // Resets.

        $this->add([
            'name' => 'limit_login_clear_total_lockouts',
            'type' => 'Checkbox',
            'options' => [
                'label' => 'Reset total lockouts', // @translate
            ],
            'attributes' => [
                'value' => false,
            ],
        ]);

        $this->add([
            'name' => 'limit_login_clear_current_lockouts',
            'type' => 'Checkbox',
            'options' => [
                'label' => 'Clear current lockouts', // @translate
            ],
            'attributes' => [
                'value' => false,
            ],
        ]);

        $this->add([
            'name' => 'limit_login_clear_log',
            'type' => 'Checkbox',
            'options' => [
                'label' => 'Clear IP log', // @translate
            ],
            'attributes' => [
                'value' => false,
            ],
        ]);

        // Lockout.

        $this->add([
            'name' => 'limit_login_allowed_retries',
            'type' => 'Text',
            'options' => [
                'label' => 'Allowed retries', // @translate
            ],
        ]);

        $this->add([
            'name' => 'limit_login_lockout_duration',
            'type' => 'Text',
            'options' => [
                'label' => 'Lockout duration (seconds)', // @translate
            ],
        ]);

        $this->add([
            'name' => 'limit_login_allowed_lockouts',
            'type' => 'Text',
            'options' => [
                'label' => 'Allowed retries', // @translate
            ],
        ]);

        $this->add([
            'name' => 'limit_login_long_duration',
            'type' => 'Text',
            'options' => [
                'label' => 'Long lock out (seconds)', // @translate
            ],
        ]);

        $this->add([
            'name' => 'limit_login_valid_duration',
            'type' => 'Text',
            'options' => [
                'label' => 'Valid duration (seconds)', // @translate
            ],
        ]);

        // Site connection.

        $this->add([
            'type' => 'Radio',
            'name' => 'limit_login_client_type',
            'options' => [
                'label' => 'Client type', // @translate
                'value_options' => [
                    \LimitLoginAttempts\Module::DIRECT_ADDR => 'Direct connection', // @translate
                    \LimitLoginAttempts\Module::PROXY_ADDR => 'From behind a reversy proxy', // @translate
                ],
            ],
        ]);

        $this->add([
            'name' => 'limit_login_cookies',
            'type' => 'Checkbox',
            'options' => [
                'label' => 'Handle cookie login', // @translate
            ],
        ]);

        // Notification.

        $this->add([
            'name' => 'limit_login_lockout_notify',
            'type' => 'MultiCheckbox',
            'options' => [
                'label' => 'Notify on lockout', // @translate
                'value_options' => [
                    'log' => 'Log IP', // @translate
                    'email' => 'Email', // @translate
                ],
            ],
        ]);

        $this->add([
            'name' => 'limit_login_notify_email_after',
            'type' => 'Text',
            'options' => [
                'label' => 'Email to admin after attempts', // @translate
            ],
        ]);
    }
}

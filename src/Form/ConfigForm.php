<?php declare(strict_types=1);

namespace Lockout\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;

class ConfigForm extends Form
{
    public function init(): void
    {
        // Resets.

        $this->add([
            'name' => 'lockout_clear_current_lockouts',
            'type' => Element\Checkbox::class,
            'options' => [
                'label' => 'Clear current lockouts', // @translate
            ],
            'attributes' => [
                'value' => false,
            ],
        ]);

        $this->add([
            'name' => 'lockout_clear_total_lockouts',
            'type' => Element\Checkbox::class,
            'options' => [
                'label' => 'Reset counter', // @translate
            ],
            'attributes' => [
                'value' => false,
            ],
        ]);

        $this->add([
            'name' => 'lockout_clear_logs',
            'type' => Element\Checkbox::class,
            'options' => [
                'label' => 'Clear IP log', // @translate
            ],
            'attributes' => [
                'value' => false,
            ],
        ]);

        // Lockout.

        $this->add([
            'name' => 'lockout_allowed_retries',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Allowed retries', // @translate
            ],
        ]);

        $this->add([
            'name' => 'lockout_lockout_duration',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Lockout duration (seconds)', // @translate
            ],
        ]);

        $this->add([
            'name' => 'lockout_allowed_lockouts',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Allowed lockouts before long lockout', // @translate
            ],
        ]);

        $this->add([
            'name' => 'lockout_long_duration',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Long lock out (seconds)', // @translate
            ],
        ]);

        $this->add([
            'name' => 'lockout_valid_duration',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Valid duration (seconds)', // @translate
            ],
        ]);

        $this->add([
            'name' => 'lockout_whitelist',
            'type' => Element\Textarea::class,
            'options' => [
                'label' => 'Whitelist of IPs', // @translate
            ],
            'attributes' => [
                'placeholder' => 'One IP by line (ipv4 or ipv6)',  // @translate
            ],
        ]);

        // Site connection.

        $this->add([
            'name' => 'lockout_client_type',
            'type' => Element\Radio::class,
            'options' => [
                'label' => 'Client type', // @translate
                'value_options' => [
                    \Lockout\Module::DIRECT_ADDR => 'Direct connection', // @translate
                    \Lockout\Module::PROXY_ADDR => 'From behind a reverse proxy', // @translate
                ],
            ],
        ]);

        /*
        $this->add([
            'name' => 'lockout_cookies',
            'type' => Element\Checkbox::class,
            'options' => [
                'label' => 'Handle cookie login', // @translate
            ],
        ]);
        */

        // Notification.

        $this->add([
            'name' => 'lockout_lockout_notify',
            'type' => Element\MultiCheckbox::class,
            'options' => [
                'label' => 'Notify on lockout', // @translate
                'value_options' => [
                    'log' => 'Log IP', // @translate
                    'email' => 'Email', // @translate
                ],
            ],
        ]);

        $this->add([
            'name' => 'lockout_notify_email_after',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Email to admin after attempts', // @translate
            ],
        ]);

        $inputFilter = $this->getInputFilter();
        foreach ($this as $element) {
            $inputFilter->add([
                'name' => $element->getName(),
                'required' => false,
            ]);
        }
    }
}

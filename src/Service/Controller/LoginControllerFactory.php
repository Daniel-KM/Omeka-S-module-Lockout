<?php
namespace LimitLoginAttempts\Service\Controller;

use Interop\Container\ContainerInterface;
use LimitLoginAttempts\Controller\LoginController;
use Zend\ServiceManager\Factory\FactoryInterface;

class LoginControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        return new LoginController(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\AuthenticationService')
        );
    }
}

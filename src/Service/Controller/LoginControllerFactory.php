<?php
namespace Lockout\Service\Controller;

use Interop\Container\ContainerInterface;
use Lockout\Controller\LoginController;
use Laminas\ServiceManager\Factory\FactoryInterface;

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

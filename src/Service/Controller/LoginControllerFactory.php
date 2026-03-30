<?php declare(strict_types=1);

namespace Lockout\Service\Controller;

use Laminas\ServiceManager\Factory\FactoryInterface;
use Lockout\Controller\LoginController;
use Psr\Container\ContainerInterface;

class LoginControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new LoginController(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\AuthenticationService')
        );
    }
}

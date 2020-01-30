<?php declare(strict_types=1);

namespace Rebel\Hashing;

/**
 * Defines any extra hasher methods in an abstract scope.
 */
abstract class AbstractHasher
{
    /**
     * Get informtion on a hash.
     *
     * @param string $hash The hash to get info on.
     *
     * @return array Returns the hash info.
     */
    public function getInfo(string $hash): array
    {
        return password_get_info($hash);
    }
}

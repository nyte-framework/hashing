<?php declare(strict_types=1);

namespace Rebel\Hashing;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the crypt blowfish algorithm.
 */
final class Bcrypt extends AbstractHasher implements Hasher
{
    use BasicHasher;

    /**
     * Comput a new bcrypt hash.
     *
     * @param string $password The password to hash.
     *
     * @return string Returns the hashed password.
     */
    public function compute(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT, $this->options);
    }

    /**
     * Determine if the hash needs a rehash.
     *
     * @param string $hash The hash to check.
     *
     * @return bool Returns true if the hash needs a rehash and false if not.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, $this->options);
    }

    /**
     * Configure the bcrypt hasher options.
     *
     * @param OptionsResolver The symfony options resolver.
     *
     * @return void Returns nothing.
     */
    private function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'cost' => 10,
        ]);
        $resolver->setAllowedTypes('cost', 'int');
    }
}

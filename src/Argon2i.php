<?php declare(strict_types=1);

namespace Rebel\Hashing;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the argon2id algorithm.
 */
final class Argon2i extends AbstractHasher implements Hasher
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
        return password_hash($password, PASSWORD_ARGON2I, $this->options);
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
        return password_needs_rehash($hash, PASSWORD_ARGON2I, $this->options);
    }

    /**
     * Configure the bcrypt hasher options.
     *
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver The symfony options resolver.
     *
     * @return void Returns nothing.
     */
    private function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => PASSWORD_ARGON2_DEFAULT_THREADS,
        ]);
        $resolver->setAllowedTypes('memory_cost', 'int');
        $resolver->setAllowedTypes('time_cost', 'int');
        $resolver->setAllowedTypes('threads', 'int');
    }
}

<?php declare(strict_types=1);

namespace Rebel\Hashing;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the argon2i algorithm.
 */
final class Argon2i extends AbstractHasher implements Hasher
{
    /** @var array $options The argon2i hasher options. */
    private array $options = [];

    /**
     * Construct a new argon2i hasher.
     *
     * @param array $options The argon2i hasher options.
     *
     * @return void Returns nothing.
     */
    public function __construct(array $options = [])
    {
        $this->setOptions($options);
    }

    /**
     * Set the argon2i hasher options.
     *
     * @param array $options The argon2i hasher options.
     *
     * @return \Rebel\Hashing\Hasher Returns the hasher.
     */
    public function setOptions(array $options = []): Hasher
    {
        $resolver = new OptionsResolver();
        $this->configureOptions($resolver);
        $this->options = $resolver->resolve($options);
        return $this;
    }

    /**
     * Verify the password matches the given hash.
     *
     * @param string $password The password to check.
     * @param string $hash     The hash the password must match.
     *
     * @return bool Returns true if the password matches and false if not.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Comput a new argon2i hash.
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
     * Configure the argon2i hasher options.
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

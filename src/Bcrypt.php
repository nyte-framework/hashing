<?php declare(strict_types=1);

namespace Rebel\Hashing;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Hash the password using the bcrypt algorithm.
 */
final class Bcrypt extends AbstractHasher implements Hasher
{
    /** @var array $options The bcrypt hasher options. */
    private array $options = [];

    /**
     * Construct a new bcrypt hasher.
     *
     * @param array $options The bcrypt hasher options.
     *
     * @return void Returns nothing.
     */
    public function __construct(array $options = [])
    {
        $this->setOptions($options);
    }

    /**
     * Set the bcrypt hasher options.
     *
     * @param array $options The bcrypt hasher options.
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
     * Comput a new bcrypt hash.
     *
     * @param string $password The password to hash.
     *
     * @return null|string Returns the hashed password.
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
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver The symfony options resolver.
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

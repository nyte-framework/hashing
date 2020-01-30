<?php declare(strict_types=1);

namespace Rebel\Hashing;
    
/**
 * Basic hasher methods and variables.
 */
trait BasicHasher
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
     * @param string $hash     THe hash the password must match.
     *
     * @return bool Retursn true if the password matches and false if not.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}

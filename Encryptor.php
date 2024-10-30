<?php

declare(strict_types=1);

namespace Phphleb\Encryptor;

use InvalidArgumentException;

/**
 * Performs encryption and decryption of string values (previously encrypted in this way).
 * Suitable for AES encryption methods.
 *
 * Осуществляет шифрование и расшифровку строковых значений (ранее зашифрованных этим способом).
 * Подходит для методов шифрования AES.
 */
final readonly class Encryptor
{
    /**
     * These parameters must be the same for encryption and decryption of the same value type.
     *
     * Эти параметры должны быть одинаковы для шифрования и расшифровки одного типа значения.
     *
     * @param string $key - passphrase.
     *                    - кодовая фраза.
     *
     * @param string $cipherMethod - encryption method (AES).
     *                             - метод шифрования (AES).
     *
     * @param int $ivLength - the length of the initializing vector must correspond
     *                        to the size of the encryption method block.
     *
     *                      - длина инициализирующего вектора, должна соответствовать
     *                        размерам блока шифровального метода.
     */
    public function __construct(
        private string $key,
        private string $cipherMethod = 'aes-256-cbc',
        private int $ivLength = 16,
    )
    {
        if (empty($this->key)) {
            throw new InvalidArgumentException("Salt cannot be empty");
        }
        if (empty($this->cipherMethod)) {
            throw new InvalidArgumentException("Cipher method cannot be empty");
        }
        if (empty($this->ivLength)) {
            throw new InvalidArgumentException("IV length cannot be empty");
        }
    }

    /**
     * Encrypts a string of arbitrary length, returning ciphertext.
     *
     * Шифрует строку произвольной длины, возвращая зашифрованный текст.
     *
     * @throws EncryptorException
     */
    public function encrypt(string $plaintext): string
    {
        $iv = openssl_random_pseudo_bytes($this->ivLength);

        try {
            $ciphertext = openssl_encrypt($plaintext, $this->cipherMethod, $this->key, OPENSSL_RAW_DATA, $iv);
        } catch (\Exception $e) {
            throw new EncryptorException($e->getMessage(), $e->getCode(), $e);
        }

        return base64_encode($iv . $ciphertext);
    }

    /**
     * Decrypts text encrypted by the encrypt() method, returning the decrypted string.
     *
     * Расшифровывает текст, зашифрованный методом encrypt(), возвращая расшифрованную строку.
     *
     * @throws EncryptorException|EncryptorFailedException
     */
    public function decrypt(string $ciphertext): string
    {
        $decoded = base64_decode($ciphertext);

        $iv = substr($decoded, 0, $this->ivLength);
        $encryptedData = substr($decoded, $this->ivLength);
        try {
            $plaintext = openssl_decrypt($encryptedData, $this->cipherMethod, $this->key, OPENSSL_RAW_DATA, $iv);
        } catch (\Exception $e) {
            throw new EncryptorException($e->getMessage(), $e->getCode(), $e);
        }

        if ($plaintext === false) {
            throw new EncryptorFailedException("Decryption failed");
        }

        return $plaintext;
    }
}


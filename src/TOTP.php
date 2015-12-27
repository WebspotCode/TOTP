<?php

namespace Spot\TOTP;

/**
 * Based on PHPGangsta_GoogleAuthenticator class for handling Google Authenticator
 * 2-factor authentication
 *
 * @author     Michael Kliewe (PHPGangsta_GoogleAuthenticator), Jelmer Schreuder (modifications)
 * @copyright  2012 Michael Kliewe
 * @license    http://www.opensource.org/licenses/bsd-license.php BSD License
 */
class TOTP
{
    /** @var  int */
    private $codeLength = 6;

    /**
     * @param  int $codeLength
     */
    public function __construct(int $codeLength = 6)
    {
        if (!is_int($codeLength) || $codeLength < 6) {
            throw new \OutOfRangeException('Code length must be a valid integer and be 6 or larger.');
        }
        $this->codeLength = $codeLength;
    }

    /** @return  int */
    protected function getCodeLength() : int
    {
        return $this->codeLength;
    }

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param   int $secretLength
     * @return  string
     */
    public function createSecret(int $secretLength = 16) : string
    {
        $validChars = $this->getBase32LookupTable();
        $secret = '';
        for ($i = 0; $i < $secretLength; $i++) {
            $secret .= $validChars[array_rand($validChars)];
        }
        return $secret;
    }

    /**
     * Calculate the code, with given secret and point in time
     */
    public function getCode(string $secret, int $timeSlice = null) : string
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }
        $secretKey = $this->base32Decode($secret);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // Hash it with users secret key
        $hmac = hash_hmac('SHA1', $time, $secretKey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hmac, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hmac, $offset, 4);
        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->getCodeLength());
        return str_pad($value % $modulo, $this->getCodeLength(), '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from google charts
     */
    public function getQRCodeUrl(string $name, string $secret, string $title = null) : string
    {
        $url = 'otpauth://totp/' . urlencode($name) . '?';

        $vars = ['secret' => $secret];
        if (!is_null($title)) {
            $vars['issuer'] = $title;
        }

        return $url . http_build_query($vars);
    }

    /**
     * Check if the code is correct. This will accept codes starting from
     * $discrepancy*30sec ago to $discrepancy*30sec from now
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, int $currentTimeSlice = null) : bool
    {
        if (strlen($code) !== $this->getCodeLength()) {
            throw new \InvalidArgumentException('Code must have exact length: ' . $this->getCodeLength());
        }

        if ($currentTimeSlice === null) {
            $currentTimeSlice = floor(time() / 30);
        }

        // Attempt to match by going through codes ($discrepancy * 30 seconds) before and after
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        // No match found
        return false;
    }

    /**
     * Throws Exception when the secret isn't valid
     *
     * @return  void
     * @throws  \InvalidArgumentException
     */
    protected function validateSecret(string $secret)
    {
        if (empty($secret)) {
            throw new \InvalidArgumentException('Secret cannot be empty');
        }

        // Check encoding
        $base32chars = $this->getBase32LookupTable();
        if (preg_match('#([^' . implode('', $base32chars) . '=])#', $secret, $matches) === 1) {
            throw new \InvalidArgumentException('Invalid character encountered in secret: ' . $matches[1]);
        }

        // Check padding
        $paddingCharCount = substr_count($secret, '=');
        $allowedValues = [6, 4, 3, 1, 0];
        if (!in_array($paddingCharCount, $allowedValues)) {
            throw new \InvalidArgumentException(
                'Invalid padding encountered in secret, must be 6, 4, 3, 1 or 0'
            );
        }
        if ($paddingCharCount > 0 && substr($secret, -($paddingCharCount)) !== str_repeat('=', $paddingCharCount)) {
            throw new \InvalidArgumentException(
                'Invalid padding encountered in secret, all = characters must be at the end'
            );
        }
    }

    /**
     * Helper class to decode base32
     */
    protected function base32Decode(string $secret) : string
    {
        $this->validateSecret($secret);

        $base32charsFlipped = array_flip($this->getBase32LookupTable());

        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);

        // Go byte by byte through the secret and build the output binary string
        $binaryString = '';
        for ($byte = 0; $byte < count($secret); $byte = $byte + 8) {
            $string = '';
            for ($bit = 0; $bit < 8; $bit++) {
                $char = base_convert($base32charsFlipped[$secret[$byte + $bit]], 10, 2);
                $string .= str_pad($char, 5, '0', STR_PAD_LEFT);
            }

            $eightBits = str_split($string, 8);
            foreach ($eightBits as $bit) {
                $binaryString .= (($y = chr(base_convert($bit, 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * Get array with all 32 characters for decoding from/encoding to base32
     *
     * @return  string[]
     */
    protected function getBase32LookupTable() : array
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        ];
    }
}

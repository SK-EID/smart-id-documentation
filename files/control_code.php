/**
 * Compute's verification code for Smart-ID
 *
 * @param string $rawHashInBase64       base64 encoded hash ("SHA256", "SHA384" or "SHA512)
 * @return string                       Verification Code, 0000-9999, left-paded with zeros
 *
 */
function VerificationCode($rawHashInBase64){
     
    // Hash raw input with SHA256
    $sha256Hashed_input = hash('sha256', base64_decode($rawHashInBase64), $raw_output = true);
     
    // extract 2 rightmost bytes from it, interpret them as a big-endian unsigned integer
    $integer = implode('', unpack('n', substr($sha256Hashed_input, -2, 2)));
     
    // take the last 4 digits in decimal for display
    $VerificationCode=str_pad(substr(($integer % 10000), -4), 4, '0', STR_PAD_LEFT);
     
    return $VerificationCode;
}

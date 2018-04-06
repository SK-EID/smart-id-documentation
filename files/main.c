// clang main.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -o Test 
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief VerificationCode generates Smart-ID verification code
 * @param in raw hash used in Smart-ID request (must be base64 decoded first)
 * @param size raw hash size in
 * @param out Verification Code, 0000-9999, left-paded with zeros
 * @return returns 0 on error or lenght of code size in chars
 */
int VerificationCode(const unsigned char *in, size_t size, char *out)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	if(SHA256(in, size, digest) == NULL)
		return 0;
	char buffer[5];
	if(snprintf(buffer, 5, "%02X%02X", digest[SHA256_DIGEST_LENGTH - 2], digest[SHA256_DIGEST_LENGTH - 1]) != 4)
		return 0;
	return sprintf(out, "%04lu", strtoul(buffer, NULL, 16) % 10000);
}

int main(int argc, char *argv[])
{
	if(argc != 2)
		return 0;
	FILE *f = fopen(argv[1], "rb");

	// Get file size
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	rewind(f);

	// Read content
	unsigned char *data = (unsigned char*)malloc(sizeof(unsigned char)*size);
	fread(data, 1, size, f);
	fclose(f);

	// Calculate code
	char code[4];
	int result = VerificationCode(data, size, code);
	free(data);
	return printf("Verification code: %s\n", code);
}

#include "seal/seal.h"
#include <iostream>
#include <iomanip>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace std;
using namespace seal;

template<typename T>
void println(T&& x)
{
	/*
         * Define window size to print separation lines.
         */
        winsize w;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	/*
	 * Print an object x for each column of the terminal.
	 */
	cout << left << setw(w.ws_col) << setfill(x) << "";
}

int main()
{
	/*
	 * Store remaining noise budget for the computation.
	 */
	int rem_noise_bdgt;
	/*
	 * Encryption parameters for the BFV example.
	 */
	EncryptionParameters parms(scheme_type::bfv);
	/*
	 * Set the polynomial modulus degree as a power of 2.
	 * Options: {1024, 2048, 4096, 8192, 16384, 32768}
	 * With smaller degrees the security level is sacrified in exchange of computational efficiency.
	 */
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	/*
	 * Set the coefficient modulus bit length.
	 * Its upper bound is set by the polymodulus degree chosen.
	 * For poly_modulus_degree=4096, the coeff_modulus needed is 109.
	 */
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	/*
	 * Determine the size of the plaintext data type and the consumption of noise budget in the multiplication.
	 * It should be kept as small as possible.
	 */
	parms.set_plain_modulus(1024);
	/*
	 * Context
	 */
	SEALContext context(parms);
	/*
	 * Public Key Encryption scheme.
	 * Multiple parties will be able to encode with the public key but only one can decrypt with the secret key.
	 * The KeyGenerator will automatically generate the secret key.
	 * Create as many public keys as desired.
	 */
	KeyGenerator keygen(context);
	SecretKey secret_key = keygen.secret_key();
	PublicKey public_key;
	keygen.create_public_key(public_key);
	/*
	 * Encryptor tool given a public key.
	 */
	Encryptor encryptor(context, public_key);
	/*
	 * Evaluator tool to be able to compute sums and multiplications.
	 */
	Evaluator evaluator(context);
	/*
	 * Decryptor tool given the secret key.
	 */
	Decryptor decryptor(context, secret_key);


	/*
	 * Once the parameters have been set, let's compute the encryption of a polynomial.
	 * This example will show how the multiplication consumes a great deal of noise budget.
	 *
	 * The polynomial will be: 2x⁴ + 4x²
	 * We will first evaluate its direct computation and the effect on the noise budget.
	 */

	// Define the plaintext the formula will be computed onto
	uint64_t x = 4;
	char hex_string[20];
	sprintf(hex_string, "%lu", x);
	Plaintext x_plain(hex_string);
	
	// Encrypt the given plaintext
	Ciphertext x_encrypted;
	encryptor.encrypt(x_plain, x_encrypted);
	rem_noise_bdgt = decryptor.invariant_noise_budget(x_encrypted);
	cout << "Size of the encrypted ciphertext: " << x_encrypted.size() << endl;
	cout << "Noise budget of the ciphertext: " << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;
	println('*');

	// Compute the formula
	cout << "Compute 2x⁴ + 4x²" << endl;
	println('*');

	Ciphertext encrypted_result;
	
	Plaintext plain_two("2");
	Plaintext plain_four("4");
	
	Ciphertext x_sq;
	evaluator.square(x_encrypted, x_sq);
	evaluator.multiply_plain_inplace(x_sq, plain_four);
	rem_noise_bdgt = rem_noise_bdgt - decryptor.invariant_noise_budget(x_sq);
	cout << "Size of 4*x²: " << x_sq.size() << endl;
	cout << "Noise budget of 4*x²: " << decryptor.invariant_noise_budget(x_sq) << " bits" << endl << endl;

	Ciphertext x_fourth;
	evaluator.square(x_encrypted, x_fourth);
	evaluator.square_inplace(x_fourth);
	evaluator.multiply_plain_inplace(x_fourth, plain_two);
	rem_noise_bdgt = rem_noise_bdgt - decryptor.invariant_noise_budget(x_fourth);
	cout << "Size of 2*x⁴: " << x_fourth.size() << endl;
	cout << "Noise budget of 2*x⁴: " << decryptor.invariant_noise_budget(x_fourth) << " bits" << endl << endl;

	evaluator.add(x_sq, x_fourth, encrypted_result);
	rem_noise_bdgt = rem_noise_bdgt - decryptor.invariant_noise_budget(encrypted_result);
	cout << "Size of 2*x⁴ + 4*x²: " << encrypted_result.size() << endl;
	cout << "Noise budget of 2*x⁴ + 4*x²: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl << endl;

	// Check decryption
	Plaintext decrypted_result;
	decryptor.decrypt(encrypted_result, decrypted_result);
	cout << "Decryption: 0x" << decrypted_result.to_string() << endl;
	cout << "Remaining noise budget: " << rem_noise_bdgt << endl;

	return 0;
}

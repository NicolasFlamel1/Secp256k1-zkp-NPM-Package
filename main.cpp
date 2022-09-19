// Header files
#include <climits>
#include <cerrno>
#include <string>
#include <vector>

// Check if using Emscripten
#ifdef __EMSCRIPTEN__

	// Header files
	#include <emscripten.h>
	#include "secp256k1_aggsig.h"
	#include "secp256k1_bulletproofs.h"
	#include "secp256k1_commitment.h"
	#include "secp256k1_ecdh.h"

// Otherwise
#else

	// Header files
	extern "C" {
		#include "secp256k1_aggsig.h"
		#include "secp256k1_bulletproofs.h"
		#include "secp256k1_commitment.h"
		#include "secp256k1_ecdh.h"
	}
#endif

using namespace std;


// Definitions

// Check if using Emscripten
#ifdef __EMSCRIPTEN__

	// Export
	#define EXPORT extern "C"

// Otherwise
#else

	// Export
	#define EXPORT static

	// Emscripten keepalive
	#define EMSCRIPTEN_KEEPALIVE
#endif


// Constants

// Blind size
static const size_t BLIND_SIZE = 32;

// Generator J public
static const secp256k1_pubkey GENERATOR_J_PUBLIC = {
	{
		0x5F, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2A, 0x8D, 0x8B, 0x39, 0x7E, 0x9B, 0xF4, 0x54, 0x29, 0x2F, 0x5A, 0x1B, 0x3D, 0x38, 0x85, 0x16, 0xC2, 0xF3, 0x03, 0xFC, 0x95, 0x67, 0xF5, 0x60, 0xB8, 0x3A, 0xC4, 0xC5, 0xA6, 0xDC, 0xA2, 0x01, 0x59, 0xFC, 0x56, 0xCF, 0x74, 0x9A, 0xA6, 0xA5, 0x65, 0x31, 0x6A, 0xA5, 0x03, 0x74, 0x42, 0x3F, 0x42, 0x53, 0x8F, 0xAA, 0x2C, 0xD3, 0x09, 0x3F, 0xA4
	}
};

// Secret key size
static const size_t SECRET_KEY_SIZE = 32;

// Commit size
static const size_t COMMIT_SIZE = 33;

// Public key size
static const size_t PUBLIC_KEY_SIZE = 33;

// Uncompressed public key size
static const size_t UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;

// Bulletproof proof size
static const size_t BULLETPROOF_PROOF_SIZE = 675;

// Bulletproof message size
static const size_t BULLETPROOF_MESSAGE_SIZE = 20;

// Decimal number base
static const int DECIMAL_NUMBER_BASE = 10;

// Scratch space size
static const size_t SCRATCH_SPACE_SIZE = 30 * 1024;

// Number of generators
static const size_t NUMBER_OF_GENERATORS = 256;

// Bits in a byte
static const size_t BITS_IN_A_BYTE = 8;

// Single-signer signature size
static const size_t SINGLE_SIGNER_SIGNATURE_SIZE = 64;

// Single-signer message size
static const size_t SINGLE_SIGNER_MESSAGE_SIZE = 32;

// Seed size
static const size_t SEED_SIZE = 32;

// Bits proven per range
static const size_t BITS_PROVEN_PER_RANGE = sizeof(uint64_t) * BITS_IN_A_BYTE;

// Nonce size
static const size_t NONCE_SIZE = 32;

// Tweak size
static const size_t TWEAK_SIZE = 32;

// Maximum message hash signature size
static const size_t MAXIMUM_MESSAGE_HASH_SIGNATURE_SIZE = 72;

// Message hash size
static const size_t MESSAGE_HASH_SIZE = 32;

// Tau x size
static const size_t TAU_X_SIZE = 32;


// Global variables

// Context
static secp256k1_context *context = nullptr;

// Scratch space
static secp256k1_scratch_space *scratchSpace = nullptr;

// Generators
static secp256k1_bulletproof_generators *generators = nullptr;


// Function prototypes

// Initialize
EXPORT bool EMSCRIPTEN_KEEPALIVE initialize(InstanceData *instanceData);

// Uninistalize
EXPORT bool EMSCRIPTEN_KEEPALIVE uninitialize(InstanceData *instanceData);

// Blind size
EXPORT size_t EMSCRIPTEN_KEEPALIVE blindSize(InstanceData *instanceData);

// Blind switch
EXPORT bool EMSCRIPTEN_KEEPALIVE blindSwitch(InstanceData *instanceData, uint8_t *result, const uint8_t *blind, size_t blindSize, const char *value);

// Blind sum
EXPORT bool EMSCRIPTEN_KEEPALIVE blindSum(InstanceData *instanceData, uint8_t *result, const uint8_t *blinds, size_t blindsSizes[], size_t numberOfBlinds, size_t numberOfPositiveBlinds);

// Is valid secret key
EXPORT bool EMSCRIPTEN_KEEPALIVE isValidSecretKey(InstanceData *instanceData, const uint8_t *secretKey, size_t secretKeySize);

// Is valid public key
EXPORT bool EMSCRIPTEN_KEEPALIVE isValidPublicKey(InstanceData *instanceData, const uint8_t *publicKey, size_t publicKeySize);

// Is valid commit
EXPORT bool EMSCRIPTEN_KEEPALIVE isValidCommit(InstanceData *instanceData, const uint8_t *commit, size_t commitSize);

// Is valid single-signer signature
EXPORT bool EMSCRIPTEN_KEEPALIVE isValidSingleSignerSignature(InstanceData *instanceData, const uint8_t *signature, size_t signatureSize);

// Bulletproof size
EXPORT size_t EMSCRIPTEN_KEEPALIVE bulletproofProofSize(InstanceData *instanceData);

// Create bulletproof
EXPORT bool EMSCRIPTEN_KEEPALIVE createBulletproof(InstanceData *instanceData, uint8_t *proof, char *proofSize, const uint8_t *blind, size_t blindSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *privateNonce, size_t privateNonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize);

// Create bulletproof blindless
EXPORT bool EMSCRIPTEN_KEEPALIVE createBulletproofBlindless(InstanceData *instanceData, uint8_t *proof, char *proofSize, uint8_t *tauX, size_t tauXSize, const uint8_t *tOne, size_t tOneSize, const uint8_t *tTwo, size_t tTwoSize, const uint8_t *commit, size_t commitSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize);

// Bulletproof message size
EXPORT size_t EMSCRIPTEN_KEEPALIVE bulletproofMessageSize(InstanceData *instanceData);

// Rewind bulletproof
EXPORT bool EMSCRIPTEN_KEEPALIVE rewindBulletproof(InstanceData *instanceData, char *value, uint8_t *blind, uint8_t *message, const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *nonce, size_t nonceSize);

// Verify bulletproof
EXPORT bool EMSCRIPTEN_KEEPALIVE verifyBulletproof(InstanceData *instanceData, const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *extraCommit, size_t extraCommitSize);

// Public key size
EXPORT size_t EMSCRIPTEN_KEEPALIVE publicKeySize(InstanceData *instanceData);

// Public key from secret key
EXPORT bool EMSCRIPTEN_KEEPALIVE publicKeyFromSecretKey(InstanceData *instanceData, uint8_t *publicKey, const uint8_t *secretKey, size_t secretKeySize);

// Public key from data
EXPORT bool EMSCRIPTEN_KEEPALIVE publicKeyFromData(InstanceData *instanceData, uint8_t *publicKey, const uint8_t *data, size_t dataSize);

// Uncompressed public key size
EXPORT size_t EMSCRIPTEN_KEEPALIVE uncompressedPublicKeySize(InstanceData *instanceData);

// Uncompress public key
EXPORT bool EMSCRIPTEN_KEEPALIVE uncompressPublicKey(InstanceData *instanceData, uint8_t *uncompressedPublicKey, const uint8_t *publicKey, size_t publicKeySize);

// Secret key size
EXPORT size_t EMSCRIPTEN_KEEPALIVE secretKeySize(InstanceData *instanceData);

// Secret key tweak add
EXPORT bool EMSCRIPTEN_KEEPALIVE secretKeyTweakAdd(InstanceData *instanceData, uint8_t *secretKey, size_t secretKeySize, const uint8_t *tweak, size_t tweakSize);

// Public key tweak add
EXPORT bool EMSCRIPTEN_KEEPALIVE publicKeyTweakAdd(InstanceData *instanceData, uint8_t *publicKey, size_t publicKeySize, const uint8_t *tweak, size_t tweakSize);

// Secret key tweak multiply
EXPORT bool EMSCRIPTEN_KEEPALIVE secretKeyTweakMultiply(InstanceData *instanceData, uint8_t *secretKey, size_t secretKeySize, const uint8_t *tweak, size_t tweakSize);

// Public key tweak multiply
EXPORT bool EMSCRIPTEN_KEEPALIVE publicKeyTweakMultiply(InstanceData *instanceData, uint8_t *publicKey, size_t publicKeySize, const uint8_t *tweak, size_t tweakSize);

// Shared secret key from secret key and public key
EXPORT bool EMSCRIPTEN_KEEPALIVE sharedSecretKeyFromSecretKeyAndPublicKey(InstanceData *instanceData, uint8_t *sharedSecretKey, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *publicKey, size_t publicKeySize);

// Commit size
EXPORT size_t EMSCRIPTEN_KEEPALIVE commitSize(InstanceData *instanceData);

// Pedersen commit
EXPORT bool EMSCRIPTEN_KEEPALIVE pedersenCommit(InstanceData *instanceData, uint8_t *result, const uint8_t *blind, size_t blindSize, const char *value);

// Pedersen commit sum
EXPORT bool EMSCRIPTEN_KEEPALIVE pedersenCommitSum(InstanceData *instanceData, uint8_t *result, const uint8_t *positiveCommits, size_t positiveCommitsSizes[], size_t numberOfPositiveCommits, const uint8_t *negativeCommits, size_t negativeCommitsSizes[], size_t numberOfNegativeCommits);

// Pedersen commit to public key
EXPORT bool EMSCRIPTEN_KEEPALIVE pedersenCommitToPublicKey(InstanceData *instanceData, uint8_t *publicKey, const uint8_t *commit, size_t commitSize);

// Public key to Pedersen commit
EXPORT bool EMSCRIPTEN_KEEPALIVE publicKeyToPedersenCommit(InstanceData *instanceData, uint8_t *commit, const uint8_t *publicKey, size_t publicKeySize);

// Single-signer signature size
EXPORT size_t EMSCRIPTEN_KEEPALIVE singleSignerSignatureSize(InstanceData *instanceData);

// Seed size
EXPORT size_t EMSCRIPTEN_KEEPALIVE seedSize(InstanceData *instanceData);

// Create single-signer signature
EXPORT bool EMSCRIPTEN_KEEPALIVE createSingleSignerSignature(InstanceData *instanceData, uint8_t *signature, const uint8_t *message, size_t messageSize, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *secretNonce, size_t secretNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize, const uint8_t *seed, size_t seedSize);

// Add single-signer signatures
EXPORT bool EMSCRIPTEN_KEEPALIVE addSingleSignerSignatures(InstanceData *instanceData, uint8_t *result, const uint8_t *signatures, size_t signaturesSizes[], size_t numberOfSignatures, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize);

// Verify single-signer signature
EXPORT bool EMSCRIPTEN_KEEPALIVE verifySingleSignerSignature(InstanceData *instanceData, const uint8_t *signature, size_t signatureSize, const uint8_t *message, size_t messageSize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicKeyTotal, size_t publicKeyTotalSize, bool isPartial);

// Single-signer signature from data
EXPORT bool EMSCRIPTEN_KEEPALIVE singleSignerSignatureFromData(InstanceData *instanceData, uint8_t *signature, const uint8_t *data, size_t dataSize);

// Uncompact single-signer signature size
EXPORT size_t EMSCRIPTEN_KEEPALIVE uncompactSingleSignerSignatureSize(InstanceData *instanceData);

// Compact single-signer signature
EXPORT bool EMSCRIPTEN_KEEPALIVE compactSingleSignerSignature(InstanceData *instanceData, uint8_t *result, const uint8_t *signature, size_t signatureSize);

// Uncompact single-signer signature
EXPORT bool EMSCRIPTEN_KEEPALIVE uncompactSingleSignerSignature(InstanceData *instanceData, uint8_t *result, const uint8_t *signature, size_t signatureSize);

// Combine public keys
EXPORT bool EMSCRIPTEN_KEEPALIVE combinePublicKeys(InstanceData *instanceData, uint8_t *result, const uint8_t *publicKeys, size_t publicKeysSizes[], size_t numberOfPublicKeys);

// Nonce size
EXPORT size_t EMSCRIPTEN_KEEPALIVE nonceSize(InstanceData *instanceData);

// Create secret nonce
EXPORT bool EMSCRIPTEN_KEEPALIVE createSecretNonce(InstanceData *instanceData, uint8_t *nonce, const uint8_t *seed, size_t seedSize);

// Maximum message hash signature size
EXPORT size_t EMSCRIPTEN_KEEPALIVE maximumMessageHashSignatureSize(InstanceData *instanceData);

// Create message hash signature
EXPORT bool EMSCRIPTEN_KEEPALIVE createMessageHashSignature(InstanceData *instanceData, uint8_t *signature, char *signatureSize, const uint8_t *messageHash, size_t messageHashSize, const uint8_t *secretKey, size_t secretKeySize);

// Verify message hash signature
EXPORT bool EMSCRIPTEN_KEEPALIVE verifyMessageHashSignature(InstanceData *instanceData, const uint8_t *signature, size_t signatureSize, const uint8_t *messageHash, size_t messageHashSize, const uint8_t *publicKey, size_t publicKeySize);

// Is zero array
static bool isZeroArray(InstanceData *instanceData, void *value, size_t size);


// Supporting function implementation

// Initialize
bool initialize(InstanceData *instanceData) {

	// Check if creating context failed
	context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	if(!context) {
	
		// Return false
		return false;
	}
	
	// Check if creating scratch space failed
	scratchSpace = secp256k1_scratch_space_create(instanceData->context, SCRATCH_SPACE_SIZE);
	if(!scratchSpace) {
	
		// Return false
		return false;
	}
	
	// Check if creating generators failed
	generators = secp256k1_bulletproof_generators_create(instanceData->context, &secp256k1_generator_const_g, NUMBER_OF_GENERATORS);
	if(!generators) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Uninitialize
bool uninitialize(InstanceData *instanceData) {

	// Check if generators exist
	if(generators) {
	
		// Destroy generators
		secp256k1_bulletproof_generators_destroy(instanceData->context, generators);
		
		// Clear generators
		generators = nullptr;
	}
	
	// Check if scratch space exists
	if(scratchSpace) {
	
		// Destroy scratch space
		secp256k1_scratch_space_destroy(scratchSpace);
		
		// Clear scratch space
		scratchSpace = nullptr;
	}

	// Check if context exists
	if(context) {
	
		// Destroy context
		secp256k1_context_destroy(context);
		
		// Clear context
		context = nullptr;
	}
	
	// Return true
	return true;
}

// Blind size
size_t blindSize(InstanceData *instanceData) {

	// Return blind size
	return BLIND_SIZE;
}

// Blind switch
bool blindSwitch(InstanceData *instanceData, uint8_t *result, const uint8_t *blind, size_t blindSize, const char *value) {

	// Check if blind is invalid
	if(blindSize != BLIND_SIZE) {
	
		// Return false
		return false;
	}

	// Check if parsing value as a number failed
	char *lastCharacter;
	errno = 0;
	uint64_t numericValue = strtoull(value, &lastCharacter, DECIMAL_NUMBER_BASE);
	if(lastCharacter == value || *lastCharacter != '\0' || value[0] == '-' || value[0] == '+' || (numericValue == ULLONG_MAX && errno == ERANGE)) {
	
		// Return false
		return false;
	}
	
	// Check if performing blind switch failed
	if(!secp256k1_blind_switch(instanceData->context, result, blind, numericValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g, &GENERATOR_J_PUBLIC)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Blind sum
bool blindSum(InstanceData *instanceData, uint8_t *result, const uint8_t *blinds, size_t blindsSizes[], size_t numberOfBlinds, size_t numberOfPositiveBlinds) {

	// Go through all blinds
	vector<const uint8_t *> blindsAddresses(numberOfBlinds);
	for(size_t i = 0; i < numberOfBlinds; ++i) {
	
		// Check if blind is invalid
		if(blindsSizes[i] != BLIND_SIZE) {
		
			// Return false
			return false;
		}
		
		// Store blind's address
		blindsAddresses[i] = &blinds[i * BLIND_SIZE];
	}
	
	// Check if performing pedersen blind sum failed
	if(!secp256k1_pedersen_blind_sum(instanceData->context, result, blindsAddresses.data(), numberOfBlinds, numberOfPositiveBlinds))
	
		// Return false
		return false;
	
	// Return true
	return true;	
}

// Is valid secret key
bool isValidSecretKey(InstanceData *instanceData, const uint8_t *secretKey, size_t secretKeySize) {

	// Check if secret key size is invalid
	if(secretKeySize != SECRET_KEY_SIZE) {
	
		// Return false
		return false;
	}

	// Check if cannot verify secret key
	if(!secp256k1_ec_seckey_verify(instanceData->context, secretKey)) {
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid public key
bool isValidPublicKey(InstanceData *instanceData, const uint8_t *publicKey, size_t publicKeySize) {

	// Check if public key size is invalid
	if(publicKeySize != PUBLIC_KEY_SIZE) {
	
		// Return false
		return false;
	}

	// Check if cannot verify public key
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Clear memory
		explicit_bzero(&publicKeyData, sizeof(publicKeyData));
		
		// Return false
		return false;
	}
	
	// Clear memory
	explicit_bzero(&publicKeyData, sizeof(publicKeyData));
	
	// Return true
	return true;
}

// Is valid commit
bool isValidCommit(InstanceData *instanceData, const uint8_t *commit, size_t commitSize) {

	// Check if commit size is invalid
	if(commitSize != COMMIT_SIZE) {
	
		// Return false
		return false;
	}

	// Check if cannot verify commit
	secp256k1_pedersen_commitment commitData;
	if(!secp256k1_pedersen_commitment_parse(instanceData->context, &commitData, commit)) {
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid single-signer signature
bool isValidSingleSignerSignature(InstanceData *instanceData, const uint8_t *signature, size_t signatureSize) {

	// Check if signature size is invalid
	if(signatureSize != SINGLE_SIGNER_SIGNATURE_SIZE) {
	
		// Return false
		return false;
	}

	// Check if cannot verify signature
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_ecdsa_signature_parse_compact(instanceData->context, &signatureData, signature)) {
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Bulletproof proof size
size_t bulletproofProofSize(InstanceData *instanceData) {

	// Return bulletproof proof size
	return BULLETPROOF_PROOF_SIZE;
}

// Create bulletproof
bool createBulletproof(InstanceData *instanceData, uint8_t *proof, char *proofSize, const uint8_t *blind, size_t blindSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *privateNonce, size_t privateNonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize) {

	// Check if blind is invalid
	if(blindSize != BLIND_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing value as a number failed
	char *lastCharacter;
	errno = 0;
	uint64_t numericValue = strtoull(value, &lastCharacter, DECIMAL_NUMBER_BASE);
	if(lastCharacter == value || *lastCharacter != '\0' || value[0] == '-' || value[0] == '+' || (numericValue == ULLONG_MAX && errno == ERANGE)) {
	
		// Return false
		return false;
	}
	
	// Check if nonce is invalid
	if(nonceSize != NONCE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if private nonce is invalid
	if(privateNonceSize != NONCE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if message is invalid
	if(messageSize != BULLETPROOF_MESSAGE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if creating bulletproof failed
	size_t numericProofSize = BULLETPROOF_PROOF_SIZE;
	if(!secp256k1_bulletproof_rangeproof_prove(instanceData->context, instanceData->scratchSpace, instanceData->generators, proof, &numericProofSize, nullptr, nullptr, nullptr, &numericValue, nullptr, &blind, nullptr, 1, &secp256k1_generator_const_h, BITS_PROVEN_PER_RANGE, nonce, privateNonce, extraCommitSize ? extraCommit : nullptr, extraCommitSize, message)) {
	
		// Return false
		return false;
	}
	
	// Copy numeric proof size to proof size
	string stringProofSize = to_string(numericProofSize);
	memcpy(proofSize, stringProofSize.c_str(), stringProofSize.length() + sizeof('\0'));
	
	// Return true
	return true;
}

// Create bulletproof blindless
bool createBulletproofBlindless(InstanceData *instanceData, uint8_t *proof, char *proofSize, uint8_t *tauX, size_t tauXSize, const uint8_t *tOne, size_t tOneSize, const uint8_t *tTwo, size_t tTwoSize, const uint8_t *commit, size_t commitSize, const char *value, const uint8_t *nonce, size_t nonceSize, const uint8_t *extraCommit, size_t extraCommitSize, const uint8_t *message, size_t messageSize) {

	// Check if tau x is invalid
	if(tauXSize != TAU_X_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing t one failed
	secp256k1_pubkey tOneData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &tOneData, tOne, tOneSize)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing t two failed
	secp256k1_pubkey tTwoData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &tTwoData, tTwo, tTwoSize)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing commit failed
	secp256k1_pedersen_commitment commitData;
	if(!secp256k1_pedersen_commitment_parse(instanceData->context, &commitData, commit)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing value as a number failed
	char *lastCharacter;
	errno = 0;
	uint64_t numericValue = strtoull(value, &lastCharacter, DECIMAL_NUMBER_BASE);
	if(lastCharacter == value || *lastCharacter != '\0' || value[0] == '-' || value[0] == '+' || (numericValue == ULLONG_MAX && errno == ERANGE)) {
	
		// Return false
		return false;
	}
	
	// Check if nonce is invalid
	if(nonceSize != NONCE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if message is invalid
	if(messageSize != BULLETPROOF_MESSAGE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if creating bulletproof blindless failed
	size_t numericProofSize = BULLETPROOF_PROOF_SIZE;
	const secp256k1_pedersen_commitment *commits[] = {
		&commitData
	};
	if(!secp256k1_bulletproof_rangeproof_prove(instanceData->context, instanceData->scratchSpace, instanceData->generators, proof, &numericProofSize, tauX, &tOneData, &tTwoData, &numericValue, nullptr, nullptr, commits, 1, &secp256k1_generator_const_h, BITS_PROVEN_PER_RANGE, nonce, nullptr, extraCommitSize ? extraCommit : nullptr, extraCommitSize, message)) {
	
		// Return false
		return false;
	}
	
	// Copy numeric proof size to proof size
	string stringProofSize = to_string(numericProofSize);
	memcpy(proofSize, stringProofSize.c_str(), stringProofSize.length() + sizeof('\0'));
	
	// Return true
	return true;
}

// Bulletproof message size
size_t bulletproofMessageSize(InstanceData *instanceData) {

	// Return bulletproof message size
	return BULLETPROOF_MESSAGE_SIZE;
}

// Rewind bulletproof
bool rewindBulletproof(InstanceData *instanceData, char *value, uint8_t *blind, uint8_t *message, const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *nonce, size_t nonceSize) {
	
	// Check if commit is invalid
	if(commitSize != COMMIT_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if nonce is invalid
	if(nonceSize != NONCE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing commit failed
	secp256k1_pedersen_commitment commitData;
	if(!secp256k1_pedersen_commitment_parse(instanceData->context, &commitData, commit)) {
	
		// Return false
		return false;
	}
	
	// Check if performing bulletproof rangeproof rewind failed
	uint64_t numericValue;
	if(!secp256k1_bulletproof_rangeproof_rewind(instanceData->context, &numericValue, blind, proof, proofSize, 0, &commitData, &secp256k1_generator_const_h, nonce, nullptr, 0, message)) {
	
		// Return false
		return false;
	}
	
	// Copy numeric value to value
	string stringValue = to_string(numericValue);
	memcpy(value, stringValue.c_str(), stringValue.length() + sizeof('\0'));
	
	// Return true
	return true;
}

// Verify bulletproof
bool verifyBulletproof(InstanceData *instanceData, const uint8_t *proof, size_t proofSize, const uint8_t *commit, size_t commitSize, const uint8_t *extraCommit, size_t extraCommitSize) {

	// Check if commit is invalid
	if(commitSize != COMMIT_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing commit failed
	secp256k1_pedersen_commitment commitData;
	if(!secp256k1_pedersen_commitment_parse(instanceData->context, &commitData, commit)) {
	
		// Return false
		return false;
	}
	
	// Check if cannot verify bulletproof
	if(!secp256k1_bulletproof_rangeproof_verify(instanceData->context, instanceData->scratchSpace, instanceData->generators, proof, proofSize, nullptr, &commitData, 1, BITS_PROVEN_PER_RANGE, &secp256k1_generator_const_h, extraCommitSize ? extraCommit : nullptr, extraCommitSize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Public key size
size_t publicKeySize(InstanceData *instanceData) {

	// Return public key size
	return PUBLIC_KEY_SIZE;
}

// Public key from secret key
bool publicKeyFromSecretKey(InstanceData *instanceData, uint8_t *publicKey, const uint8_t *secretKey, size_t secretKeySize) {

	// Check if secret key is invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}

	// Check if creating public key from secret key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_create(instanceData->context, &publicKeyData, secretKey)) {
	
		// Clear memory
		explicit_bzero(&publicKeyData, sizeof(publicKeyData));
	
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t publicKeySize = PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, publicKey, &publicKeySize, &publicKeyData, SECP256K1_EC_COMPRESSED)) {
	
		// Clear memory
		explicit_bzero(&publicKeyData, sizeof(publicKeyData));
	
		// Return false
		return false;
	}
	
	// Clear memory
	explicit_bzero(&publicKeyData, sizeof(publicKeyData));
	
	// Return true
	return true;
}

// Public key from data
bool publicKeyFromData(InstanceData *instanceData, uint8_t *publicKey, const uint8_t *data, size_t dataSize) {

	// Check if creating public key from data failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, data, dataSize)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t publicKeySize = PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, publicKey, &publicKeySize, &publicKeyData, SECP256K1_EC_COMPRESSED)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Uncompressed public key size
size_t uncompressedPublicKeySize(InstanceData *instanceData) {

	// Return uncompressed public key size
	return UNCOMPRESSED_PUBLIC_KEY_SIZE;
}

// Uncompress public key
bool uncompressPublicKey(InstanceData *instanceData, uint8_t *uncompressedPublicKey, const uint8_t *publicKey, size_t publicKeySize) {

	// Check if public key size is invalid
	if(publicKeySize != PUBLIC_KEY_SIZE) {
	
		// Return false
		return false;
	}

	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t uncompressedPublicKeySize = UNCOMPRESSED_PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, uncompressedPublicKey, &uncompressedPublicKeySize, &publicKeyData, SECP256K1_EC_UNCOMPRESSED)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Secret key size
size_t secretKeySize(InstanceData *instanceData) {

	// Return secret key size
	return SECRET_KEY_SIZE;
}

// Secret key tweak add
bool secretKeyTweakAdd(InstanceData *instanceData, uint8_t *secretKey, size_t secretKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Check if secret key is invalid and it's not zero
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize) && !isZeroArray(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if tweak is invalid
	if(tweakSize != TWEAK_SIZE) {
	
		// Return false
		return false;
	}

	// Check if performing secret key tweak add failed
	if(!secp256k1_ec_privkey_tweak_add(instanceData->context, secretKey, tweak)) {
	
		// Return false
		return false;
	}
	
	// Check if secret key is invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Public key tweak add
bool publicKeyTweakAdd(InstanceData *instanceData, uint8_t *publicKey, size_t publicKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if tweak is invalid
	if(tweakSize != TWEAK_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if performing public key tweak add failed
	if(!secp256k1_ec_pubkey_tweak_add(instanceData->context, &publicKeyData, tweak)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t newPublicKeySize = PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, publicKey, &newPublicKeySize, &publicKeyData, SECP256K1_EC_COMPRESSED)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Secret key tweak multiply
bool secretKeyTweakMultiply(InstanceData *instanceData, uint8_t *secretKey, size_t secretKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Check if secret key is invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if tweak is invalid
	if(tweakSize != TWEAK_SIZE) {
	
		// Return false
		return false;
	}

	// Check if performing secret key tweak multiply failed
	if(!secp256k1_ec_privkey_tweak_mul(instanceData->context, secretKey, tweak)) {
	
		// Return false
		return false;
	}
	
	// Check if secret key is still invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Public key tweak multiply
bool publicKeyTweakMultiply(InstanceData *instanceData, uint8_t *publicKey, size_t publicKeySize, const uint8_t *tweak, size_t tweakSize) {

	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if tweak is invalid
	if(tweakSize != TWEAK_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if performing public key tweak multiply failed
	if(!secp256k1_ec_pubkey_tweak_mul(instanceData->context, &publicKeyData, tweak)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t newPublicKeySize = PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, publicKey, &newPublicKeySize, &publicKeyData, SECP256K1_EC_COMPRESSED)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Shared secret key from secret key and public key
bool sharedSecretKeyFromSecretKeyAndPublicKey(InstanceData *instanceData, uint8_t *sharedSecretKey, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *publicKey, size_t publicKeySize) {

	// Check if secret key is invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if getting the shared secret key failed
	if(!secp256k1_ecdh(instanceData->context, sharedSecretKey, &publicKeyData, secretKey)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Commit size
size_t commitSize(InstanceData *instanceData) {

	// Return commit size
	return COMMIT_SIZE;
}

// Pedersen commit
bool pedersenCommit(InstanceData *instanceData, uint8_t *result, const uint8_t *blind, size_t blindSize, const char *value) {

	// Check if blind is invalid
	if(blindSize != BLIND_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing value as a number failed
	char *lastCharacter;
	errno = 0;
	uint64_t numericValue = strtoull(value, &lastCharacter, DECIMAL_NUMBER_BASE);
	if(lastCharacter == value || *lastCharacter != '\0' || value[0] == '-' || value[0] == '+' || (numericValue == ULLONG_MAX && errno == ERANGE)) {
	
		// Return false
		return false;
	}
	
	// Check if performing Pedersen commit failed
	secp256k1_pedersen_commitment commit;
	if(!secp256k1_pedersen_commit(instanceData->context, &commit, blind, numericValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		
		// Return false
		return false;
	}
	
	// Check if serializing commit failed
	if(!secp256k1_pedersen_commitment_serialize(instanceData->context, result, &commit)) {
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Pedersen commit sum
bool pedersenCommitSum(InstanceData *instanceData, uint8_t *result, const uint8_t *positiveCommits, size_t positiveCommitsSizes[], size_t numberOfPositiveCommits, const uint8_t *negativeCommits, size_t negativeCommitsSizes[], size_t numberOfNegativeCommits) {
	
	// Go through all positive commits
	vector<secp256k1_pedersen_commitment> positiveCommitsData(numberOfPositiveCommits);
	vector<const secp256k1_pedersen_commitment *> positiveCommitsAddresses(numberOfPositiveCommits);
	size_t positiveCommitsOffset = 0;
	
	for(size_t i = 0; i < numberOfPositiveCommits; ++i) {
	
		// Check if positive commit is invalid
		if(positiveCommitsSizes[i] != COMMIT_SIZE) {
		
			// Return false
			return false;
		}

		// Check if parsing positive commit failed
		if(!secp256k1_pedersen_commitment_parse(instanceData->context, &positiveCommitsData[i], &positiveCommits[positiveCommitsOffset])) {
		
			// Return false
			return false;
		}
		
		// Update offset
		positiveCommitsOffset += positiveCommitsSizes[i];
		
		// Store positive commit's address
		positiveCommitsAddresses[i] = &positiveCommitsData[i];
	}
	
	// Go through all negative commits
	vector<secp256k1_pedersen_commitment> negativeCommitsData(numberOfNegativeCommits);
	vector<const secp256k1_pedersen_commitment *> negativeCommitsAddresses(numberOfNegativeCommits);
	size_t negativeCommitsOffset = 0;
	
	for(size_t i = 0; i < numberOfNegativeCommits; ++i) {
	
		// Check if negative commit is invalid
		if(negativeCommitsSizes[i] != COMMIT_SIZE) {
		
			// Return false
			return false;
		}

		// Check if parsing negative commit failed
		if(!secp256k1_pedersen_commitment_parse(instanceData->context, &negativeCommitsData[i], &negativeCommits[negativeCommitsOffset])) {
		
			// Return false
			return false;
		}
		
		// Update offset
		negativeCommitsOffset += negativeCommitsSizes[i];
		
		// Store negative commit's address
		negativeCommitsAddresses[i] = &negativeCommitsData[i];
	}
	
	// Check if performing Pedersen commit sum failed
	secp256k1_pedersen_commitment commit;
	if(!secp256k1_pedersen_commit_sum(instanceData->context, &commit, positiveCommitsAddresses.data(), numberOfPositiveCommits, negativeCommitsAddresses.data(), numberOfNegativeCommits)) {
		
		// Return false
		return false;
	}
	
	// Check if serializing commit failed
	if(!secp256k1_pedersen_commitment_serialize(instanceData->context, result, &commit)) {
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Pedersen commit to public key
bool pedersenCommitToPublicKey(InstanceData *instanceData, uint8_t *publicKey, const uint8_t *commit, size_t commitSize) {

	// Check if commit is invalid
	if(commitSize != COMMIT_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing commit failed
	secp256k1_pedersen_commitment commitData;
	if(!secp256k1_pedersen_commitment_parse(instanceData->context, &commitData, commit)) {
	
		// Return false
		return false;
	}
	
	// Check if performing Pedersen commit to public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_pedersen_commitment_to_pubkey(instanceData->context, &publicKeyData, &commitData)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t publicKeySize = PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, publicKey, &publicKeySize, &publicKeyData, SECP256K1_EC_COMPRESSED)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Public key to Pedersen commit
bool publicKeyToPedersenCommit(InstanceData *instanceData, uint8_t *commit, const uint8_t *publicKey, size_t publicKeySize) {

	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if performing public key to Pedersen commit failed
	secp256k1_pedersen_commitment commitData;
	if(!secp256k1_pubkey_to_pedersen_commitment(instanceData->context, &commitData, &publicKeyData)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing commit failed
	if(!secp256k1_pedersen_commitment_serialize(instanceData->context, commit, &commitData)) {
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Single-signer signature size
size_t singleSignerSignatureSize(InstanceData *instanceData) {

	// Return single-signer signature size
	return SINGLE_SIGNER_SIGNATURE_SIZE;
}

// Seed size
size_t seedSize(InstanceData *instanceData) {

	// Return seed size
	return SEED_SIZE;
}

// Create single-signer signature
bool createSingleSignerSignature(InstanceData *instanceData, uint8_t *signature, const uint8_t *message, size_t messageSize, const uint8_t *secretKey, size_t secretKeySize, const uint8_t *secretNonce, size_t secretNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize, const uint8_t *seed, size_t seedSize) {

	// Check if message is invalid
	if(messageSize != SINGLE_SIGNER_MESSAGE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if secret key is invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if secret nonce is invalid
	if(secretNonce && secretNonceSize != NONCE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if seed is invalid
	if(seedSize != SEED_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if a public nonce is provided
	secp256k1_pubkey publicNonceData;
	if(publicNonce) {
	
		// Check if parsing public nonce failed
		if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicNonceData, publicNonce, publicNonceSize)) {
		
			// Return false
			return false;
		}
		
		// Check if public nonce starts with a zero array
		if(isZeroArray(instanceData, &publicNonceData, 256 / BITS_IN_A_BYTE)) {
		
			// Return false
			return false;
		}
	}
	
	// Check if a public nonce total is provided
	secp256k1_pubkey publicNonceTotalData;
	if(publicNonceTotal) {
	
		// Check if parsing public nonce total failed
		if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicNonceTotalData, publicNonceTotal, publicNonceTotalSize)) {
		
			// Return false
			return false;
		}
		
		// Check if public nonce total starts with a zero array
		if(isZeroArray(instanceData, &publicNonceTotalData, 256 / BITS_IN_A_BYTE)) {
		
			// Return false
			return false;
		}
	}
	
	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if public key starts with a zero array
	if(isZeroArray(instanceData, &publicKeyData, 256 / BITS_IN_A_BYTE)) {
	
		// Return false
		return false;
	}
	
	// Check if creating single-signer signature failed
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_aggsig_sign_single(instanceData->context, reinterpret_cast<uint8_t *>(&signatureData), message, secretKey, secretNonce, nullptr, publicNonce ? &publicNonceData : nullptr, publicNonceTotal ? &publicNonceTotalData : nullptr, &publicKeyData, seed)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing signature failed
	if(!secp256k1_ecdsa_signature_serialize_compact(instanceData->context, signature, &signatureData)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Add single-signer signatures
bool addSingleSignerSignatures(InstanceData *instanceData, uint8_t *result, const uint8_t *signatures, size_t signaturesSizes[], size_t numberOfSignatures, const uint8_t *publicNonceTotal, size_t publicNonceTotalSize) {

	// Go through all signatures
	vector<secp256k1_ecdsa_signature> signaturesData(numberOfSignatures);
	vector<const uint8_t *> signaturesAddresses(numberOfSignatures);
	size_t signaturesOffset = 0;
	
	for(size_t i = 0; i < numberOfSignatures; ++i) {
	
		// Check if signature is invalid
		if(signaturesSizes[i] != SINGLE_SIGNER_SIGNATURE_SIZE) {
		
			// Return false
			return false;
		}
		
		// Check if parsing signature failed
		if(!secp256k1_ecdsa_signature_parse_compact(instanceData->context, &signaturesData[i], &signatures[signaturesOffset])) {
		
			// Return false
			return false;
		}
		
		// Update offset
		signaturesOffset += signaturesSizes[i];
		
		// Store signatures's address
		signaturesAddresses[i] = reinterpret_cast<uint8_t *>(&signaturesData[i]);
	}
	
	// Check if parsing public nonce total failed
	secp256k1_pubkey publicNonceTotalData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicNonceTotalData, publicNonceTotal, publicNonceTotalSize)) {
	
		// Return false
		return false;
	}
	
	// Check if adding single-signer signatures failed
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_aggsig_add_signatures_single(instanceData->context, reinterpret_cast<uint8_t *>(&signatureData), signaturesAddresses.data(), numberOfSignatures, &publicNonceTotalData)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing signature failed
	if(!secp256k1_ecdsa_signature_serialize_compact(instanceData->context, result, &signatureData)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Verify single-signer signatures
bool verifySingleSignerSignature(InstanceData *instanceData, const uint8_t *signature, size_t signatureSize, const uint8_t *message, size_t messageSize, const uint8_t *publicNonce, size_t publicNonceSize, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *publicKeyTotal, size_t publicKeyTotalSize, bool isPartial) {

	// Check if signature is invalid
	if(signatureSize != SINGLE_SIGNER_SIGNATURE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing signature failed
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_ecdsa_signature_parse_compact(instanceData->context, &signatureData, signature)) {
	
		// Return false
		return false;
	}
	
	// Check if signature starts with a zero array
	if(isZeroArray(instanceData, &signatureData, 256 / BITS_IN_A_BYTE)) {
	
		// Return false
		return false;
	}
	
	// Check if message is invalid
	if(messageSize != SINGLE_SIGNER_MESSAGE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if a public nonce is provided
	secp256k1_pubkey publicNonceData;
	if(publicNonce) {
	
		// Check if parsing public nonce failed
		if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicNonceData, publicNonce, publicNonceSize)) {
		
			// Return false
			return false;
		}
		
		// Check if public nonce starts with a zero array
		if(isZeroArray(instanceData, &publicNonceData, 256 / BITS_IN_A_BYTE)) {
		
			// Return false
			return false;
		}
	}
	
	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if public key starts with a zero array
	if(isZeroArray(instanceData, &publicKeyData, 256 / BITS_IN_A_BYTE)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing public key total failed
	secp256k1_pubkey publicKeyTotalData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyTotalData, publicKeyTotal, publicKeyTotalSize)) {
	
		// Return false
		return false;
	}
	
	// Check if public key total starts with a zero array
	if(isZeroArray(instanceData, &publicKeyTotalData, 256 / BITS_IN_A_BYTE)) {
	
		// Return false
		return false;
	}

	// Check if verifying single-signer signature failed
	if(!secp256k1_aggsig_verify_single(instanceData->context, reinterpret_cast<uint8_t *>(&signatureData), message, publicNonce ? &publicNonceData : nullptr, &publicKeyData, &publicKeyTotalData, nullptr, isPartial)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Single-signer signature from data
bool singleSignerSignatureFromData(InstanceData *instanceData, uint8_t *signature, const uint8_t *data, size_t dataSize) {

	// Check if data size is invalid
	if(dataSize != SINGLE_SIGNER_SIGNATURE_SIZE) {
	
		// Return false
		return false;
	}

	// Check if creating signature from data failed
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_ecdsa_signature_parse_compact(instanceData->context, &signatureData, data)) {
	
		// Return false
		return false;
	}

	// Check if serializing signature failed
	if(!secp256k1_ecdsa_signature_serialize_compact(instanceData->context, signature, &signatureData)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Uncompact single-signer signature size
size_t uncompactSingleSignerSignatureSize(InstanceData *instanceData) {

	// Return uncompact single-signer signature size
	return sizeof(secp256k1_ecdsa_signature);
}

// Compact single-signer signature
bool compactSingleSignerSignature(InstanceData *instanceData, uint8_t *result, const uint8_t *signature, size_t signatureSize) {

	// Check if signature size is invalid
	if(signatureSize != sizeof(secp256k1_ecdsa_signature)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing signature failed
	if(!secp256k1_ecdsa_signature_serialize_compact(instanceData->context, result, reinterpret_cast<const secp256k1_ecdsa_signature *>(signature))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Uncompact single-signer signature
bool uncompactSingleSignerSignature(InstanceData *instanceData, uint8_t *result, const uint8_t *signature, size_t signatureSize) {

	// Check if signature size is invalid
	if(signatureSize != SINGLE_SIGNER_SIGNATURE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if unserializing signature failed
	if(!secp256k1_ecdsa_signature_parse_compact(instanceData->context, reinterpret_cast<secp256k1_ecdsa_signature *>(result), signature)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Combine public keys
bool combinePublicKeys(InstanceData *instanceData, uint8_t *result, const uint8_t *publicKeys, size_t publicKeysSizes[], size_t numberOfPublicKeys) {

	// Go through all publc keys
	vector<secp256k1_pubkey> publicKeysData(numberOfPublicKeys);
	vector<const secp256k1_pubkey *> publicKeysAddresses(numberOfPublicKeys);
	size_t publicKeysOffset = 0;
	
	for(size_t i = 0; i < numberOfPublicKeys; ++i) {
	
		// Check if parsing public key failed
		if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeysData[i], &publicKeys[publicKeysOffset], publicKeysSizes[i])) {
		
			// Return false
			return false;
		}
		
		// Update offset
		publicKeysOffset += publicKeysSizes[i];
		
		// Store public key's address
		publicKeysAddresses[i] = &publicKeysData[i];
	}

	// Check if combining public keys failed
	secp256k1_pubkey combinedPublicKeysData;
	if(!secp256k1_ec_pubkey_combine(instanceData->context, &combinedPublicKeysData, publicKeysAddresses.data(), numberOfPublicKeys)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing combined public key failed
	size_t combinedPublicKeySize = PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(instanceData->context, result, &combinedPublicKeySize, &combinedPublicKeysData, SECP256K1_EC_COMPRESSED)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Nonce size
size_t nonceSize(InstanceData *instanceData) {

	// Return nonce size
	return NONCE_SIZE;
}

// Create secret nonce
bool createSecretNonce(InstanceData *instanceData, uint8_t *nonce, const uint8_t *seed, size_t seedSize) {

	// Check if seed is invalid
	if(seedSize != SEED_SIZE) {
	
		// Return false
		return false;
	}

	// Check if creating a secret nonce failed
	if(!secp256k1_aggsig_export_secnonce_single(instanceData->context, nonce, seed)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Maximum message hash signature size
size_t maximumMessageHashSignatureSize(InstanceData *instanceData) {

	// Return maximum message hash signature size
	return MAXIMUM_MESSAGE_HASH_SIGNATURE_SIZE;
}

// Create message hash signature
bool createMessageHashSignature(InstanceData *instanceData, uint8_t *signature, char *signatureSize, const uint8_t *messageHash, size_t messageHashSize, const uint8_t *secretKey, size_t secretKeySize) {

	// Check if message hash is invalid
	if(messageHashSize != MESSAGE_HASH_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if secret key is invalid
	if(!isValidSecretKey(instanceData, secretKey, secretKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if signing the message hash failed
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_ecdsa_sign(instanceData->context, &signatureData, messageHash, secretKey, secp256k1_nonce_function_rfc6979, nullptr)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing signature failed
	size_t numericSignatureSize = MAXIMUM_MESSAGE_HASH_SIGNATURE_SIZE;
	if(!secp256k1_ecdsa_signature_serialize_der(instanceData->context, signature, &numericSignatureSize, &signatureData)) {
	
		// Return false
		return false;
	}
	
	// Copy numeric signature size to signature size
	string stringSignatureSize = to_string(numericSignatureSize);
	memcpy(signatureSize, stringSignatureSize.c_str(), stringSignatureSize.length() + sizeof('\0'));
	
	// Return true
	return true;
}

// Verify message hash signature
bool verifyMessageHashSignature(InstanceData *instanceData, const uint8_t *signature, size_t signatureSize, const uint8_t *messageHash, size_t messageHashSize, const uint8_t *publicKey, size_t publicKeySize) {

	// Check if signature is invalid
	if(signatureSize > MAXIMUM_MESSAGE_HASH_SIGNATURE_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing signature failed
	secp256k1_ecdsa_signature signatureData;
	if(!secp256k1_ecdsa_signature_parse_der(instanceData->context, &signatureData, signature, signatureSize)) {
	
		// Return false
		return false;
	}
	
	// Check if message hash is invalid
	if(messageHashSize != MESSAGE_HASH_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if parsing public key failed
	secp256k1_pubkey publicKeyData;
	if(!secp256k1_ec_pubkey_parse(instanceData->context, &publicKeyData, publicKey, publicKeySize)) {
	
		// Return false
		return false;
	}
	
	// Check if verifying signature failed
	if(!secp256k1_ecdsa_verify(instanceData->context, &signatureData, messageHash, &publicKeyData)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is zero array
bool isZeroArray(InstanceData *instanceData, void *value, size_t size) {

	// Create zeros buffer
	vector<uint8_t> zerosBuffer(size);
	explicit_bzero(zerosBuffer.data(), size);
	
	// Return if value is equal to the zero buffer
	return !memcmp(value, zerosBuffer.data(), size);
}

// Use strict
"use strict";

// Try
try {

	// Export secp256k1-zkp React Native module
	module["exports"] = require("@nicolasflamel/secp256k1-zkp-react");
}

// Catch errors
catch(error) {

	// Try
	try {
	
		// Export secp256k1-zkp Node.js addon
		module["exports"] = require("@nicolasflamel/secp256k1-zkp-native");
	}
	
	// Catch errors
	catch(error) {
	
		// Export secp256k1-zkp WASM wrapper
		module["exports"] = require("@nicolasflamel/secp256k1-zkp-wasm");
	}
}

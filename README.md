# Secp256k1-zkp NPM Package

### Description
NPM package for parts of [libsecp256k1-zkp](https://github.com/NicolasFlamel1/secp256k1-zkp).

This package will attempt to use the following modules in the order they are listed. This results in the fastest secp256k1-zkp implementation being used on every platform.
* [Secp256k1-zkp React Native Module](https://github.com/NicolasFlamel1/Secp256k1-zkp-React-Native-Module)
* [Secp256k1-zkp Node.js Addon](https://github.com/NicolasFlamel1/Secp256k1-zkp-Node.js-Addon)
* [Secp256k1-zkp WASM Wrapper](https://github.com/NicolasFlamel1/Secp256k1-zkp-WASM-Wrapper)

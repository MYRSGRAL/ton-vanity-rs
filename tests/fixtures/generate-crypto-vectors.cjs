// Воспроизведение публичных фикстур через независимые SDK без GPU/сети.
// node generate-crypto-vectors.cjs /путь/к/TON-Vanity-W5-Windows/node_modules
const root = require('node:path').resolve(process.argv[2]);
const bip39 = require(root + '/bip39');
const {derivePath} = require(root + '/ed25519-hd-key');
const {WalletContractV5R1} = require(root + '/@ton/ton');
const {keyPairFromSeed} = require(root + '/@ton/crypto');
const vectors = [0, 255].map(byte => {
    const entropy = Buffer.alloc(32, byte);
    const mnemonic = bip39.entropyToMnemonic(entropy);
    const seed = bip39.mnemonicToSeedSync(mnemonic, '');
    const privateKey = Buffer.from(derivePath("m/44'/607'/0'", seed.toString('hex')).key);
    const publicKey = keyPairFromSeed(privateKey).publicKey;
    const wallet = WalletContractV5R1.create({publicKey, workchain: 0});
    return {
        entropy: entropy.toString('hex'), mnemonic, seed: seed.toString('hex'),
        private_key: privateKey.toString('hex'), public_key: publicKey.toString('hex'),
        address: wallet.address.toString({bounceable: false, urlSafe: true, testOnly: false}),
    };
});
process.stdout.write(JSON.stringify(vectors, null, 2) + '\n');

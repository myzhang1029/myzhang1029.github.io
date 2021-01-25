/* OpenPGP Encrypt abstract functions */
'use strict';

const default_data = {
	nopeerkey: "Please fill the key!",
	noselfkey: "Please generate keys first!",
	askpass: "Your passphrase (leave out for none):",
	not_generated: "Not generated!",
	waitplz: "Please wait..."
};
var data;
if (!data) {
	data = default_data;
}
var storage = window.localStorage;

/* Things to be run on page load */
function loadHandler() {
	let peerkey = storage.getItem("peerkey");
	if (peerkey) {
		document.getElementById("pubkey").value = peerkey;
	}
	document.getElementById("result").value = "";
}
document.addEventListener('DOMContentLoaded', loadHandler, false);

/* Display error and rethrow */
function errorHandler(error) {
	document.getElementById("result").value = error;
	throw error;
}

/* Get peer key */
async function ensureAndGetPeerKey() {
	let peerkey = document.getElementById("pubkey").value;
	if (!peerkey) {
		document.getElementById("result").value = data.nopeerkey;
		throw "Missing peer public key!";
	}
	storage.setItem("peerkey", peerkey);
	return await openpgp.key.readArmored(peerkey);
}

/* Show Generate tab */
async function showGenTab() {
	document.getElementById("gendetails").style.display = "block";
}

/* Generate a new key pair */
async function generate() {
	let options = {
		userIds: [{
			name: document.getElementById("name").value,
			email: document.getElementById("email").value
		}],
		curve: 'ed25519',
		passphrase: document.getElementById("pp").value
	};
	document.getElementById("gendetails").style.display = "none";
	openpgp.generateKey(options).then(function (key) {
		let privkey = key.privateKeyArmored;
		let pubkey = key.publicKeyArmored;
		let revocationSignature = key.revocationSignature;
		storage = window.localStorage;
		storage.setItem("myprivkey", privkey);
		storage.setItem("mypubkey", pubkey);
		storage.setItem("revocation", revocationSignature);
		showPubKey();
	}).catch(errorHandler);
}

/* Encrypt message */
async function encrypt() {
	let message = document.getElementById("ta").value;
	let options = {
		message: openpgp.message.fromText(message),
		publicKeys: (await ensureAndGetPeerKey()).keys
	};
	openpgp.encrypt(options).then(ciphertext => {
		document.getElementById("result").value = ciphertext.data;
	}).catch(errorHandler);
}

/* Decrypt message */
async function decrypt() {
	let privkey = storage.getItem("myprivkey");
	let armored_message = document.getElementById("ta").value;
	if (!privkey) {
		document.getElementById("result").value = data.noselfkey;
		throw "Key pair not generated!";
	}
	let passphrase = window.prompt(data.askpass);
	const privKeyObj = (await openpgp.key.readArmored(privkey)).keys[0];
	if (passphrase) {
		await privKeyObj.decrypt(passphrase);
	}
	openpgp.message.readArmored(armored_message).then(message => {
		let options = {
			message: message,
			privateKeys: [privKeyObj]
		};
		openpgp.decrypt(options).then(plaintext => {
			document.getElementById("result").value = plaintext.data;
		}).catch(errorHandler);
	}).catch(errorHandler);
}

/* Show my own pub key */
async function showPubKey() {
	let mypub = storage.getItem("mypubkey");
	if (mypub) {
		document.getElementById("result").value = mypub;
	} else {
		document.getElementById("result").value = data.not_generated;
		throw "Key pair not generated!";
	}
}

/* Show peer user IDs */
async function showPeerInfo() {
	let result = "";
	let peerkey = await ensureAndGetPeerKey();
	peerkey.keys.forEach(key => {
		key.users.forEach(user => {
			result += user.userId.userid + "\n"
		})
	})
	document.getElementById("result").value = result;
}

/* Clear result and input */
async function clearResult() {
	document.getElementById("result").value = "";
	document.getElementById("ta").value = "";
}

/* Clear all keys and messages */
async function forgetEverything() {
	window.localStorage.clear();
	clearResult();
	document.getElementById("pubkey").value = "";
}

/* Show a waiting message */
async function wrap(f) {
	document.getElementById("result").value = data.waitplz;
	await eval(f + "()");
}

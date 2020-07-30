/* OpenPGP Encrypt abstract functions */
const default_data = {
    nopeerkey: "Please fill the key!",
    noselfkey: "Please generate keys first!",
    askpass: "Your passphrase (leave out for none):",
    not_generated: "Not generated!",
    waitplz: "Please wait..."
};
var data;
if (!data)
{
    data = default_data;
}

/* Things to be run on page load */
function loadHandler() {
  storage = window.localStorage;
  peerkey = storage.getItem("peerkey");
  if (peerkey) {
    document.getElementById("pubkey").value = peerkey;
  }
  document.getElementById("result").value = "";
}
document.addEventListener('DOMContentLoaded', loadHandler, false);

/* Get peer key */
async function ensureAndGetPeerKey() {
  storage = window.localStorage;
  peerkey = document.getElementById("pubkey").value;
  if (!peerkey) {
    document.getElementById("result").value = data.nopeerkey;
    return;
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
  var options = {
    userIds: [{
      name: document.getElementById("name").value,
      email:document.getElementById("email").value
    }],
    numBits: 4096,
    passphrase: document.getElementById("pp").value
  };
  document.getElementById("gendetails").style.display = "none";
  openpgp.generateKey(options).then(function(key) {
    var privkey = key.privateKeyArmored;
    var pubkey = key.publicKeyArmored;
    var revocationSignature = key.revocationSignature;
    storage = window.localStorage;
    storage.setItem("myprivkey", privkey);
    storage.setItem("mypubkey", pubkey);
    storage.setItem("revocation", revocationSignature);
    showPubKey();
  }).catch(error => {
    document.getElementById("result").value = error;
  });
}

/* Encrypt message */
async function encrypt() {
  storage = window.localStorage;
  message = document.getElementById("ta").value;
  var options = {
    message: openpgp.message.fromText(message),
    publicKeys: (await ensureAndGetPeerKey()).keys
  };
  openpgp.encrypt(options).then(ciphertext => {
    document.getElementById("result").value = ciphertext.data;
  }).catch(error => {
    document.getElementById("result").value = error;
  });
}

/* Decrypt message */
async function decrypt() {
  storage = window.localStorage;
  privkey = storage.getItem("myprivkey");
  message = document.getElementById("ta").value;
  if (!privkey || !pubkey) {
    document.getElementById("result").value = data.noselfkey;
    return;
  }
  passphrase = window.prompt(data.askpass);
  const privKeyObj = (await openpgp.key.readArmored(privkey)).keys[0];
  if (passphrase) {
    await privKeyObj.decrypt(passphrase);
  }
  var options = {
    message: await openpgp.message.readArmored(message),
    privateKeys: [privKeyObj]
  };
  openpgp.decrypt(options).then(plaintext => {
    document.getElementById("result").value = plaintext.data;
  }).catch(error => {
    document.getElementById("result").value = error;
  });
}

/* Show my own pub key */
async function showPubKey() {
  storage = window.localStorage;
  mypub = storage.getItem("mypubkey");
  if (mypub) {
    document.getElementById("result").value = mypub;
  } else {
    document.getElementById("result").value = data.not_generated;
  }
}

/* Show peer user IDs */
async function showPeerInfo() {
  result = "";
  peerkey = await ensureAndGetPeerKey();
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
  await eval(f+"()");
}
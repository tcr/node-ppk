var ber = require('asn1').Ber;
var sshpk = require('sshpk');
var fs = require('fs');
var RSA = require('node-rsa');
var execSync = require('child_process').execSync;

function linebrk (str, maxLen) {
    var res = '';
    var i = 0;
    while (i + maxLen < str.length) {
        res += str.substring(i, i + maxLen) + "\n";
        i += maxLen;
    }
    return res + str.substring(i, str.length);
};

console.log('hi');

var fileOptions = {
  encoding: 'utf8',
  mode: 0o600,
};

// Generate SSH key
var key = new RSA({
  b: 1024
});
var privateKey = key.exportKey('private');
var publicKey = sshpk.parseKey(key.exportKey('public'), 'pem').toString('ssh') + '\n';

var c = key.exportKey('components');
var private_exponent = c.d;
var p = c.p;
var q = c.q;
var iqmp = c.coeff;

var i = 0;

function prepend(b, n) {
  let w = new Buffer(4);
  w.writeUInt32BE(n.length, 0);
  return Buffer.concat([b, w, n]);
}

var b = new Buffer(0);
b = prepend(b, private_exponent);
b = prepend(b, p);
b = prepend(b, q);
b = prepend(b, iqmp);
var privblob = b;
var privkey = privblob.toString('base64');

console.log(linebrk(privkey, 64))


    /* Now create the MAC. */
//     {
// 	unsigned char *macdata;
// 	int maclen;
// 	unsigned char *p;
// 	int namelen = strlen(key->alg->name);
// 	int enclen = strlen(cipherstr);
// 	int commlen = strlen(key->comment);
// 	SHA_State s;
// 	unsigned char mackey[20];
var header = "putty-private-key-file-mac-key";
// 	maclen = (4 + namelen +
// 		  4 + enclen +
// 		  4 + commlen +
// 		  4 + pub_blob_len +
// 		  4 + priv_encrypted_len);
// 	macdata = snewn(maclen, unsigned char);
// 	p = macdata;
// #define DO_STR(s,len) PUT_32BIT(p,(len));memcpy(p+4,(s),(len));p+=4+(len)

var b = new Buffer(0);
b = prepend(b, new Buffer("rsa2"));
b = prepend(b, new Buffer("none"));
b = prepend(b, new Buffer("imported-openssh-key"));
// console.log(sshpk.parseKey(key.exportKey('public'), 'pem'));
b = prepend(b, key.exportKey('pkcs1-public-der'));
b = prepend(b, privblob);

var crypto = require('crypto');

var sha1 = crypto.createHash('sha1');
sha1.update(b);

var mac = crypto.createHmac('sha1', sha1.digest('hex')).update(b).digest('hex');
console.log('Private-MAC:', mac);

// 	DO_STR(key->alg->name, namelen);
// 	DO_STR(cipherstr, enclen);
// 	DO_STR(key->comment, commlen);
// 	DO_STR(pub_blob, pub_blob_len);
// 	DO_STR(priv_blob_encrypted, priv_encrypted_len);
//
// 	SHA_Init(&s);
// 	SHA_Bytes(&s, header, sizeof(header)-1);
// 	if (passphrase)
// 	    SHA_Bytes(&s, passphrase, strlen(passphrase));
// 	SHA_Final(&s, mackey);
// 	hmac_sha1_simple(mackey, 20, macdata, maclen, priv_mac);
// 	smemclr(macdata, maclen);
// 	sfree(macdata);
// 	smemclr(mackey, sizeof(mackey));
// 	smemclr(&s, sizeof(s));
//     }


var keyFile = 'putty';
fs.writeFileSync(keyFile + '.pub', publicKey, fileOptions);
fs.writeFileSync(keyFile, privateKey, fileOptions);

execSync('puttygen putty -o putty.ppk');

console.log('');
console.log(fs.readFileSync('putty.ppk', 'utf-8'))

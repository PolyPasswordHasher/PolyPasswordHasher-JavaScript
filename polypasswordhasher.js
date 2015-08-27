/* A basic library that demonstrates PolyHash when applied to passwords (see 
https://polypasswordhasher.poly.edu/ for details). This includes shielded 
password support via AES 256. */

var fs = require('fs');
var sss = require('secrets.js');
var crypto = require('crypto');

/**
* Represents a PPH object
* @param threshold
* @param passwordfile
* @param isolatedcheckbits
*/
var PPH = function (threshold, passwordfile, isolatedcheckbits) {
	//initializes instance variables or sets them to undefined
	this.threshold = threshold; 
	this.passwordfile = passwordfile;

	//number of bytes of data used for isolated validation
	this.isolatedcheckbits = isolatedcheckbits || 0;

	this.knownsecret = false;
	//shielded support: this could be random (and unknown) in the default
	// algorithm
	this.shieldedkey = undefined;

	this.shamirsecretshares = [];

	this.saltsize = 16;

	this.ICBiterations = 1000;
	this.recombinationiterations = 100000;

	//secret verification routines
	this.secretlength = 31; //because SSS library pads shares by 1 byte
	this.secretintegritycheck = undefined;

	//number of used shares
	this.nextavailableshare = 0;

	this.accountdict = {};
	this.bootstrapaccounts = [];

	if (typeof passwordfile === 'undefined') {
		this.shieldedkey = this.create_secret();

		//MUST generate at least the threshold number of shares
		this.shamirsecretshares = sss.share(this.shieldedkey, this.threshold,
				this.threshold);

		this.knownsecret = true;
		this.nextavailableshare = 1;

		return;
	}

	var passwordfiledata = fs.readFileSync(passwordfile);
	passwordfiledata = JSON.parse(passwordfiledata);

	//deserializing
	this.accountdict = passwordfiledata.accountdict;
	this.secretintegritycheck = passwordfiledata.secretintegritycheck;

	if (typeof this.accountdict !== "object" || 
			typeof this.secretintegritycheck !== "string")
		throw new Error("Password file did not load correctly;" +
				" could not deserialize data.");

	//goes through the accountdict and sets nextavailableshare to the largest
	//  share in the accountdict
	for (var user=0; user<this.accountdict.length; user++)
		for (var share=0; share<this.accountdict[user].length; share++)
			this.nextavailableshare = Math.max(
					this.accountdict[user][share]["sharenumber"],
					nextavailableshare);

	//..then generates a new share for use
	this.nextavailableshare++;
}


/**
* Creates a new account. Throws an exception if given bad data or if the 
* system isn't initialized
* @param username 
* @param password
* @param shares
*/
PPH.prototype.create_account = function (username, password, shares) {

	if (username in this.accountdict)
		throw new Error(username + " is already a username");

	if (shares < 0 || shares > 255 || (shares + this.nextavailableshare) > 255)
		throw new Error("Invalid number of shares: " + shares + "\n" + shares +
				"+" + this.nextavailableshare + "must be less than 255");

	//each user gets their own list in the accountdict
	this.accountdict[username] = [];

	//if bootstrapping, then a bootstrap account will be created
	if (!this.knownsecret) {
		if (shares !== 0) {
			delete this.accountdict[username];
			throw new Error("Cannot produce shares; still bootstrapping!");
		} else {
			var thisentry = {};
			thisentry.sharenumber = -1;
			//multiply by 8 bc sss.random() takes bits
			thisentry.salt = sss.random(this.saltsize * 8);
			//the salt and password are hashed together
			thisentry.saltedpasshash = _SHA256(thisentry["salt"] + password);
			this.accountdict[username].push(thisentry);

			//use this to update accounts after bootstrapping finishes
			this.bootstrapaccounts.push(thisentry);
		}
	} else if (shares === 0) {
		var thisentry = {};
		thisentry.sharenumber = 0;
		//multiply by 8 bc sss.random() takes bits
		thisentry.salt = sss.random(this.saltsize * 8);
		var tempsaltedpasshash = _SHA256(thisentry["salt"] + password);
		thisentry.saltedpasshash = _AESencrypt(this.shieldedkey,
				tempsaltedpasshash);
		thisentry.saltedpasshash += this.create_isolated_validation_bits(
				tempsaltedpasshash);

		this.accountdict[username].push(thisentry);
		return;
	}

	for (var sharenumber=this.nextavailableshare; 
			sharenumber<this.nextavailableshare+shares; sharenumber++) {
		thisentry = {};
		thisentry.sharenumber = sharenumber;

		var shamirsecretshare = sss.newShare(sharenumber,
				this.shamirsecretshares).substring(3);
		thisentry.salt = sss.random(this.saltsize*8);
		var tempsaltedpasshash = _SHA256(thisentry["salt"] + password);

		thisentry.saltedpasshash = _xor(tempsaltedpasshash, shamirsecretshare);
		thisentry.saltedpasshash += this.create_isolated_validation_bits(
				tempsaltedpasshash);

		this.accountdict[username].push(thisentry);
	}

	this.nextavailableshare += shares;
}

/**
* Checks if a login combination is valid.
* @param username the login username
* @param password the login password
*/
PPH.prototype.is_valid_login = function (username, password) {

	if (!this.knownsecret && this.isolatedcheckbits === 0)
		throw new Error("Still bootstrapping-isolated validation is disabled");

	if (!(username in this.accountdict))
		throw new Error("Unknown user: " + username);
	
	var saltedpasshash, tempsaltedpasshash, tempsharenumber_dec;
	for (var entry=0; entry<this.accountdict[username].length; entry++) {
		tempsaltedpasshash = _SHA256(this.accountdict[username][entry]["salt"]+
				password);
		saltedpasshash = this.accountdict[username][entry]["saltedpasshash"];
		tempsharenumber_dec = this.accountdict[username][entry]["sharenumber"];

		//if this is a bootstrap account:
		if (tempsharenumber_dec === -1)
			return (saltedpasshash === tempsaltedpasshash);

		//if bootstrapping, isolated validation needs to be done
		if (!this.knownsecret) {
			if (this.isolated_validation(tempsaltedpasshash, saltedpasshash))
				return true;
			else
				return false;
		}

		//XOR to remove hash from the hashXORshare (i.e. to get share)
		var tempsharedata = _xor(tempsaltedpasshash, saltedpasshash.substring(0,
				saltedpasshash.length - this.isolatedcheckbits));

		var isolatedcheck;
		if (this.isolatedcheckbits > 0)
			isolatedcheck = this.isolated_validation(tempsaltedpasshash,
					saltedpasshash);
		else
			isolatedcheck = false;

		//If it's a shielded account..
		if (tempsharenumber_dec === 0) {
			var tempAES = _AESencrypt(this.shieldedkey, tempsaltedpasshash);
			var tempSPH = saltedpasshash.substring(0, saltedpasshash.length -
					this.isolatedcheckbits);
			if (tempAES === tempSPH)
				return true;
			
			if (isolatedcheck)
				console.log("Possible break-in:" +
						" Isolated check matches but full hash doesn't");
			return false;
		}

		var tempshare = [tempsharenumber_dec, tempsharedata];
		if (_validate(this.shamirsecretshares, tempshare))  return true;

		if (isolatedcheck)
			console.log("Possible break-in:" +
					" Isolated check matches but full hash doesn't");
		return false;
	}
}

/**
* Saves the password file to disk
* @param passwordfile
*/
PPH.prototype.write_password_data = function (passwordfile) {

	if (this.threshold >= this.nextavailableshare)
		throw new Error("Would write undecodable password file." +
				" Must have more shares before writing.");

	//Backing up important info, setting it to undefined, and writing the rest
	var knownsecretbackup = this.knownsecret;
	var shieldedkeybackup = this.shieldedkey;
	var shamirsecretsharesbackup = JSON.parse(
			JSON.stringify(this.shamirsecretshares));

	this.shieldedkey = undefined;
	this.shamirsecretshares = undefined;

	fs.writeFileSync(passwordfile, JSON.stringify(this));

	this.knownsecret = knownsecretbackup;
	this.shieldedkey = shieldedkeybackup;
	this.shamirsecretshares = shamirsecretsharesbackup;
}

/**
* Attempts to access password file through list of login combinations
* @param logindata a list of username + password combinations such as
* [["ecr","issleepdeprived"],["bernie","willneverwin"],["konami","upup"]]
*/
PPH.prototype.unlock_password_data = function (logindata) {

	if (this.knownsecret)
		throw new Error("PPH is already in normal operation!");

	//finds the shares and sees if the secret can be recovered
	var sharelist = [];
	for (var login=0; login<logindata.length; login++) {
		var username = logindata[login][0];
		var password = logindata[login][1];
		if (!(username in this.accountdict))
			throw new Error("Unknown user: " + username);

		for (var entry=0; entry<this.accountdict[username].length; entry++) {
			//caches the entry
			var tempentry = this.accountdict[username][entry];

			//ignore shielded account entries
			if (tempentry["sharenumber"] === 0)
				continue; //skips over this iteration of the loop

			var tempsaltedpasshash = _SHA256(tempentry["salt"] + password);
			var tempsharenumber_hex = tempentry["sharenumber"].toString(16);
			if (tempsharenumber_hex.length === 1)
				tempsharenumber_hex = "0" + tempsharenumber_hex;
			var tempshare = "8" + tempsharenumber_hex + _xor(tempsaltedpasshash,
					tempentry["saltedpasshash"].substring(0,
					tempentry["saltedpasshash"].length -
					this.isolatedcheckbits));
			sharelist.push(tempshare);
		}
	}
	//Throws an error if a share is incorrect or there are other issues
	// (e.g. not enough shares to meet the threshold)
	var combined = sss.combine(sharelist); //gets the shieldedkey
	//resets the SSSobj
	this.shamirsecretshares = sharelist.slice(0, this.threshold);

	if (!(this.verify_secret(combined)))
		throw new Error("This is not a valid secret recombination." +
				" Inadequate/incorrect shares provided.");

	this.shieldedkey = combined;

	//changes bootstrap accounts -> shielded accounts
	for (entry=0; entry<this.bootstrapaccounts.length; entry++) {
		//caches the entry
		var tempentry = this.bootstrapaccounts[entry];

		tempentry["saltedpasshash"] = _AESencrypt(this.shieldedkey,
				tempentry["saltedpasshash"]);
		tempentry["sharenumber"] = 0;
	}

	//no more bootstrap accounts bc secret was recovered
	this.bootstrapaccounts = [];
	this.knownsecret = true;
}

/**
* Compares local isolated check bits with the isolated check bits provided and
* checks if the provided password is correct
* @param saltedpasshash
* @param storedhash
*/
PPH.prototype.isolated_validation = function (temphash, storedhash) {

	var saltedpasshashICB = this.create_isolated_validation_bits(temphash);
	var localICBs = storedhash.substring(storedhash.length -
			this.isolatedcheckbits);
	return saltedpasshashICB === localICBs;
}

/**
* Creates and returns a random 31-byte secret which is hashed
* 100k times and stored to verify the secret upon recombination
* @return the secret
*/
PPH.prototype.create_secret = function () {

	var secretlength = this.secretlength;
	var verificationiterations = this.recombinationiterations;

	//makes random 31-byte string..multiply by 8 bc random() takes bits
	var secret = sss.random(this.secretlength * 8);
	
	//hashes secret 100k times
	var secretdigest = _SHA256(secret);
	for (var i=1; i<verificationiterations; i++)
		secretdigest = _SHA256(secretdigest);

	//used later to verify you get the correct secret back
	this.secretintegritycheck = secretdigest;
	
	return secret;
}

/**
* Compares the provided secret with the stored integrity check
* @param secret
* @return boolean that indicates whether the secret passes the integrity check
*/
PPH.prototype.verify_secret = function (secret) {

	var secretlength = this.secretlength;
	var verificationiterations = this.recombinationiterations;

	//hashes the secret passed in 100k times
	var hashedsecret = _SHA256(secret);
	for (var i=1; i<verificationiterations; i++)
		hashedsecret = _SHA256(hashedsecret);

	return hashedsecret === this.secretintegritycheck;
}

/**
* Creates and returns the isolated-check bits suffix for a saltedpasshash
* @param saltedpasshash
* @return the suffix
*/
PPH.prototype.create_isolated_validation_bits = function (saltedpasshash) {
	
	var ICBs = this.isolatedcheckbits;
	var ICBiterations = this.ICBiterations;

	var tempsaltedpasshash;

	for (var i=1; i<ICBiterations; i++)
		tempsaltedpasshash = _SHA256(saltedpasshash);

	return saltedpasshash.substring(saltedpasshash.length - ICBs);
}




//-----------Helper functions-----------
/**
* Does AES encryption
* @param key the key used to encrypt the message
* @param msg the text to encrypt
* @return the encrypted msg
*/
var _AESencrypt = function (key, msg) {
	
	var cipher = crypto.createCipher("aes-256-ctr", key);
	var charstr = "";
	for (var i=0; i<msg.length; i+=2)
		charstr += String.fromCharCode(parseInt(msg.substring(i, i+2), 16));

	var ciphertext = cipher.update(charstr, "ascii", "hex");
	//cipher.final("hex");
	return ciphertext;
}

/**
* Does SHA256 hashing
* @param msg the text to hash
* @return the hash
*/
var _SHA256 = function (msg) {

	var sha256 = crypto.createHash("sha256");
	return sha256.update(msg).digest("hex");
}

/**
* Checks if a given share is valid
* @param SSSobj a JSON that represents the shamirsecretobj
* @param share the share to be validated as a list of 2
*/
var _validate = function (storedshares, share) {

	if (typeof share !== "object" || share.length !== 2)
		throw new Error("Share is not a list of length 2: " + typeof share);

	if (share[1].length !== 64)
		throw new Error("Share is of incorrect length: " + share.length);

	var correctshare = sss.newShare(share[0], storedshares);

	if (correctshare.substring(3) === share[1]) return true;
	return false;
}

/**
* Generates and returns a bytearray
* @param str the string to be turned into a bytearray
* @return the bytearray
*/
var _bytearray = function (str) {

	var bytearray = [];
	for (var i=0; i<str.length; i+=2)
		bytearray.push(parseInt("0x" + str.substring(i, i+2)));
	return bytearray;
}

/**
* Does the exclusive-or of two strings of hex numbers
* @param x a string
* @param y another string
* @return the XOR as a string
*/
var _xor = function (x, y) {

	if (typeof x !== typeof y || typeof x !== "string" || typeof y !== "string")
		throw new Error(x + " (" + typeof x + ") and/or " + y + " (" + typeof y +
				") are/is not of type string");

	if (x.length !== y.length || x.length !== 64)
		throw new Error(x + " and/or " + y + " are/is not 32 bytes");

	var xb = _bytearray(x);
	var yb = _bytearray(y);

	var result = "";
	for (var i=0; i<xb.length; i++) {
		var temp = (xb[i]^yb[i]).toString(16);
		if (temp.length === 1)
			result += ("0" + temp);
		else
			result += temp;
	}
	return result;
}

module.exports = PPH;

/* Tests the various methods of the PolyPasswordHasher library during isolated
*  validation. Should print nothing if everything goes well.
*/

var PPH = require("./polypasswordhasher.js");
var THRESHOLD = 10;
var pph = new PPH(THRESHOLD);

pph.create_account('admin','correct horse',THRESHOLD/2);
pph.create_account('root','battery staple',THRESHOLD/2);
pph.create_account('superuser','purple monkey dishwasher',THRESHOLD/2);

pph.create_account('alice','kitten',1);
pph.create_account('bob','puppy',1);
pph.create_account('charlie','velociraptor',1);
pph.create_account('dennis','menace',0);
pph.create_account('eve','iamevil',0);

//T: valid share
assert(pph.is_valid_login('alice','kitten')==true);
//T: valid share
assert(pph.is_valid_login('admin','correct horse')==true);
//F: doesn't pass any of the checks
assert(pph.is_valid_login('alice','nyancat!')==false);
//T: password encrypts the right way
assert(pph.is_valid_login('dennis','menace')==true);
//F: pswd doesn't encrypt the same way
assert(pph.is_valid_login('dennis','password')==false);
//T: password encrypts the right way
assert(pph.is_valid_login('eve','iamevil')==true);

pph.write_password_data('securepasswords');

pph = undefined;

pph = new PPH(THRESHOLD, "securepasswords");

var ok = true;
try{
	pph.is_valid_login("alice","kitten");
}
catch(e) {
	ok = false;
}
if (ok)
	console.log("Can't get here! It's still bootstrapping!");


pph.unlock_password_data([['admin','correct horse'],
		['root','battery staple'],
		['bob','puppy'],
		['dennis','menace']]);

assert(pph.is_valid_login('alice','kitten'));


var assert = function (condition) { 
    if (!condition)
        throw Error("Assert failed");
};
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

console.log("alice+kitten T: "+pph.is_valid_login('alice','kitten')) //valid share
console.log("admin+correct horse T: "+pph.is_valid_login('admin','correct horse')) //valid share
console.log("alice+nyancat F: "+pph.is_valid_login('alice','nyancat!')) //nothing checked out
console.log("dennis+menace T: "+pph.is_valid_login('dennis','menace')) //password encrypts the right way
console.log("dennis+password F: "+pph.is_valid_login('dennis','password')) //shielded account but pswd doesn't encrypt the same way
console.log("eve+iamevil T: "+pph.is_valid_login('eve','iamevil')); //password encrypts the right way

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

//now alice can have all the kittens her cat-loving heart desires
console.log(pph.is_valid_login('alice','kitten'));
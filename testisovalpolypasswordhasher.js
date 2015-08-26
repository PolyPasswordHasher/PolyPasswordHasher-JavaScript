var PPH = require("./polypasswordhasher.js");
var THRESHOLD = 10;
var pph = new PPH(THRESHOLD, undefined, 2);

pph.create_account('admin','correct horse',THRESHOLD/2);
pph.create_account('root','battery staple',THRESHOLD/2);
pph.create_account('superuser','purple monkey dishwasher',THRESHOLD/2);

pph.create_account('alice','kitten',1);
pph.create_account('bob','puppy',1);
pph.create_account('charlie','velociraptor',1);
pph.create_account('dennis','menace',0);
pph.create_account('eve','iamevil',0);

console.log("alice+kitten: "+pph.is_valid_login('alice','kitten')) //SN16 T bc valid share -ok
console.log("admin+correct horse: "+pph.is_valid_login('admin','correct horse')) //SN1 T bc valid share -ok
console.log("alice+nyancat: "+pph.is_valid_login('alice','nyancat!')) //SN16 F nothing worked -ok
console.log("dennis+menace: "+pph.is_valid_login('dennis','menace')) //SN0 T bc password encrypts the right way -ok
console.log("dennis+password: "+pph.is_valid_login('dennis','password')) //SN0 F bc shielded account but pswd doesn't encrypt the same way -ok
console.log("eve+iamevil: "+pph.is_valid_login('eve','iamevil')); //T bc password encrypts the right way

pph.write_password_data('securepasswords');

pph = undefined;

pph = new PPH(THRESHOLD,'securepasswords',2);

pph.create_account("bootstrapper", 'password', 0);

var ok = true;
try{
	console.log("T: "+pph.is_valid_login("bootstrapper",'password'));
	console.log("F: "+pph.is_valid_login("bootstrapper",'nopassword'));
}
catch(e){
	console.log("Bootstrap account creation failed.");
	ok = false;	
}
if (ok)
	console.log("bootstrap account logins can be checked");


try{
	console.log("T: "+pph.is_valid_login('alice','kitten'));
	console.log("T: "+pph.is_valid_login('admin','correct horse'));
	console.log("F: "+pph.is_valid_login('alice','nyancat!'));
}
catch(e){
	console.log("Isolated validation but it is still bootstrapping!!!");
}

ok=true;
try{
	pph.create_account('moe','tadpole',1);
}
catch(e){
	//Should be bootstrapping...
	console.log("This is right");
	ok=false;
}
if (ok){
	console.log("Isolated validation does not allow account creation!");
}

pph.unlock_password_data([['admin','correct horse'],
						['root','battery staple'],
						['bob','puppy'],
						['dennis','menace']]);

//alice has a cat fetish
console.log(pph.is_valid_login('alice','kitten'));

pph.create_account('moe','tadpole',1);
pph.create_account('larry','fish',0);
var results = new Object();
db.targets.find({}).forEach(function(z) {
	var output = "";
	department = z.department;
	division = z.division;
	email_address = z.email_address;
	email_count = z.email_count;
	organization_id = z.organization_id;
	firstname = z.firstname;
	lastname = z.lastname;
	title = z.title;
	site = z.site;
	output += department + "," + division + "," + email_address + "," + email_count + "," + organization_id + "," + firstname + "," + lastname + "," + title + "," + site + "\n";
	print(output);
} );

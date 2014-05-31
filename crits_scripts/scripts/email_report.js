var results = new Object();
db.email.find({}, {'from': 1, 'source': 1}).forEach(function(z) { 
	var output = "";
	datetime = z.source[0].instances[0].date;
	from = z.from
	name = z.source[0].name
	reference = z.source[0].instances[0].reference
	output += datetime + "," + from + "," + name + "," + reference + "\n";
	print(output);
} );

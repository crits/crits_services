var results = new Object();
map = function() {
	if ("x_mailer" in this) {
		emit({name: this.x_mailer}, {count: 1})
	}
}
reduce = function(k,v) { 
	var count=0; 
	v.forEach(function(v) { 
		count += v["count"]; }); 
	return {count: count}; 
}
//db.email.mapReduce(map, reduce, {out: "email_test"})
var results = db.email.mapReduce(map, reduce, {out: {inline: 1}})
results.results.forEach(function(z) {
	print("'" + z._id.name + "' = " + z.value.count)
})


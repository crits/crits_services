var results = new Object();
db.getMongo().setSlaveOk();
map = function() {
	if ("md5" in this) {
		emit({name: this.md5}, {count: 1})
	}
}
reduce = function(k,v) {
	var count=0;
	v.forEach(function(v) {
		count += v["count"]; });
	return {count: count};
}
finalize = function(k, v) {
	if (value.count > 1) {
		return value; }
}
//db.samples.mapReduce(map, reduce, {out: "dup_md5"})
var cmd = {
	mapreduce: "sample",
	map: map,
	reduce: reduce,
	finalize: finalize,
	out: {inline: 1}
}
var results = db.runCommand(cmd)
for (foo in results.results) {
	print(foo._id.name, foo.value.count);
}


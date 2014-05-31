// Change the date to one of your choosing.
// Can also use this for an upper bound:
//var a = db.samples.find({'source.instances.date': {$gte: ISODate("2011-06-11T00:00:00.000Z"), $lte: ISODate("2012-06-13T00:00:00.000Z")}}, {'md5': 1});
var a = db.sample.find({'source.instances.date': {$gte: ISODate("2011-06-11T00:00:00.000Z")}}, {'md5': 1});
a.forEach(function(z) { print(z.md5); });

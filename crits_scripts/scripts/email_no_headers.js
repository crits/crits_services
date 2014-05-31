var source_name = "your organization";
db.email.find({'raw_headers': {$exists: false}, 'source.name': source_name}).forEach(function(z) {
     print(z.subject + "," + z.from + "," + z.source[0].instances[0].date);
});

var source_name = "your organization";
if (typeof search_type == 'undefined') {
    search_type = 'md5'; }
db.email.find({'attachment.md5': {$exists: true}, 'source.name': source_name}).forEach(function(z) {
    z.attachment.forEach(function(y) {
        if (search_type == 'md5') {
            if (y.md5 != null) {
                var a = db.sample.findOne({'md5': y.md5.toLowerCase()}, {'md5': 1});
                if (a == null) { print(z.from + "," + z.source[0].instances[0].date + "," + y.md5.toLowerCase() + "," + y.filename); }
            }
        }
        else if (search_type == 'filename') {
            if (y.filename != null && y.md5 == null) {
                print(z.from + "," + z.source[0].instances[0].date + ",," + y.filename + "," + z.source[0].instances[0].reference); }
        }
    } );
} );

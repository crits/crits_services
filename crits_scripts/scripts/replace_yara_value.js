value = "ups_h101_constants";
replace = "md5_constants";
save = false;
db.sample.find({'analysis.results.result': value}).forEach(function(x) {
        try {
        x.analysis.forEach(function(y) {
                y.results.forEach(function(z) {
                        if (z.result == value) {
                                z.result = replace;
                                print("replacing for " + x.md5);
                                save = true;
                        }
                })
        })
        }
        catch (err) { print("error on " + x.md5); }
        if (save == true) {
                db.sample.save(x);
        }
})


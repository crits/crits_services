if (typeof value == 'undefined') {
        value = ["ups_h101_constants"]; }
var stringlist = {};
for (i=0; i<value.length; i++) { stringlist[value[i]] = ''; }
collection = db.samples
save = false;
collection.find({'analysis.results.result': {$in:  value}}).forEach(function(x) {
        try {
        x.analysis.forEach(function(y) {
		if ("results" in y) {
	                for (z=0; z < y.results.length; z++) {
				if ("result" in y.results[z]) {
       		                 	if (y.results[z].result in stringlist) {
       	                        	 print("chopping " + y.results[z].result + " from " + x.md5);
       	                        	 y.results.splice(z);
       	                        	 save = true;
                	        	}
				}
                	}
		}
        })
        }
        catch (err) { print("error on " + x.md5); }
        if (save == true) {
                collection.save(x);
        }
})


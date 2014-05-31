map = function() {
                this.analysis.forEach(function(z) {
                        if ("results" in z && z.service_name == "yara") {
                                z.results.forEach(function(x) {
                                        emit({engine: z.service_name, version: z.version, result: x.result} ,{count: 1});
                                })
                        }
                        })
                }
reduce = function(k,v) { var count=0; v.forEach(function(v) { count += v["count"]; }); return {count: count}; }
out = db.sample.mapReduce(map, reduce, {out: {inline: 1}});
print(out);

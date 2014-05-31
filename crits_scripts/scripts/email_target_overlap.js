Array.prototype.has= function (v) {
    for (i = 0; i < this.length; i++) {
        if (this[i] == v) {
            return i;
        }
    }
    return false;
}
var source_name = "your organization";
var campaign_name = "the campaign";

var msgs = db.email.find({'campaign.name': campaign_name, 'source.name': source_name}).sort({'source.instances.date': -1});
var baseline = 0;
var base = msgs[0].to;
var msgs = db.email.find({'campaign.name': campaign_name, 'source.name': source_name}).sort({'source.instances.date': -1});
msgs.forEach(function(z) {
	var overlap = 0;
	z.to.forEach(function(y) {
		if (base.has(y)) {overlap += 1; }
	});
	var ratio = overlap / z.to.length * 100;
	print(z.source[0].instances[0].date.getMonth() + 1 + "/" + z.source[0].instances[0].date.getFullYear() + "\t", overlap + "\t", z.to.length + "\t", ratio + '%');
});


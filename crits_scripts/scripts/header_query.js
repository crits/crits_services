if (typeof campaign == 'undefined') {
    campaign = "Unknown"; }
if (typeof sanitize == 'undefined') {
    sanitize = false; }
var results = new Object();
db.email.find({'campaign.name': campaign, 'raw_headers': {$exists: true}}).forEach(function(z) {
    var output = "";
    raw_headers = z.raw_headers;
    raw_headers = raw_headers.replace(/ (\S+: )/g, "\r\n$1");
    if (sanitize) {
        raw_headers = raw_headers.replace(/((To|CC|Bcc): .*)/, "To: xxx@xxx.xxx");
    }
    output += raw_headers + "\r\n\r\n";

    if (z.raw_body != undefined) { output += z.raw_body; };
    output += "\r\n--------------------------------------------------------------\r\n";
    print(output);
} );

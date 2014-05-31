function lcs(lcstest, lcstarget) {
 matchfound = 0
 lsclen = lcstest.length
  for(lcsi=0; lcsi<lcstest.length; lcsi++){
   lscos=0
    for(lcsj=0; lcsj<lcsi+1; lcsj++){
     re = new RegExp("(?:.{" + lscos + "})(.{" + lsclen + "})", "i");
     temp = re.test(lcstest);
     re = new RegExp("(" + RegExp.$1 + ")", "i");
      if(re.test(lcstarget)){
       matchfound=1;
       result = RegExp.$1;
       break;
       }
     lscos = lscos + 1;
     }
     if(matchfound==1){return result; break;}
    lsclen = lsclen - 1;
   }
  result = "";
  return result;
 }

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

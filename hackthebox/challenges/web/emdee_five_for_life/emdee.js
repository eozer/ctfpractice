var http = require("http")
var querystring = require("querystring")
var md5 = require('spark-md5').hash

const url = '167.99.86.47'
const port = 32568

var options = {
    hostname: url,
    port: port,
    path: '/',
};

// console.time("emdee")
var d = ""
var getReq = http.request({ ...options }, (res) => {
    res.setEncoding('utf8');
    res.on('data', (chunk) => {
        // let idx = chunk.indexOf("<h3 align='center'>") + 19
        // console.log(idx)
        // hash = md5(chunk.substring(idx, idx + 20))
        // console.log(Buffer.byteLength(post_data))
        var encodeme = chunk.substring(167, 187) // NOTE: Got from above
        var postReq = http.request({
            hostname: url,
            port: port,
            path: '/',
            method: "POST", headers: {
                'Cookie': res.rawHeaders[5],
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': 37 //Buffer.byteLength(post_data) // NOTE: Got from left
            }
        }, (res2) => {
            res2.setEncoding('utf8');
            res2.on('data', (c2) => {
                d += c2
            });
            res2.on('end', ()=>{
                // console.log(encodeme)
                // console.log(md5(encodeme))
                console.log(d)
            })
        });
        postReq.write(querystring.stringify({
            'hash': md5(encodeme)
        }))
        postReq.end()
    });
});
getReq.end();
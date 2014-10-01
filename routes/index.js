var express = require('express');
var http = require('http');
var util = require('util');
var spawn = require('child_process').spawn;
var crypto = require('crypto');
var Iconv = require("iconv").Iconv;
var geoip = require('geoip-lite');
var google = require('googleapis');
/*
var OAuth2 = google.auth.OAuth2;
var CLIENT_ID = '129252659172-atrukhe89ukegeevpg44np7tpddi3br4.apps.googleusercontent.com';
var CLIENT_SECRET = 'wmEpjkaH7LHKDvWv-HWRCEKy';
var REDIRECT_URL = 'urn:ietf:wg:oauth:2.0:oob';
var oauth2Client = new OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL);
var scopes = [
  'https://www.googleapis.com/auth/urlshortener',
];

var url = oauth2Client.generateAuthUrl({
  access_type: 'offline', // 'online' (default) or 'offline' (gets refresh_token)
  scope: scopes // If you only need one scope you can pass it as string
});
*/
/*
oauth2Client.getToken(code, function(err, tokens) {
	console.log(err);
	if(!err) {
		oauth2Client.setCredentials(tokens);
	}
});
*/
var router = express.Router();

function spawn_pipe_http(req, res, cmd, args, time) {
	var process = spawn(cmd, args, {
	});
	process.stdout.pipe(res);
	process.stderr.pipe(res);

	var timer = setTimeout(function() {
		console.log('spawn_pipe_http: timeout');
		process.stdout.unpipe(res);
		process.stderr.unpipe(res);
		process.kill('SIGUSR2');
	}, time);
	/*
	process.stdout.on('data', function(data)  {
		console.log('stdout:' + data);
	});
	process.stderr.on('data', function(data)  {
		console.log('stderr:' + data);
	});
	*/
	//process.on('close', function(code, signal) {
	//});
	res.connection.on('error', function(err)  {
		console.log(err);
	});
	process.on('error', function(err)  {
		console.log(err);
	});
	process.on('exit', function(code, signal)  {
		console.log('spawn_pipe_http: signal(' + signal + ')');
		if (signal=='SIGUSR2') {
			res.write('timeout');
		}
		if (timer) clearTimeout(timer);
		res.end();
	});
	req.connection.on('end', function() {
		console.log('req connection end');
		process.stdout.unpipe(res);
		process.stderr.unpipe(res);
		process.kill();
	});

	return process;
}

function iconv_encode(str, from, to) {
	var iconv = new Iconv(from, to + '//IGNORE');
	return iconv.convert(str);
}

router.get('/', function(req, res) {
	var locals = {};

	locals.title = 'Tools';
	locals.webinfo = {
		ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
		agent: req.headers['user-agent']
	};

	locals.ciphers = crypto.getCiphers();
	locals.hashes = crypto.getHashes();

	res.render('index', locals);
});

router.post('/encode', function(req, res) {
	var type = req.body['type'];
	var plain = req.body['from'];
	var encoding = req.body['encoding'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	result = '';
	try {
		var buff = null;
		if (encoding!='utf8') {
			buff = iconv_encode(plain, 'utf-8', encoding);
		} else {
			buff = new Buffer(plain);
		}

		if (type=='base64') {
			result = buff.toString('base64');
		} else if (type=='url') {
			var enc = [];
			for (var i=0; i<buff.length; i++) {
				if ((buff[i] >= 0x30 && buff[i] <= 0x39)
					|| (buff[i] >= 0x41 && buff[i] <= 0x5A)
					|| (buff[i] >= 0x61 && buff[i] <= 0x7A))
				{
					enc.push(String.fromCharCode(buff[i]));
				} else {
					enc.push('%' + buff[i].toString(16).toUpperCase());
				}
			}
			result = enc.join('');
		}
	} catch (e) {
		result = e.message;
	}
	res.write(result);
	res.end();
});

router.post('/decode', function(req, res) {
	var type = req.body['type'];
	var encoded = req.body['to'];
	var encoding = req.body['encoding'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	result = '';
	try {
		var buff = null;
		if (type=='base64') {
			buff = new Buffer(encoded, 'base64');
		} else if (type=='url') {
			var dec = [];
			for (var i=0; i<encoded.length; i++) {
				if (encoded[i]=='%') {
					if (i+2 < encoded.length) {
						dec.push(encoded.substring(i+1, i+3).toUpperCase());
						i+=2;
					}
					continue;
				} else {
					dec.push(encoded.charCodeAt(i).toString(16));
				}
			}
			buff = new Buffer(dec.join(''), 'hex');
		}

		if (encoding!='utf8') {
			result = iconv_encode(buff, encoding, 'utf-8').toString();
		} else {
			result = buff.toString();
		}
	} catch (e) {
		result = e.message;
	}
	res.write(result);
	res.end();
});

router.post('/cipher', function(req, res) {
	var type = req.body['type'];
	var password = req.body['password'];
	var input_encoding = req.body['input-encoding'];
	var output_encoding = req.body['output-encoding'];
	var plain = req.body['from'];

	if (!type) type = 'aes128';
	if (!input_encoding) input_encoding = 'utf8';
	if (!output_encoding) output_encoding = 'hex';

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	var result = '';
	try {
		var cipher = crypto.createCipher(type, password);
		result = cipher.update(new Buffer(plain), input_encoding, output_encoding);
		result += cipher.final(output_encoding);
	} catch (e) {
		result = e.message;
	}
	res.write(result);
	res.end();
});

router.post('/decipher', function(req, res) {
	var type = req.body['type'];
	var password = req.body['password'];
	var input_encoding = req.body['input-encoding'];
	var output_encoding = req.body['output-encoding'];
	var ecrypt = req.body['to'];

	if (!type) type = 'aes128';
	if (!input_encoding) input_encoding = 'utf8';
	if (!output_encoding) output_encoding = 'hex';

	//res.writeHead(200, {'Content-Type': 'text/plain'});

	var result = '';
	try {
		var decipher = crypto.createDecipher(type, password);
		result = decipher.update(ecrypt, output_encoding, input_encoding);
		result += decipher.final(input_encoding);
	} catch (e) {
		result = e.message;
	}

	res.write(result);
	res.end();
});

router.post('/hash', function(req, res) {
	var type = req.body['type'];
	var plain = req.body['plain'];

	if (!type) type = 'md5';

	//res.writeHead(200, {'Content-Type': 'text/plain'});

	var result = '';
	try {
		var md5hash = crypto.createHash(type);
		md5hash.update(plain);
		result = md5hash.digest('hex');
	} catch (e) {
		result = e.message;
	}

	res.write(result);
	res.end();
});

router.post('/headers', function(req, res) {
	var url = req.body['url'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});

	if (!url) {
		res.write('error: input url');
		res.end();
		return;
	}
	if (url.indexOf('http://')!=0) {
		url = 'http://' + url;
	}

	var request = http.request(url, function(response) {
		response.resume();
		res.write(util.inspect(response.headers));
		res.end();
		return;
	});
	request.on('error', function(e) {
		console.log('problem with request: ' + e.message);
		console.log(e);
		res.write('problem with request: ' + e.message);
		res.end();
	});
	request.on('socket', function (socket) {
		socket.setTimeout(15*1000);  
		socket.on('timeout', function() {
			request.abort();
			res.write('socket timeout');
			res.end();
		});
	});
	request.end();
});

router.post('/ping', function(req, res) {
	var host = req.body['host'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	if (!host) {
		res.write('error: input host');
		res.end();
		return;
	}

	host = host.replace(/^[-]+/g, '').replace(/[^0-9a-zA-Z.-]/g, '');
	spawn_pipe_http(req, res, "ping", ['-c3', host], 30000);
});

router.post('/nslookup', function(req, res) {
	var host = req.body['host'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	if (!host) {
		res.write('error: input host');
		res.end();
		return;
	}
	host = host.replace(/^[-]+/g, '').replace(/[^0-9a-zA-Z.-]/g, '');
	spawn_pipe_http(req, res, "nslookup", [host], 30000);
});

router.post('/whois', function(req, res) {
	var host = req.body['host'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	if (!host) {
		res.write('error: input host');
		res.end();
		return;
	}
	host = host.replace(/^[-]+/g, '').replace(/[^0-9a-zA-Z.-]/g, '');
	spawn_pipe_http(req, res, "whois", [host], 30000);
});

router.post('/geoip', function(req, res) {
	var ip = req.body['ip'];

	//res.writeHead(200, {'Content-Type': 'text/plain'});
	if (!ip) {
		res.write('error: input ip');
		res.end();
		return;
	}
	ip = ip.replace(/[^0-9.]/g, '');
	console.log(ip);

	var result = '';
	try {
		var geo = geoip.lookup(ip);
		result = util.inspect(geo);
	} catch (e) {
		result = e.message;
	}
	res.write(result);
	res.end();
});

router.post('/linkshort', function(req, res) {
	var url = req.body['url'];
	if (!url) {
		res.write('error: input url');
		res.end();
		return;
	}

	var key = 'AIzaSyBG-79rox9JnCJiv7YRrGILZRjAmv5Mer4';

	var result = '';
	try {
		var urlshortener = google.urlshortener('v1');
		var params = {
			'resource': { 
				'longUrl': url 
			},
			auth:key,
		};

		urlshortener.url.insert(params, function (err, response) {
			if (err) {
				res.write(err);
				res.write(response);
				res.end();
			} else {
				res.write(response.id);
				res.end();
			}
		});
	} catch (e) {
		res.write(e.message);
		res.end();
	}
});


module.exports = router;

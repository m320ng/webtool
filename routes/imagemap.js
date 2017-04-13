var express = require('express');
var http = require('http');
var util = require('util');
var fs = require('fs');

var router = express.Router();

router.get('/', function(req, res) {
	var locals = {};

	res.render('imagemap/index', locals);
});

router.post('/upload', function(req, res) {
	console.log(req.files);
	res.setHeader('content-type', 'text/html');
	res.write('<script>parent.callback_upload("'+req.files['file']['path']+'")</script>');
	res.end();
});


module.exports = router;

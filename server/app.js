const express = require("express")
const http = require("http")
const request = require("request-promise")
const bodyParser = require("body-parser")
const {createHash} = require("crypto")

var app = express()

const appId = "wx5a1efd84eae4d10f"
const secret = "c73207ad87a0050dd12e6b779dac35b5"

const encrypt = (algorithm, content) => {
	let hash = createHash(algorithm)
	hash.update(content)
	return hash.digest("hex")
}
const sha1 = content => encrypt("sha1", content)
const md5 = content => encrypt("md5", content)

var jsonParser = bodyParser.json()
var urlencodeParser = bodyParser.urlencoded({extend: false})

var tokenObj
var jsapi_ticketObj

app.all("*", function(req, res, next) {
	res.header("Access-Control-Allow-Origin", "*")
	res.header("Access-Control-Allow-Headers", "X-Requested-With")
	res.header("Access-Control-Allow-Methods", "PUT,POST,GET,DELETE,OPTIONS")
	res.header("X-Powered-By", " 3.2.1")
	res.header("Content-Type", "application/json;charset=utf-8")
	next()
})
app.get("/authority", urlencodeParser, function(req, res, next) {
	get_access_token(req, res)
})

// body: {"access_token":"31_2gQZ0lkUfDW1mxH3yKr8nRfyvDbW3XHv1O6fQCeNeRQH-bWg63ktgK_2pPh69Kt51nzqfJ4P58fUUEd-LFr__7SaMjiwZonFo7hi27xHe9UMAXIJxplApmr9Q2gNXh2I7YZ6g-P-Cp8G6AWvJRMhAGAUCX","expires_in":7200}

http.createServer(app).listen(3000, function() {
	console.log("Server is listening at: localhost:3000")
})

function get_access_token(req, res) {
	var now = new Date().getTime()
	if (!tokenObj || now - tokenObj.time >= 7200000) {
		request("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + appId + "&secret=" + secret)
			.then(function(body) {
				console.log("authority body: \n", body)
				var data = JSON.parse(body)
				tokenObj = {access_token: data.access_token, time: new Date().getTime()}
				get_jsapi_ticket(req, res, tokenObj.access_token)
			})
			.catch(function(err) {
				// POST failed...
				console.error("err:", err) // Print the error if one occurred
				res.send(err)
			})
	} else {
		get_signature(req, res, jsapi_ticketObj.ticket)
		console.log("tokenObj: \n", tokenObj)
	}
}
function get_jsapi_ticket(req, res, access_token) {
	request("https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=" + access_token + "&type=jsapi")
		.then(function(body) {
			console.log("get_jsapi_ticket body: \n", body)
			var data = JSON.parse(body)
			if (data.errcode == 40001) {
				tokenObj = null
				get_access_token(res)
			} else {
				jsapi_ticketObj = data
				get_signature(req, res, jsapi_ticketObj.ticket)
			}
		})
		.catch(function(err) {
			// POST failed...
			console.error("err:", err) // Print the error if one occurred
			res.send(err)
		})
}
function get_signature(req, res, jsapi_ticket) {
	var noncestr = "Wm3Wsfr323zaeccnW"
	var timestamp = new Date().getTime()
	var url = req.query.url
	var string1 = "jsapi_ticket=" + jsapi_ticket + "&noncestr=" + noncestr + "&timestamp=" + timestamp + "&url=" + url
	var signature = sha1(string1)
	console.log("string1: ", string1)
	console.log("signature: ", signature)
	res.send({
		appId: appId,
		timestamp: timestamp,
		signature: signature,
		noncestr: noncestr
	})
}

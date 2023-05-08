const authHost = "http://127.0.0.1:8000";

const authorizeUrl = "/oauth2/authorize";

const tokenUrl = "/oauth2/token";

const redirectUri = "http://127.0.0.1:3000/html/redirect.html";

const clientId = "client";

const clientSecret = "secret";

const responseType = "code";

const scope = "read";

const grantType = "authorization_code";

function appendParam(url, key, value) {
    if (url.indexOf("?") != -1) {
        return url + "&" + key + "=" + value;
    } else {
        return url + "?" + key + "=" + value;
    }
}

function oauth2Process() {
    let requestParam = getRequestParam();
    if (requestParam.code == null) {
        // get authorize code
        let link = authHost + authorizeUrl;
        link = appendParam(link, "response_type", responseType);
        link = appendParam(link, "client_id", clientId);
        link = appendParam(link, "scope", scope);
        link = appendParam(link, "redirect_uri", redirectUri);
        window.location.href = link;
    } else {
        // base64 for client info
        let clientInfoBase64 = btoa(clientId + ":" + clientSecret);
        // splice token url
        let link = authHost + tokenUrl;
        link = appendParam(link, "client_id", clientId);
        link = appendParam(link, "redirect_uri", redirectUri);
        link = appendParam(link, "grant_type", grantType);
        link = appendParam(link, "code", requestParam.code);
        // call api
        let httpRequest = new XMLHttpRequest();
        httpRequest.open("POST", link, true);
        httpRequest.setRequestHeader("Authorization", "Basic " + clientInfoBase64);
        httpRequest.send();
        httpRequest.onreadystatechange = function () {
            let tokenObj = eval("(" + httpRequest.responseText + ")");
            window.sessionStorage.setItem("Authorization", tokenObj.token_type + " " + tokenObj.access_token);
            console.log(window.sessionStorage.getItem("Authorization"));
            window.location.href = "/html/home.html"
        }
    }
}

function getRequestParam() {
    const url = location.href;
    let urlStr = url.split('?')[1];
    let obj = {};
    if (urlStr == null) {
        return obj;
    }
    let paramsArr = urlStr.split('&')
    for(let i = 0,len = paramsArr.length;i < len;i++){
        // 再通过 = 将每一个参数分割为 key:value 的形式
        let arr = paramsArr[i].split('=')
        obj[arr[0]] = arr[1];
    }
    return obj;
}
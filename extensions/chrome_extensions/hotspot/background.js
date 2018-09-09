
chrome.cookies.onChanged.addListener(function(info) {
	var cookie= {}
 	if (info["cause"] ==="explicit" ){
		if  (info["removed"] ===false ){
			cookie[info.cookie.name] = JSON.stringify(info.cookie)
  			console.log(info["cause"] + " -- " + JSON.stringify(info.cookie));

			chrome.storage.local.set(cookie);
		}
	}
  });

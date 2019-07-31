var cookie= []

browser.cookies.onChanged.addListener(function(info) {
 	if (info["cause"] ==="explicit" ){
		if  (info["removed"] ===false ){
			var set_cookie= {}
			let loadTime = new Date().getTime() / 1000;
			
			
			var cart= JSON.parse(JSON.stringify(info.cookie))
			cart.createdate = loadTime

			
			//console.log(cart);
			cookie.push(JSON.stringify(cart));
			
				
			set_cookie["set_cookie"] = cookie;
			//console.log(set_cookie);
			browser.storage.local.set(set_cookie);
		}
	}
 

});


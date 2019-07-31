

chrome.cookies.onChanged.addListener(function(info) {
	var cookie= {}
 	if (info["cause"] ==="explicit" ){
		if  (info["removed"] ===false ){

			var cookie= "";
			

			chrome.storage.local.get('cookie', function(result){
				//console.log("--->>>" + result.cookie);
				let loadTime = new Date().getTime() / 1000;
				var cookie_list= JSON.parse(JSON.stringify(info.cookie));
				cookie_list.createdate = loadTime;
	
				if (result.cookie =="undefined"){
					cookie = "";
				}
				else{
        				cookie= result.cookie;
				}

				if (cookie !="undefined"){
					//console.log("--->>>" + cookie_list);
					chrome.storage.local.set({'cookie':  cookie + "!!!" + JSON.stringify(cookie_list)});
				
				}
        		
  			  });

			
			

		}
	}
  });

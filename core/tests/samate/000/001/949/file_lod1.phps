<html>
<head>
<title>Remote File Inclusion</title>
</head>
<body>
	<h1>Remote File Inclusion</h1>
	This is a link for the scanners: <a href="?q=file">here</a><br />
	<h1>Content:</h1>
<?php
	if (isset($_GET['q']))
	{
		$fName =  $_GET['q'] . '.inc';
		if (file_exists($fName))
			include ($fName);
		else
			include ("error.inc");
	}
	else
		echo "Default content...";
?>
</body>
</html>

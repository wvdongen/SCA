<?php 
	/* 
		?q=<script>alert(/xss/);</script>  
		?i=42<script>alert(/xss/);</script>
	*/
	function typecast($string, $type)
	{
		switch($type)
		{
			case 'integer': return (int)($string);
			case 'string' : return $string;
			default:        return $string;
		}
	}
?>
<html>
<body>
<h1>Basic XSS</h1>
You entered (string type) <em>q</em> = <?php echo isset($_GET['q']) ? typecast($_GET['q'], 'string') : 'empty'; ?>
<br />
You entered (integer type) <em>i</em> = <?php echo isset($_GET['i']) ? typecast($_GET['i'], 'integer') : 'empty'; ?>
<br />
<form action="" method="get">
    <input name="q" type="text" />
    <input name="i" type="text" />
    <input name="Submit" type="submit" />
</form> 
</body>
</html>
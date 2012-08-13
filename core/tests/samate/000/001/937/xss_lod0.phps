<?php /* ?q=<script>alert(/xss/);</script>  */ ?>
<html>
<body>
<h1>Basic XSS</h1>
You entered <em>q</em> = <?php echo isset($_GET['q']) ? $_GET['q'] : 'empty'; ?>
<br />
<form action="" method="get">
    <input name="q" type="text" />
    <input name="Submit" type="submit" />
</form> 
</body>
</html>
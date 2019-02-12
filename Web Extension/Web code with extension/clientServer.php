<?php
header("Access-Control-Allow-Origin: *");
$site=$_POST['url'];
$html = file_get_contents($site);
//echo $html;
$bytes=file_put_contents('markup.txt', $html);

// Can use this if your default interpreter is Python 2.x.
// Has some problem executing 'which python2'. So, absolute path is just simpler.
//$python_path=exec("which python 2>&1 ");
//$decision=exec("$python_path test.py $site 2>&1 ");

//$command = escapeshellcmd('test.py $site');
//$decision = shell_exec($command);

$decision=exec("C:\Users\umesh\Anaconda3\python.exe test.py $site 2>&1 ");
echo $decision;
?>

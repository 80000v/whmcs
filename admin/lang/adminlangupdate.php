<?php

error_reporting(0);

define('WHMCS',true);

echo "Starting<br />";

require("english.php");

$lines = file("english.php");

echo "Loaded English Language File<br />";

$_LANG2 = $_ADMINLANG;

    $langs = array();
    $dirpath = dirname(__FILE__);
    $dh = opendir($dirpath);
	while (false !== ($file = readdir($dh))) {
		if (!is_dir(ROOTDIR."/lang/$file")) {
			$pieces = explode(".",$file);
			if ($pieces[1]=="php" && $pieces[0]!="english" && $pieces[0]!="adminlangupdate") $langs[] = $pieces[0];
		}
	}
	closedir($dh);

echo "Loaded Other Language Files<br />";

foreach ($langs AS $lang) {

    $_ADMINLANG = array();
    require($lang.".php");

    $data = '';

    foreach ($lines AS $line) {
        if (substr($line,0,1)=='$') {
            $parts = explode("'",$line);
            if (count($parts)=="1") $parts = explode('"',$line);
            $langkey1 = $parts[1];
            $langkey2 = $parts[3];
            $trans = $_ADMINLANG[$langkey1][$langkey2];
            if (!$trans) $trans = $_LANG2[$langkey1][$langkey2];
            $data .= '$_ADMINLANG[\''.$langkey1.'\'][\''.$langkey2.'\'] = "'.str_replace('"','\"',$trans).'";'."\n";
        } else {
            $data .= $line;
        }
    }

    /*

    foreach ($_LANG2 AS $key=>$trans) {


        if ($_LANG[$key]) $trans = $_LANG[$key];

        $data .= '$_LANG["'.$key.'"] = "'.str_replace('"','\"',str_replace('<br />','&lt;br /&gt;',$trans)).'";'."\n";

    }

    */

    $fp = fopen($lang.".php", "w");
	fwrite($fp, $data);
	fclose($fp);

    echo "Updated $lang<br />";

}

echo "Done";

?>
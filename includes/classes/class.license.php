<?php
/**
 *
 * @ WHMCS Decoded && Nulled By Mtimer
 *
 * @ Version  : 5.2.7
 * @ Author   : MTIMER
 * @ Release on : 2013-09-15
 * @ Website  : http://www.mtimer.cn
 *
 * */

class WHMCS_License {
	protected $licensekey = "";
	protected $localkey = "";
	protected $keydata = array();
	protected $salt = "";
	protected $date = "";
	protected $localkeydecoded = false;
	protected $responsedata = "";
	protected $forceremote = false;
	protected $postmd5hash = "";
	protected $releasedate = "20130423";
	protected $localkeydays = "10";
	protected $allowcheckfaildays = "5";
	protected $debuglog = array();
	protected $version = "9eb7da5f081b3fc7ae1e460afdcb89ea8239eca1";

	function __construct() {
	}


	function init() {
		global $whmcs;

		$obj = new WHMCS_License();
		$obj->licensekey = $whmcs->get_license_key();
		$obj->localkey = $whmcs->get_config( "License" );
		$obj->salt = sha1( "WHMCS" . $whmcs->get_config( "Version" ) . "TFB" . $whmcs->get_hash() );
		$obj->date = date( "Ymd" );
		$obj->decodeLocalOnce();

		if (isset( $_GET["forceremote"] )) {
			$obj->forceRemoteCheck();
			exit();
		}

		return $obj;
	}


	function getHosts() {
		$hosts = gethostbynamel( "api.mtimer.cn" );
		return $hosts;
	}


	function getLicenseKey() {
		return $this->licensekey;
	}


	function getHostIP() {
		return isset( $_SERVER["SERVER_ADDR"] ) ? $_SERVER["SERVER_ADDR"] : (isset( $_SERVER["LOCAL_ADDR"] ) ? $_SERVER["LOCAL_ADDR"] : "");
	}


	function getHostDomain() {
		return $_SERVER["SERVER_NAME"];
	}


	function getHostDir() {
		return ROOTDIR;
	}


	function getSalt() {
		return $this->salt;
	}


	function getdate() {
		return $this->date;
	}


	function checkLocalKeyExpiry() {
		$originalcheckdate = $this->getKeyData( "checkdate" );
		$localexpirymax = date( "Ymd", mktime( 0, 0, 0, date( "m" ), date( "d" ) - $this->localkeydays, date( "Y" ) ) );

		if ($originalcheckdate < $localexpirymax) {
			return false;
		}

		$localmax = $localexpirymax = date( "Ymd", mktime( 0, 0, 0, date( "m" ), date( "d" ) + 2, date( "Y" ) ) );

		if ($localmax < $originalcheckdate) {
			return false;
		}

		return true;
	}


	function remoteCheck() {
		$localkeyvalid = $this->decodeLocalOnce();
		$this->debug( "Local Key Valid: " . $localkeyvalid );

		if ($localkeyvalid) {
			$localkeyvalid = $this->checkLocalKeyExpiry();
			$this->debug( "Local Key Expiry: " . $localkeyvalid );

			if ($localkeyvalid) {
				$localkeyvalid = $this->validateLocalKey();
				$this->debug( "Local Key Validation: " . $localkeyvalid );
			}
		}


		if (( !$localkeyvalid || $this->forceremote )) {
			$postfields = array();
			$postfields["licensekey"] = $this->getLicenseKey();
			$postfields["domain"] = $this->getHostDomain();
			$postfields["ip"] = $this->getHostIP();
			$postfields["dir"] = $this->getHostDir();
			$postfields["check_token"] = sha1( time() . $this->getLicenseKey() . mt_rand( 1000000000, 9999999999 ) );
			$this->debug( "Performing Remote Check: " . print_r( $postfields, true ) );
			$data = $this->callHome( $postfields );

			if (!$data) {
				$this->debug( "Remote check not returned ok" );

				if ($this->getLocalMaxExpiryDate() < $this->getKeyData( "checkdate" )) {
					$this->setKeyData( array( "status" => "Active" ) );
				}
				else {
					$this->setInvalid( "noconnection" );
				}
			}
			else {
				$results = $this->processResponse( $data );

				if ($this->posthash != sha1( "Mtimer.CN" . $postfields["check_token"] )) {
					print_r($this->posthash);print_r(sha1( "Mtimer.CN" . $postfields["check_token"] ));die;
					$this->setInvalid();
					return false;
				}

				$this->setKeyData( $results );
				$this->updateLocalKey();
			}
		}

		$this->debug( "Remote Check Done" );
		return true;
	}


	function getLocalMaxExpiryDate() {
		return date( "Ymd", mktime( 0, 0, 0, date( "m" ), date( "d" ) - ( $this->localkeydays + $this->allowcheckfaildays ), date( "Y" ) ) );
	}


	function buildQuery($postfields) {
		$query_string = "";
		foreach ($postfields as $k => $v) {
			$query_string .= "" . $k . "=" . urlencode( $v ) . "&";
		}

		return $query_string;
	}


	function callHome($postfields) {
		$query_string = $this->buildQuery( $postfields );
		$res = $this->callHomeLoop( $query_string, 5 );

		if ($res) {
			return $res;
		}

		return $this->callHomeLoop( $query_string, 30 );
	}


	function callHomeLoop($query_string, $timeout = 5) {
		$hostips = $this->getHosts();
		foreach ($hostips as $hostip) {
			$responsecode = $this->makeCall( $hostip, $query_string, $timeout );

			if ($responsecode == 200) {
				return $this->responsedata;
			}
		}

		return false;
	}


	function makeCall($ip, $query_string, $timeout = 5) {
//		$url = "http://" . $ip . "/whmcs/verify52.php";
		$url = "http://api.mtimer.cn/whmcs/verify52.php";
		$this->debug( "Request URL " . $url );
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_POST, 1 );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $query_string );
		curl_setopt( $ch, CURLOPT_TIMEOUT, $timeout );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 0 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, 0 );
		$this->responsedata = curl_exec( $ch );
		$responsecode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$this->debug( "Response Code: " . $responsecode . " Data: " . $this->responsedata );

		if (curl_error( $ch )) {
			$this->debug( "Curl Error: " . curl_error( $ch ) . " - " . curl_errno( $ch ) );
		}

		curl_close( $ch );
		return $responsecode;
	}


	function processResponse($data) {
		$data = strrev( $data );
		$data = base64_decode( $data );
		$data = unserialize( $data );

		preg_match_all('/<(.*?)>([^<]+)<\\/\\1>/i', $data, $matches);
		$results = array();
        foreach ( $matches[1] as $k => $v )
        {
        	$results[$v] = $matches[2][$k];
        }

		$this->posthash = $results["hash"];
		unset( $results["hash"] );
		$results["checkdate"] = $this->getDate();
		return $results;
	}


	function updateLocalKey() {
		global $whmcs;

		$data_encoded = serialize( $this->keydata );
		$data_encoded = base64_encode( $data_encoded );
		$data_encoded = sha1( $this->getDate() . $this->getSalt() ) . $data_encoded;
		$data_encoded = strrev( $data_encoded );
		$splpt = strlen( $data_encoded ) / 2;
		$data_encoded = substr( $data_encoded, $splpt ) . substr( $data_encoded, 0, $splpt );
		$data_encoded = sha1( $data_encoded . $this->getSalt() ) . $data_encoded . sha1( $data_encoded . $this->getSalt() . time() );
		$data_encoded = base64_encode( $data_encoded );
		$data_encoded = wordwrap( $data_encoded, 80, "
", true );

		$whmcs->set_config( "License", $data_encoded );
		$this->debug( "Updated Local Key" );
	}


	function forceRemoteCheck() {
		$this->forceremote = true;
		$this->remoteCheck();
	}


	function setInvalid($reason = "Invalid") {
		$this->keydata = array( "status" => $reason );
	}


	function decodeLocal() {
		global $whmcs;

		$this->debug( "Decoding local key" );
		$localkey = $this->localkey;

		if (!$localkey) {
			return false;
		}

		$localkey = str_replace( "
", "", $localkey );

		$localkey = base64_decode( $localkey );
		$localdata = substr( $localkey, 40, 0 - 40 );
		$md5hash = substr( $localkey, 0, 40 );

		if ($md5hash == sha1( $localdata . $this->getSalt() )) {
			$splpt = strlen( $localdata ) / 2;
			$localdata = substr( $localdata, $splpt ) . substr( $localdata, 0, $splpt );
			$localdata = strrev( $localdata );
			$md5hash = substr( $localdata, 0, 40 );
			$localdata = substr( $localdata, 40 );
			$localdata = base64_decode( $localdata );
			$localkeyresults = unserialize( $localdata );
			$originalcheckdate = $localkeyresults["checkdate"];

			if ($md5hash == sha1( $originalcheckdate . $this->getSalt() )) {
				$localkeyresults["key"] = $whmcs->get_license_key();
				$this->debug( "Local Key Decode Successful" );
				$this->setKeyData( $localkeyresults );
			}
			else {
				$this->debug( "Local Key MD5 Hash 2 Invalid" );
			}
		}
		else {
			$this->debug( "Local Key MD5 Hash Invalid" );
		}

		$this->localkeydecoded = true;
		return $this->getKeyData( "status" ) == "Active" ? true : false;
	}


	function decodeLocalOnce() {
		if ($this->localkeydecoded) {
			return true;
		}

		return $this->decodeLocal();
	}


	function isRunningInCLI() {
		return php_sapi_name() == "cli" && empty( $_SERVER["REMOTE_ADDR"] );
	}


	function validateLocalKey() {
		if ($this->getKeyData( "status" ) != "Active") {
			$this->debug( "Local Key Status Check Failure" );
			return false;
		}


		if ($this->isRunningInCLI()) {
			$this->debug( "Running in CLI Mode" );
		}
		else {
			$this->debug( "Running in Browser Mode" );

			if ($this->isValidDomain( $this->getHostDomain() )) {
				$this->debug( "Domain Validated Successfully" );
			}
			else {
				$this->debug( "Local Key Domain Check Failure" );
				return false;
			}


			if ($this->isValidIP( $this->getHostIP() )) {
				$this->debug( "IP Validated Successfully" );
			}
			else {
				$this->debug( "Local Key IP Check Failure" );
				return false;
			}
		}


		if ($this->isValidDir( $this->getHostDir() )) {
			$this->debug( "Directory Validated Successfully" );
		}
		else {
			$this->debug( "Local Key Directory Check Failure" );
			return false;
		}

		return true;
	}


	function isValidDomain($domain) {
		$validdomains = $this->getArrayKeyData( "validdomains" );
		return in_array( $domain, $validdomains );
	}


	function isValidIP($ip) {
		$validips = $this->getArrayKeyData( "validips" );
		return in_array( $ip, $validips );
	}


	function isValidDir($dir) {
		$validdirs = $this->getArrayKeyData( "validdirs" );
		return in_array( $dir, $validdirs );
	}


	function revokeLocal() {
		global $whmcs;

		$whmcs->set_config( "License", "" );
	}


	function getKeyData($var) {
		return isset( $this->keydata[$var] ) ? $this->keydata[$var] : "";
	}


	function setKeyData($data) {
		$this->keydata = $data;
	}


	function getArrayKeyData($var) {
		$data = $this->getKeyData( $var );
		$data = explode( ",", $data );
		foreach ($data as $k => $v) {
			$data[$k] = trim( $v );
		}

		return $data;
	}


	function getProductName() {
		return $this->getKeyData( "productname" );
	}


	function getStatus() {
		return $this->getKeyData( "status" );
	}


	function getSupportAccess() {
		return $this->getKeyData( "supportaccess" );
	}


	function getReleaseDate() {
		return str_replace( "-", "", $this->releasedate );
	}


	function getActiveAddons() {
		$addons = array();
		foreach ($this->getKeyData( "addons" ) as $addon) {

			if ($addon["status"] == "Active") {
				$addons[] = $addon["name"];
				continue;
			}
		}

		return $addons;
	}


	function isActiveAddon($addon) {
		return in_array( $addon, $this->getActiveAddons() ) ? true : false;
	}


	function getExpiryDate($showday = false) {
		$expiry = $this->getKeyData( "nextduedate" );

		if (!$expiry) {
			$expiry = "Never";
		}
		else {
			if ($showday) {
				$expiry = date( "l, jS F Y", strtotime( $expiry ) );
			}
			else {
				$expiry = date( "jS F Y", strtotime( $expiry ) );
			}
		}

		return $expiry;
	}


	function getLatestVersion() {
		return $this->getKeyData( "latestversion" );
	}


	function getRequiresUpdates() {
		return $this->getKeyData( "requiresupdates" ) ? true : false;
	}


	function checkOwnedUpdates() {
		if (!$this->getRequiresUpdates()) {
			return true;
		}

		foreach ($this->getKeyData( "addons" ) as $addon) {

			if (( $addon["name"] == "Support and Updates" && $addon["status"] == "Active" )) {
				if ($this->getReleaseDate() < str_replace( "-", "", $addon["nextduedate"] )) {
					return true;
					continue;
				}

				continue;
			}
		}

		return false;
	}


	function getBrandingRemoval() {
		return true;
	}


	function getVersionHash() {
		return $this->version;
	}


	function debug($msg) {
		$this->debuglog[] = "" . $msg . "<br />";
	}


}


?>
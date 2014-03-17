<?php
class psafe3 {
	private $file; 
	private $salt;
	private $iterations = 0;
	private $strechedpw;
	private $shaps;
	private $b1;
	private $b2;
	private $b3;
	private $b4;
	private $keyk;
	private $keyl;
	private $iv;
	private $headers = [];
	private $recors = [];

	function __construct($file, $pass) {
		$this->file = fopen($file, "r");
		$tag = $this->readBytes(4);
		if($tag != "PWS3")
			exit("Not a valid Password Safe database");
		$this->salt = $this->readBits(256);
		$this->iterations = $this->readBits(32);
		$this->iterations = $this->unpackLittleEndian($this->iterations);
		$this->shaps = $this->strechedpw = $this->stretchpw($pass);
		$this->shaps = $this->sha256($this->shaps);
		$fileshaps = $this->readBytes(32);
		if($fileshaps != $this->shaps)
			exit("Wrong password inputted");
		$this->b1 = $this->readBits(128);
		$this->b2 = $this->readBits(128);
		$this->b3 = $this->readBits(128);
		$this->b4 = $this->readBits(128);
		$this->keyk = $this->twofish($this->strechedpw, $this->b1).$this->twofish($this->strechedpw, $this->b2);
		$this->keyl = $this->twofish($this->strechedpw, $this->b3).$this->twofish($this->strechedpw, $this->b4);
		$this->iv = $this->readBytes(16);
		while(1) {
			$field = $this->readField("header");
			$this->header[] = $field;
			if(!$field)
				break;
			if($field["type"] == 0xff)
				break;
		}
		$record = [];
		while(1) {
			$field = $this->readField();
			if(!$field)
				break;
			if($field["type"] == 0xff) {
				$this->records[] = $record;
				$record = [];
			} else {
				switch($field["type"]) {
					case 0x01: 
						$field["type"] = "UUID";
						$field["raw"] = unpack("H*", $field["raw"]);
						$field["raw"] = $field["raw"][1];
					break;
					case 0x02:
						$field["type"] = "Group";
					break;
					case 0x03:
						$field["type"] = "Title";
					break;
					case 0x04:
						$field["type"] = "Username";
					break;
					case 0x05:
						$field["type"] = "Notes";
					break;
					case 0x06:
						$field["type"] = "Password";
					break;
					case 0x07:
						$field["type"] = "Creation Time";
						$field["raw"] = $this->unLEDate($field["raw"]);
					break;
					case 0x08:
						$field["type"] = "Password Modification Time";
						$field["raw"] = $this->unLEDate($field["raw"]);
					break;
					case 0x09:
						$field["type"] = "Last Access Time";
						$field["raw"] = $this->unLEDate($field["raw"]);
					break;
					case 0x0a:
						$field["type"] = "Password Expire Time";
						$field["raw"] = $this->unLEDate($field["raw"]);
					break;
					case 0x0b:
						$field["type"] = "**RESERVED**";
					break;
					case 0x0c: 
						$field["type"] = "Last Modification Time";
						$field["raw"] = $this->unLEDate($field["raw"]);
					break;
					case 0x0d:
						$field["type"] = "URL";
					break;
					case 0x0e:
						$field["type"] = "Autotype";
					break;
					case 0x0f:
						$field["type"] = "Password history";
					break;
					case 0x10:
						$field["type"] = "Password policy";
						$field["raw"] = $this->unpackLittleEndian(substr($field["raw"], 0, 4));
					break;
					case 0x11:
						$field["type"] = "Password Expire Policy";
						$field["raw"] = $this->unpackLittleEndian($field["raw"]);
					break;
				}
				$record[$field["type"]] = $field["raw"];
			}
		}
	}
	/* unpackLittleEndianDate */
	function unLEDate($content) {
		return date("Y-m-d H:i:s", $this->unpackLittleEndian($content));
	}

	function unpackLittleEndian($content) {
		$content = unpack("L<", $content);
		return $content["<"];
	}

	function readBytes($bytes) {
		return fread($this->file, $bytes);
	}
	function readBits($bits) {
		return fread($this->file, $this->bitToByte($bits));
	}

	function sha256($string) { 
		return hash("sha256", $string, true); 
	}
	function hmacsha256($string, $key) { 
		return hash_hmac("sha256", $string, $key, true);
	}
	function bitToByte($n) { 
		return $n / 8;
	}
	function twofish($key, $data) { 
		return mcrypt_decrypt(MCRYPT_TWOFISH, $key, $data, "ecb"); 
	}
	function cipher($key, $data, $iv) { 
		return mcrypt_decrypt(MCRYPT_TWOFISH, $key, $data, "cbc", $iv); 
	}
	function decrypt($data) {
		$d = $this->cipher($this->keyk, $data, $this->iv);
		$this->iv = $data;
		return $d;
	}
	function stretchpw($string) {
		$stretched = $this->sha256($string.$this->salt);
		for($i = 0; $i < $this->iterations; $i++)
			$stretched = $this->sha256($stretched);
		return $stretched;
	}
	function readField($header = "") {
		$data = $this->readBytes(16);
		if(!$data || strlen($data) < 16)
			exit("Error parsing field");
		if($data == "PWS3-EOFPWS3-EOF") // EOF
			return 0;
		$data = $this->decrypt($data);
		$len = $this->unpackLittleEndian(substr($data, 0, 4));
		$type = unpack("C", substr($data, 4, 1));
		$type = $type[1];
		$raw = substr($data, 5);
		if($len > 11) {
			$step = (int)(($len + 4) / 16);
			for($i = 0; $i < $step; $i++) {
				$data = $this->readBytes(16);
				if(!$data || strlen($data) < 16)
					exit("Error parsing field");
				$raw .= $this->decrypt($data);
			}
		}
		$raw = substr($raw, 0, $len);
		return ["type" => $type, "raw" => $raw];
	}	
}

<?php
/**
 * SQL INJECTION KILLER
 * =====================
 *
 * SQL Injection is top second vulnerable of software, website
 *
 * SQLSafe is a lightweight PHP class for detecting malicious query (SQL Injection)
 * It uses the filter technique to detect whether a parameter is DANGEROUS to process
 *
 * @author      Current authors: Tong Vuu <tongvuu@gmail.com>
 *                               SilverWolf <silverwolf@ceh.vn>
 *
 *
 * @license     Code and contributions have 'MIT License'
 * 
 *
 * @link        Homepage:     http://evildragon.info OR http://ceh.vn
 *
 * @version     1.0.1.2
 */
class sqlsafe
{
	private 		$requestdb;
	private 		$typedb;
	private 		$textFilter;
	private 		$saveHR;
	private 		$protectionMode;
	private 		$redirectPage;

	private static 	$instance;

	protected	function	__construct()
	{
		$this->typedb = array("num" => "verifyNumber",
				"date"=>"verifyDate",
				"text" => "verifyText" , 
				"rnum" => "verifyRealNumber" , 
				"unknown" => "acceptArg");
		$this->requestdb = array('id' => "num" );
		$this->textFilter = array('union','concat','schema','columns','table','hex','unhex');
		$this->saveHR = true;
		$this->protectionMode = true;
		$this->redirectPage = "http://ledsieure.com";
	}
	public static function getInstance()
    {
        if (null === static::$instance) {
            static::$instance = new sqlsafe();
        }
        
        return static::$instance;
    }

    public function verifyParam($arg,$val)
    {
    	if(!$this->protectionMode)
    	{
    		$this->logHighRisk($arg,$val);
    		return $this->{$this->typedb["unknown"]}($val);
    	}

    	$type = $this->detectArgumentType($arg);
    	if(array_key_exists($type, $this->typedb))
    	{
    		$ret = $this->{$this->typedb[$type]}($val);
    		if(!$ret)
    		{
    			/* Hight risk detected */
    			$this->logHighRisk($arg,$val);
    			return false;
    		}
    		return true;
    	}
    	else
    	{
    		/* It is dangerous here. There is one argument not check */	
    		$this->logHighRisk($arg,$val);
    		return true;
    	}
    	
    }

    public function killIfNotSafe()
    {
    	foreach ($_REQUEST as $key => $value) 
		{
			if(!$this->verifyParam(strtolower ($key),strtolower ($value)))
			{
				header("Location: ".$this->redirectPage);
				die("");
			}
		}
    }

    private function detectArgumentType($arg)
    {
    	if(!array_key_exists($arg,$this->requestdb))
    		return $this->typedb[count($this->typedb) - 1];
    	else
    		return $this->requestdb[$arg];
    }

    private function verifyNumber($val)
    {
    	$pattern='/(\d+)/';
		$success = preg_match($pattern, $val, $match);
		if($success)
		{
			if(strlen($match[1]) != strlen($val))
				return false;
			else
				return true;
		}
		return false;
    }
    private function verifyRealNumber($val)
    {
    	$pattern='/(\d+).(\d+)/';
		$success = preg_match($pattern, $val, $match);
		if($success)
		{
			if(strlen($match[1].$match[2]) != strlen($val))
				return false;
			else
				return true;
		}
		return false;
    }
    private function verifyDate($val)
    {
    	/* This check not 100% correct */
		if(strlen($val) > 10)
			return false;
		else
			return true;
	}
    private function verifyText($val)
    {
    	for($i = 0; $i < count($this->textFilter); $i++)
		{
			if(stristr($val,$this->textFilter[$i]) !== FALSE)
				return false;
		}
		return true;
    }
    private function acceptArg($val)
    {
    	return true;
    }
    private function logHighRisk($arg,$val)
    {
    	if($this->saveHR)
    	{
    		$report_template = "-----------\nDATE\nIP\nURI\nARG = VAL\n";
	    	$report_template = str_replace("DATE", date("d/m/Y"), $report_template);
	    	$report_template = str_replace("URI", $_SERVER['REQUEST_URI'], $report_template);
	    	$report_template = str_replace("IP", $_SERVER['REMOTE_ADDR'], $report_template);
	    	$report_template = str_replace("ARG", $arg, $report_template);
	    	$report_template = str_replace("VAL", $val, $report_template);
	    	$f = fopen("highrisk.log","a+");
	    	fwrite($f, $report_template);
	    	fclose($f);
    	}
    	
    }

}

?>
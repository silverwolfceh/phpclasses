<?php
/**
 * SQL SAFE TEST
 * =====================
 *
 * @author      Current authors: Tong Vuu <tongvuu@gmail.com>
 *                               SilverWolf <silverwolf@ceh.vn>
 *
 * @link        Github:     https://github.com/silverwolfceh/phpclasses/sqlsafe_test.php
 *
 * @version     1.0.0.0
 *
 * =====================
 * HOW TO USE
 * 1. Upload sqlsafe.php and this file to a host
 * 2. Access sqlsafe_test.php?id=(number|text|sql injection|real number....) 
 *			to check that only number are accept
 */


require_once("sqlsafe.php");

sqlsafe::getInstance()->killIfNotSafe();

?>
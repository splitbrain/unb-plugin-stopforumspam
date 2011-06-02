<?php
/*
Name:     Stop Forum Spam UNB Plugin
Purpose:  Check new user registration against the API at http://www.stopforumspam.com
Version:  2011-06-02
Author:   Andreas Gohr <andi@splitbrain.org>
*/
if (!defined('UNB_RUNNING')) die('Not a UNB environment in ' . basename(__FILE__));

// Define plug-in meta-data
UnbPluginMeta('Check new user registration against the API at stopforumspam.com');
UnbPluginMeta('Andreas Gohr <andi@splitbrain.org>', 'author');
UnbPluginMeta('en', 'lang');
UnbPluginMeta('unb.devel.20110527', 'version');
UnbPluginMeta('plugin_stopforumspam_config', 'config');

if (!UnbPluginEnabled()) return;


function plugin_stopforumspam_rc($opt,$default=null){
    $val = rc($opt);
    if($val !== false && $val !== null) return $val;
    return $default;
}

function plugin_stopforumspam_config(&$data) {
    global $UNB;

    // setup config fields
    if ($data['request'] == 'fields') {
        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'sfs_email_days',
            'fieldvalue'  => plugin_stopforumspam_rc('sfs_email_days',30),
            'fieldlabel'  => 'stopforumspam config email days label',
            'fielddesc'   => 'stopforumspam config email days desc',
            'fieldsize'   => 3,
            'fieldlength' => 3,
        );
        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'sfs_email_freq',
            'fieldvalue'  => plugin_stopforumspam_rc('sfs_email_freq',1),
            'fieldlabel'  => 'stopforumspam config email freq label',
            'fielddesc'   => 'stopforumspam config email freq desc',
            'fieldsize'   => 3,
            'fieldlength' => 3,
        );

        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'sfs_ip_days',
            'fieldvalue'  => plugin_stopforumspam_rc('sfs_ip_days',30),
            'fieldlabel'  => 'stopforumspam config ip days label',
            'fielddesc'   => 'stopforumspam config ip days desc',
            'fieldsize'   => 3,
            'fieldlength' => 3,
        );
        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'sfs_ip_freq',
            'fieldvalue'  => plugin_stopforumspam_rc('sfs_ip_freq',1),
            'fieldlabel'  => 'stopforumspam config ip freq label',
            'fielddesc'   => 'stopforumspam config ip freq desc',
            'fieldsize'   => 3,
            'fieldlength' => 3,
        );

        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'sfs_user_days',
            'fieldvalue'  => plugin_stopforumspam_rc('sfs_user_days',30),
            'fieldlabel'  => 'stopforumspam config user days label',
            'fielddesc'   => 'stopforumspam config user days desc',
            'fieldsize'   => 3,
            'fieldlength' => 3,
        );
        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'sfs_user_freq',
            'fieldvalue'  => plugin_stopforumspam_rc('sfs_user_freq',1),
            'fieldlabel'  => 'stopforumspam config user freq label',
            'fielddesc'   => 'stopforumspam config user freq desc',
            'fieldsize'   => 3,
            'fieldlength' => 3,
        );

    }

    // save config data
    if ($data['request'] == 'handleform') {
        $UNB['ConfigFile']['sfs_email_days'] = (int) $_POST['sfs_email_days'];
        $UNB['ConfigFile']['sfs_email_freq'] = (int) $_POST['sfs_email_freq'];
        $UNB['ConfigFile']['sfs_ip_days'] = (int) $_POST['sfs_ip_days'];
        $UNB['ConfigFile']['sfs_ip_freq'] = (int) $_POST['sfs_ip_freq'];
        $UNB['ConfigFile']['sfs_user_days'] = (int) $_POST['sfs_user_days'];
        $UNB['ConfigFile']['sfs_user_freq'] = (int) $_POST['sfs_user_freq'];

        $data['result'] = true;
    }

    return true;
}

function plugin_stopforumspam_hook(&$data) {
    global $UNB;

    $query  = 'http://www.stopforumspam.com/api';
    $query .= '?ip='.rawurlencode($_SERVER['REMOTE_ADDR']);
    $query .= '&email='.rawurlencode($data['email']);
    $query .= '&username='.rawurlencode($data['username']);
    $query .= '&unix=1';
    $query .= '&f=serial';

    $resp = @file_get_contents($query);
    //check if something went wrong with the AP
    if($resp){
        $resp = unserialize($resp);
    }else{
        return;
    }
    if(!$resp['success']) return;

    // check email
    if($resp['email']['lastseen'] >= (time()-(60*60*24*plugin_stopforumspam_rc('sfs_email_days',30))) &&
       $resp['email']['frequency'] >= plugin_stopforumspam_rc('sfs_email_freq',1) ){

        UnbAddLog('stopforumspam: user registration blocked by email: '.$data['email']);
        $data['error'] = 'Sorry, you seem to be a spammer.';
        return;
    }

    // check username
    if($resp['username']['lastseen'] >= (time()-(60*60*24*plugin_stopforumspam_rc('sfs_user_days',30))) &&
       $resp['username']['frequency'] >= plugin_stopforumspam_rc('sfs_user_freq',1) ){

        UnbAddLog('stopforumspam: user registration blocked by username: '.$data['username']);
        $data['error'] = 'Sorry, you seem to be a spammer.';
        return;
    }

    // check ip address
    if($resp['ip']['lastseen'] >= (time()-(60*60*24*plugin_stopforumspam_rc('sfs_ip_days',30))) &&
       $resp['ip']['frequency'] >= plugin_stopforumspam_rc('sfs_ip_freq',1) ){

        UnbAddLog('stopforumspam: user registration blocked by ip: '.$_SERVER['REMOTE_ADDR']);
        $data['error'] = 'Sorry, you seem to be a spammer.';
        return;
    }
}

// Register hook functions
UnbRegisterHook('user.verifyregister', 'plugin_stopforumspam_hook');


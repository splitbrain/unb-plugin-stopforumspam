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

if (!UnbPluginEnabled()) return;

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

    // only consider data of last 30 days
    $tresh = time() - 60*60*24*30;


    if($resp['email']['lastseen'] > $tresh){
        UnbAddLog('stopforumspam: user registration blocked by email: '.$data['email']);
        $data['error'] = 'Sorry, you seem to be a spammer.';
        return;
    }

    if($resp['username']['lastseen'] > $tresh){
        UnbAddLog('stopforumspam: user registration blocked by username: '.$data['username']);
        $data['error'] = 'Sorry, you seem to be a spammer.';
        return;
    }

    if($resp['ip']['lastseen'] > $tresh){
        UnbAddLog('stopforumspam: user registration blocked by ip: '.$data['ip']);
        $data['error'] = 'Sorry, you seem to be a spammer.';
        return;
    }
}

// Register hook functions
UnbRegisterHook('user.verifyregister', 'plugin_stopforumspam_hook');


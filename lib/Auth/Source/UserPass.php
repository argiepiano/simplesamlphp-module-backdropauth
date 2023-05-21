<?php

/**
 * Backdrop authentication source for simpleSAMLphp
 *
 * Copyright SIL International, Steve Moitozo, <steve_moitozo@sil.org>, http://www.sil.org 
 *
 * This class is a Drupal authentication source which authenticates users
 * against a Drupal site located on the same server.
 *
 * This project is a port of drupalauth found at: 
 * https://github.com/drupalauth/simplesamlphp-module-drupalauth
 *
 * !!! NOTE WELL !!!
 *
 * You must configure store.type in config/config.php to be something
 * other than phpsession, or this module will not work. SQL and memcache
 * work just fine. The tell tail sign of the problem is infinite browser
 * redirection when the SimpleSAMLphp login page should be presented.
 *
 * -------------------------------------------------------------------
 *
 * To use this put something like this into config/authsources.php:
 *	
 * 	'backdrop-userpass' => array(
 * 		'backdropauth:UserPass',
 * 
 * 		// The filesystem path of the Backdrop directory.
 * 		'backdroproot' => '/var/www/backdrop-1.0.0',
 * 
 * 		// Whether to turn on debug
 * 		'debug' => true,
 * 
 * 		// Which attributes should be retrieved from the Backdrop site.				     
 * 				     
 *              'attributes' => array(
 *                                    array('backdropuservar'   => 'uid',  'callit' => 'uid'),
 *                                     array('backdropuservar' => 'name', 'callit' => 'cn'),
 *                                     array('backdropuservar' => 'mail', 'callit' => 'mail'),
 *                                     array('backdropuservar' => 'field_first_name',  'callit' => 'givenName'),
 *                                     array('backdropuservar' => 'field_last_name',   'callit' => 'sn'),
 *                                     array('backdropuservar' => 'field_organization','callit' => 'ou'),
 *                                     array('backdropuservar' => 'roles','callit' => 'roles'),
 *                                   ),
 * 	),
 * 
 * Format of the 'attributes' array explained:
 *
 * 'attributes' can be an associate array of attribute names, or NULL, in which case
 * all attributes are fetched.
 * 
 * If you want everything (except) the password hash do this:
 *  	'attributes' => NULL,
 *
 * If you want to pick and choose do it like this:
 * 'attributes' => array(
 * 		      array('backdropuservar' => 'uid',  'callit' => 'uid),
 *                     array('backdropuservar' => 'name', 'callit' => 'cn'),
 *                     array('backdropuservar' => 'mail', 'callit' => 'mail'),
 *                     array('backdropuservar' => 'roles','callit' => 'roles'),
 *                      ),
 * 
 *  The value for 'backdropuservar' is the variable name for the attribute in the 
 *  Backdrop user object.
 * 
 *  The value for 'callit' is the name you want the attribute to have when it's
 *  returned after authentication. You can use the same value in both or you can
 *  customize by putting something different in for 'callit'. For an example,
 *  look at the entry for name above.
 *
 *
 * @author Steve Moitozo <steve_moitozo@sil.org>, SIL International
 * @package backdropauth
 * @version $Id$
 */
class sspmod_backdropauth_Auth_Source_UserPass extends \SimpleSAML\Module\core\Auth\UserPassBase {

	/**
	 * Whether to turn on debugging
	 */
	private $debug;

	/**
	 * The Backdrop installation directory
	 */
	private $backdroproot;

	/**
	 * The Backdrop user attributes to use, NULL means use all available
	 */
	private $attributes;


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert(is_array($info));
		assert(is_array($config));

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);
		
		/* Get the configuration for this module */	
		$backdropAuthConfig = new sspmod_backdropauth_ConfigHelper($config,
			'Authentication source ' . var_export($this->authId, TRUE));

		$this->debug      = $backdropAuthConfig->getDebug();
		$this->attributes = $backdropAuthConfig->getAttributes();

    if (!defined('BACKDROP_ROOT')) {
      define('BACKDROP_ROOT', $backdropAuthConfig->getBackdroproot());
      /* Include the Backdrop bootstrap */
      require_once(BACKDROP_ROOT.'/core/includes/bootstrap.inc');
      require_once(BACKDROP_ROOT.'/core/includes/file.inc');

      // Fool the bootstrap process to think we are calling it from root.
      $current_dir = getcwd();
      chdir(BACKDROP_ROOT);

      /* Using BACKDROP_BOOTSTRAP_FULL means that SimpleSAMLphp must use an session storage
      * mechanism other than phpsession (see: store.type in config.php). However, this trade-off
      * prevents the need for hackery here and makes this module work better in different environments.
      */
      backdrop_bootstrap(BACKDROP_BOOTSTRAP_FULL);
      
      // we need to be able to call Backdrop user function so we load some required modules
      backdrop_load('module', 'system');
      backdrop_load('module', 'user');
      backdrop_load('module', 'field');

      chdir($current_dir);
    }
	}


	/**
	 * Attempt to log in using the given username and password.
	 *
	 * On a successful login, this function should return the users attributes. On failure,
	 * it should throw an exception. If the error was caused by the user entering the wrong
	 * username or password, a \SimpleSAML\Error_Error('WRONGUSERPASS') should be thrown.
	 *
	 * Note that both the username and the password are UTF-8 encoded.
	 *
	 * @param string $username  The username the user wrote.
	 * @param string $password  The password the user wrote.
	 * @return array  Associative array with the users attributes.
	 */
	protected function login($username, $password) {
		assert(is_string($username));
		assert(is_string($password));

    // Fool Backdrop to think we are calling it from root.
    $current_dir = getcwd();
    chdir(BACKDROP_ROOT);

		// authenticate the user
		$backdropuid = user_authenticate($username, $password);
		if(0 == $backdropuid){
			throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
		}

		// load the user object from Backdrop
		$backdropuser = user_load($backdropuid);

		// get all the attributes out of the user object
		$userAttrs = get_object_vars($backdropuser);
		
		// define some variables to use as arrays
		$userAttrNames = null;
		$attributes    = null;
		
		// figure out which attributes to include
		if(NULL == $this->attributes){
		   $userKeys = array_keys($userAttrs);
		   
		   // populate the attribute naming array
		   foreach($userKeys as $userKey){
		      $userAttrNames[$userKey] = $userKey;
		   }
		   
		}else{
		   // populate the array of attribute keys
		   // populate the attribute naming array
		   foreach($this->attributes as $confAttr){
		   
		      $userKeys[] = $confAttr['backdropuservar'];
		      $userAttrNames[$confAttr['backdropuservar']] = $confAttr['callit'];
		   
		   }
		   
		}
		   
		// an array of the keys that should never be included
		// (e.g., pass)
		$skipKeys = array('pass');

		// package up the user attributes	
		foreach($userKeys as $userKey){

		  // skip any keys that should never be included
		  if(!in_array($userKey, $skipKeys)){

		    if(   is_string($userAttrs[$userKey]) 
		       || is_numeric($userAttrs[$userKey])
		       || is_bool($userAttrs[$userKey])    ){

		       $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]);

		    }elseif(is_array($userAttrs[$userKey])){

		       // if the field is a field module field, special handling is required
		       if(substr($userKey,0,6) == 'field_'){
		          $attributes[$userAttrNames[$userKey]] = array($userAttrs[$userKey]['und'][0]['safe_value']);
		       }else{
		       // otherwise treat it like a normal array
		          $attributes[$userAttrNames[$userKey]] = $userAttrs[$userKey];
		       }
		    }

		  }
		}
    chdir($current_dir);
		return $attributes;
	}

}

?>

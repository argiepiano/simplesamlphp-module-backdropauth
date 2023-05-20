<?php

/**
 * Backdrop authentication source configuration parser.
 * 
 * This project is a port of drupalauth found at: 
 * https://github.com/drupalauth/simplesamlphp-module-drupalauth
 *
 * Copyright SIL International, Steve Moitozo, <steve_moitozo@sil.org>, http://www.sil.org 
 *
 * This class is a Backdrop authentication source which authenticates users
 * against a Backdrop site located on the same server.
 *
 * See the backdropauth-entry in config-templates/authsources.php for information about
 * configuration of these options.
 *
 * @author Steve Moitozo <steve_moitozo@sil.org>, SIL International
 * @package backdropauth
 * @version $Id$
 */
class sspmod_backdropauth_ConfigHelper {


	/**
	 * String with the location of this configuration.
	 * Used for error reporting.
	 */
	private $location;


	/**
	 * The filesystem path to the Drupal directory
	 */
	private $backdroproot;


	/**
	 * Whether debug output is enabled.
	 *
	 * @var bool
	 */
	private $debug;


  /**
   * The attributes we should fetch. Can be NULL in which case we will fetch all attributes.
   */
  private $attributes;


  /**
   * The name of the cookie
   */
  private $cookie_name;


  /**
   * The Drupal logout URL
   */
  private $backdrop_logout_url;


  /**
   * The Drupal login URL
   */
  private $backdrop_login_url;


	/**
	 * Constructor for this configuration parser.
	 *
	 * @param array $config  Configuration.
	 * @param string $location  The location of this configuration. Used for error reporting.
	 */
	public function __construct($config, $location) {
		assert('is_array($config)');
		assert('is_string($location)');

		$this->location = $location;

		/* Parse configuration. */
		$config = \SimpleSAML\Configuration::loadFromArray($config, $location);

		$this->backdroproot = $config->getString('backdroproot');
		$this->debug = $config->getBoolean('debug', FALSE);
    $this->attributes = $config->getArray('attributes', NULL);
    $this->cookie_name = $config->getString('cookie_name', 'backdropauth4ssp');
    $this->backdrop_logout_url = $config->getString('backdrop_logout_url', NULL);
    $this->backdrop_login_url = $config->getString('backdrop_login_url', NULL);

	}
	

	/**
	 * Return the debug
	 *
	 * @param boolean $debug whether or not debugging should be turned on
	 */
	public function getDebug() {
	   return $this->debug; 
	}

	/**
	 * Return the drupaldir
	 *
	 * @param string $backdroproot the directory of the Drupal site
	 */
	public function getBackdroproot() {
	   return $this->backdroproot; 
	}

  /**
   * Return the attributes
   *
   * @param array $attributes the array of Drupal attributes to use, NULL means use all available attributes
   */
  public function getAttributes() {
     return $this->attributes;
  }

  /**
   * Return the cookie name
   *
   * @param array $cookie_name the name of the cookie
   */
  public function getCookieName() {
     return $this->cookie_name;
  }

  /**
   * Return the Drupal logout URL
   *
   * @param array $backdrop_logout_url the URL of the Drupal logout page
   */
  public function getBackdropLogoutURL() {
     return $this->backdrop_logout_url;
  }

  /**
   * Return the Drupal login URL
   *
   * @param array $backdrop_login_url the URL of the Drupal login page
   */
  public function getBackdropLoginURL() {
     return $this->backdrop_login_url;
  }

}

## Introduction

Backdrop + SimpleSAMLphp + backdropauth = Complete SAML Identity Provider (IdP)

Users interact with Backdrop to create accounts, manage accounts, and authenticate. SAML SPs interact with [SimpleSAMLphp](https://simplesamlphp.org/). Backdropauth ties Backdrop to SimpleSAMLphp.

The backdropauth module for simpleSAMLphp makes it easy to create a SAML or Shibboleth identity provider (IdP) by enabling authentication of users against a Backdrop CMS site on the same server. This allows the administrator to leverage the user management and integration capabilities of [Backdrop CMS](http://backdropcms.org) for managing the identity life cycle.

NOTE: This is software establishes a SAML identity provider (IdP) using Backdrop as the user database instead of LDAP. If you want to establish your Backdrop site as a SAML service provider (SP) connected to a SAML or Shibboleth IdP, see the [simplesamlphp_auth](https://github.com/backdrop-contrib/simplesamlphp_auth) module for Backdrop CMS.

### backdropauth SimpleSAMLphp module

This module **for SimpleSAMLphp** provides an Authentication Source for authenticating users against a local Backdrop CMS site. This allows the administrator to leverage the user management and integration capabilities of Backdrop for managing the identity life cycle and the power of SimpleSAMLphp for identity integration. This is a simpleSAMLphp module, NOT a Backdrop module.
Download and enable simpleSAMLmodule only if case if you want to use Backdrop as Identity Provider.

### Backdrop CMS modules
If you want to use Backdrop as Identity Provide you should also install [backdropauth4ssp](https://github.com/backdrop-contrib/backdropauth4ssp). Please note that all issues related to Backdrop functionality should be reported there.

If you want to connect your Backdrop site as Service Provider to a SAML or Shibboleth IdP, use the [simplesamlphp_auth](github.com/backdrop-contrib/simplesamlphp_auth) module for Backdrop.

## Installation

### Reqirements
1. Install Backdrop 1.x
2. Install simpleSAMLphp 
3. Configure SimpleSAMLphp to use something other than `phpsession` for session storage, e.g., SQL or memcache (See: `store.type` in `simplesamlphp/config/config.php`).
4. Download backdropauth (this module) and unpack backdropauth
5. Move the backdropauth module directory into `simplesamlphp/modules` directory and rename as `backdropauth`
6. Configure the authentication source in `simplesamlphp/config/authsources.php` as described below.

### SimpleSAMLphp example configuration
For an example configuration, check the wiki pages for the [backdropauth4ssp](https://github.com/backdrop-contrib/backdropauth4ssp) module.

### Additional configurations: Authenticate against Backdrop and use the Backdrop login page

The advantage of this approach is that the SimpleSAMLphp IdP session is tied to a Backdrop session. This allows the user who is already logged into the Backdrop site to then navigate to a SAML SP that uses the IdP without the need to authenticate again.

**Details**

Configure the authentication source by putting following code into `simplesamlphp/config/authsources.php`

```php
'backdrop-userpass' => array('backdropauth:External',

  // The filesystem path of the Backdrop directory.
  'backdroproot' => '/var/www/backdrop',

  // Whether to turn on debug
  'debug' => true,

  // the URL of the Backdrop logout page
  'backdrop_logout_url' => 'https://www.example.com/user/logout',

  // the URL of the Backdrop login page
  'backdrop_login_url' => 'https://www.example.com/user/login',

  // The domain of the cookie that contains the uid of the logged in use.
  // This can only be set to the domain of the IdP site, or to a subdomain. 
  // Modern browsers will not allow setting this to a domain different from
  // If left empty, the domain name of the IdP site will be used.
  // the current one, or a subdomain of itself. Valid domains for an idp site
  // hosted at https://example.com are:
  // 'cookie_domain' => 'example.com', OR
  // 'cookie_domain' => '.example.com' // for all subdomains.

  // The name of the cookie. This cookie is used to provide the uid to the 
  // SP site. Default: backdropauth5ssp. 
  // 'cookie_name' => 'backdropauth5ssp',

  // Which attributes should be retrieved from the Backdrop site.
  'attributes' => array(
    array('backdropuservar'   => 'uid',  'callit' => 'uid'),
    array('backdropuservar' => 'name', 'callit' => 'cn'),
    array('backdropuservar' => 'mail', 'callit' => 'mail'),
    array('backdropuservar' => 'field_first_name',  'callit' => 'givenName'),
    array('backdropuservar' => 'field_last_name',   'callit' => 'sn'),
    array('backdropuservar' => 'field_organization','callit' => 'ou'),
    array('backdropuservar' => 'roles','callit' => 'roles'),
  ),
),
```

### Authenticate against Backdrop but use the SimpleSAMLphp login page

The advantage of this approach is that their is no obvious connection between SimpleSAMLphp IdP and the Backdrop site.

**Details**

Configure the authentication source by putting following code into `simplesamlphp/config/authsources.php`

```php
'backdrop-userpass' => array('backdropauth:UserPass',

    // The filesystem path of the Backdrop directory.
    'backdroproot' => '/home/backdrop',            

    // Whether to turn on debug
    'debug' => true,

    // Which attributes should be retrieved from the Backdrop site.
    // This can be an associate array of attribute names, or NULL, in which case
    // all attributes are fetched.
    //
    // If you want everything (except) the password hash do this:
    //      'attributes' => NULL,
    //
    // If you want to pick and choose do it like this:
    //'attributes' => array(
    //                    array('backdropuservar'   => 'uid',  'callit' => 'uid'),
    //                      array('backdropuservar' => 'name', 'callit' => 'cn'),
    //                      array('backdropuservar' => 'mail', 'callit' => 'mail'),
    //                      array('backdropuservar' => 'field_first_name',  'callit' => 'givenName'),
    //                      array('backdropuservar' => 'field_last_name',   'callit' => 'sn'),
    //                      array('backdropuservar' => 'field_organization','callit' => 'ou'),
    //                      array('backdropuservar' => 'roles','callit' => 'roles'),
    //                     ),
    //
    // The value for 'backdropuservar' is the variable name for the attribute in the
    // Backdrop user object.
    //
    // The value for 'callit' is the name you want the attribute to have when it's
    // returned after authentication. You can use the same value in both or you can
    // customize by putting something different in for 'callit'. For an example,
    // look at uid and name above.
    'attributes' => array(
      array('backdropuservar'   => 'uid',  'callit' => 'uid'),
      array('backdropuservar' => 'name', 'callit' => 'cn'),
      array('backdropuservar' => 'mail', 'callit' => 'mail'),
      array('backdropuservar' => 'field_first_name',  'callit' => 'givenName'),
      array('backdropuservar' => 'field_last_name',   'callit' => 'sn'),
      array('backdropuservar' => 'field_organization','callit' => 'ou'),
      array('backdropuservar' => 'roles','callit' => 'roles'),
  ),
),
```

## Credits
This is a Backdrop CMS ported version of a project originally created for Backdrop 7, which is currently available at https://github.com/drupalauth/simplesamlphp-module-drupalauth

Originally written by Steve Moitozo steve_moitozo@sil.org

This ported version is based on the 1.7.x branch of that original project. The commit history of that branch has been preserved here. We are very thankful to all past contributors to the Backdrop branch that have made this port possible. 

- Ported by [argiepiano](https://github.com/argiepiano)

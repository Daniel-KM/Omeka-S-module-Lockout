Limit Login Attempts (module for Omeka S)
=========================================

[Limit Login Attempts] is a module for [Omeka S] that limit rate of login
attempts, including by way of cookies, for each IP. it is fully customizable.

This module is a full rewrite of a [plugin for WordPress], create by Johan Eenfeldt (johanee).


Description
-----------

Limit the number of login attempts possible both through normal login as well as
using auth cookies.

By default Omeka S allows unlimited login attempts either through the login
page or by sending special cookies. This allows passwords (or hashes) to be
brute-force cracked with relative ease.

Limit Login Attempts blocks an Internet address from making further attempts
after a specified limit on retries is reached, making a brute-force attack
difficult or impossible.

## Features

* Limit the number of retry attempts when logging in (for each IP). Fully
  customizable
* Limit the number of attempts to log in using auth cookies in same way
* Informs user about remaining retries or lockout time on login page
* Optional logging, optional email notification
* Handles server behind reverse proxy
* It is possible to whitelist IPs using a filter. But you probably shouldn't. :-)

Translations: Bulgarian, Brazilian Portuguese, Catalan, Chinese (Traditional),
Czech, Dutch, Finnish, French, German, Hungarian, Norwegian, Persian, Romanian,
Russian, Spanish, Swedish, Turkish

The module uses standard actions and filters only.

## Screenshots

1. Loginscreen after failed login with retries remaining
2. Loginscreen during lockout
3. Administration interface in Omeka S


Installation
------------

Uncompress files in the module directory and rename module folder `LimitLoginAttempts`.

Then install it like any other Omeka module and follow the config instructions.

If your server is located behind a reverse proxy, make sure to set the option.


Frequently Asked Questions
--------------------------

## Why not reset failed attempts on a successful login?

This is very much by design. Otherwise you could brute force the "admin"
password by logging in as your own user every 4th attempt.

## What is this option about site connection and reverse proxy?

A reverse proxy is a server in between the site and the Internet (perhaps
handling caching or load-balancing). This makes getting the correct client IP to
block slightly more complicated.

The option default to NOT being behind a proxy -- which should be by far the
common case.

## How do I know if my site is behind a reverse proxy?

You probably are not or you would know. We show a pretty good guess on the
option page. Set the option using this unless you are sure you know better.

## Can I whitelist my IP so I don't get locked out?

First please consider if you really need this. Generally speaking it is not a
good idea to have exceptions to your security policies.

That said, there is now a filter which allows you to do it: "limit_login_whitelist_ip".

Example:
function my_ip_whitelist($allow, $ip) {
	 return ($ip == 'my-ip') ? true : $allow;
}
add_filter('limit_login_whitelist_ip', 'my_ip_whitelist', 10, 2);

Note that we still do notification and logging as usual. This is meant to allow
you to be aware of any suspicious activity from whitelisted IPs.

## I locked myself out testing this thing, what do I do?

Either wait, or:

If you know how to edit / add to PHP files you can use the IP whitelist
functionality described above. You should then use the "Restore Lockouts" button
on the module settings page and remove the whitelist function again.

If you have ftp / ssh access to the site, remove the folder of the module or
increase the version number in the `config/module.ini`, so it will deactivate it.

If you have access to the database (for example through phpMyAdmin) you can clear
the limit_login_lockouts option in the Omeka S `setting` table. The sql for a
standard install is: `UPDATE setting SET value = '' WHERE id = 'limit_login_lockouts';`


Warning
-------

Use it at your own risk.

It?s always recommended to backup your files and your databases and to check
your archives regularly so you can roll back if needed.


Troubleshooting
---------------

See online issues on the [module issues] page on GitHub.


License
-------

This module is published under the [GNU/GPL] license.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


Contacts
--------

* Daniel Berthereau (see [Daniel-KM] on GitHub)


Copyright
---------

* Copright Johan Eenfeldt, 2008-2012
* Copright Daniel Berthereau, 2017
* Translations: see the [WordPress page]

Thanks to Michael Skerwiderski for reverse proxy handling suggestions (WordPress).


[Limit Login Attempts]: https://github.com/Daniel-KM/Omeka-S-module-LimitLoginAttempts
[Omeka S]: https://omeka.org/s
[plugin for WordPress]: https://wordpress.org/plugins/limit-login-attempts
[module issues]: https://github.com/Daniel-KM/Omeka-S-module-LimitLoginAttempts/issues
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[WordPress page]: https://translate.wordpress.org/projects/wp-plugins/limit-login-attempts/contributors
[Daniel-KM]: https://github.com/Daniel-KM "Daniel Berthereau"

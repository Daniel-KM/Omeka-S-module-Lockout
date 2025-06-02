Lockout (module for Omeka S)
============================

> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better
> than the previous repository.__

[Lockout] is a module for [Omeka S] that limits the rate of login attempts for
each IP (not by auth cookie) in order to avoid brute-force attacks.

This module is a full rewrite of the plugin [Limit Login Attempts] for WordPress
created by Johan Eenfeldt (johanee).


Description
-----------

Limit the number of login attempts possible both through normal login.

By default Omeka S allows unlimited login attempts either through the login
page. This allows passwords (or hashes) to be brute-force cracked with relative
ease.

The module blocks an Internet address from making further attempts after a
specified limit on retries is reached, making a brute-force attack difficult or
impossible.

## Features

* Limit the number of retry attempts when logging in (for each IP)
* Fully customizable
* Informs user about remaining retries or lockout time on login page
* Optional logging and optional email notification
* Handles server behind reverse proxy
* It is possible to whitelist IPs, but you probably shouldn't. :-)

Translations: Bulgarian, Brazilian Portuguese, Catalan, Chinese (Traditional),
Czech, Dutch, Finnish, French, German, Hungarian, Norwegian, Persian, Romanian,
Russian, Spanish, Swedish, Turkish.

The module uses standard actions and filters only.

## Screenshots

1. Login screen after failed login with retries remaining.

  ![Login screen after failed login](https://gitlab.com/Daniel-KM/Omeka-S-module-Lockout/blob/master/data/readme/lockout_attempt.png)

2. Login screen during lockout.

  ![Login screen during lockout](https://gitlab.com/Daniel-KM/Omeka-S-module-Lockout/blob/master/data/readme/lockout_blocked.png)

3. Administration interface in Omeka S

  ![administration interface](https://gitlab.com/Daniel-KM/Omeka-S-module-Lockout/blob/master/data/readme/lockout_config.png)


Installation
------------

Uncompress files in the module directory and rename module folder `Lockout`.

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
the lockout_lockouts option in the Omeka S `setting` table. The sql for a
standard install is: `UPDATE setting SET value = '' WHERE id = 'lockout_lockouts';`
You can disable the module too: `UPDATE module SET is_active = 0 WHERE id = 'Lockout';`.


Warning
-------

Use it at your own risk.

It?s always recommended to backup your files and your databases and to check
your archives regularly so you can roll back if needed.


Troubleshooting
---------------

See online issues on the [module issues] page on GitLab.


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

* Daniel Berthereau (see [Daniel-KM] on GitLab)


Copyright
---------

* Copyright Johan Eenfeldt, 2008-2012
* Copyright Daniel Berthereau, 2017-2025
* Translations: see the [WordPress page]

Thanks to Michael Skerwiderski for reverse proxy handling suggestions (WordPress).


[Lockout]: https://gitlab.com/Daniel-KM/Omeka-S-module-Lockout
[Omeka S]: https://omeka.org/s
[Limit Login Attempts]: https://wordpress.org/plugins/limit-login-attempts
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-Lockout/-/issues
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[WordPress page]: https://translate.wordpress.org/projects/wp-plugins/limit-login-attempts/contributors
[GitLab]: https://gitlab.com/Daniel-KM
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"

Changelog
=========

= 3.2 =
Port for Omeka S. See commits for next logs.

= 1.7.1 =
This version fixes a security bug in version 1.6.2 and 1.7.0. Please upgrade immediately.

"Auth cookies" are special cookies set at login that authenticating you to the system. It is how WordPress "remembers" that you are logged in between page loads.

During lockout these are supposed to be cleared, but a change in 1.6.2 broke this. It allowed an attacker to keep trying to break these cookies during a lockout.

Lockout of normal password login attempts still worked as it should, and it appears that all "auth cookie" attempts would keep getting logged.

In theory the "auth cookie" is quite resistant to brute force attack. It contains a cryptographic hash of the user password, and the difficulty to break it is not based on the password strength but instead on the cryptographic operations used and the length of the hash value. In theory it should take many many years to break this hash. As theory and practice does not always agree it is still a good idea to have working lockouts of any such attempts.

= 1.7.0 =
* Added filter that allows whitelisting IP. Please use with care!!
* Update to Spanish translation, thanks to Marcelo Pedra
* Updated Swedish translation
* Tested against WordPress 3.3.2

= 1.6.2 =
* Fix bug where log would not get updated after it had been cleared
* Do plugin setup in 'init' action
* Small update to Spanish translation file, thanks to Marcelo Pedra
* Tested against WordPress 3.2.1

= 1.6.1 =
* (WordPress 3.0+) An invalid cookie can sometimes get sent multiple times before it gets cleared, resulting in multiple failed attempts or even a lockout from a single invalid cookie. Store the latest failed cookie to make sure we only count it as one failed attempt
* Define "Text Domain" correctly
* Include correct Dutch tranlation file. Thanks to Martin1 for noticing. Thanks again to Bjorn Wijers for the translation
* Updated POT file for this version
* Tested against WordPress 3.1-RC4

= 1.6.0 =
* Happy New Year
* Tested against WordPress 3.1-RC1
* Plugin now requires WordPress version 2.8+. Of course you should never ever use anything but the latest version
* Fixed deprecation warnings that had been piling up with the old version requirement. Thanks to Johannes Ruthenberg for the report that prompted this
* Removed auth cookie admin check for version 2.7.
* Make sure relevant values in $_COOKIE get cleared right away on auth cookie validation failure. There are still some problems with cookie auth handling. The lockout can trigger prematurely in rare cases, but fixing it is plugin version 2 stuff unfortunately.
* Changed default time for retries to reset from 24 hours to 12 hours. The security impact is very minor and it means the warning will disappear "overnight"
* Added question to FAQ ("Why not reset failed attempts on a successful login?")
* Updated screenshots

= 1.5.2 =
* Reverted minor cookie-handling cleanup which might somehow be responsible for recently reported cookie related lockouts
* Added version 1.x Brazilian Portuguese translation, thanks to Luciano Passuello
* Added Finnish translation, thanks to Ari Kontiainen

= 1.5.1 =
* Further multisite & WPMU support (again thanks to <erik@erikshosting.com>)
* Better error handling if option variables are damaged
* Added Traditional Chinese translation, thanks to Denny Huang <bigexplorations@bigexplorations.com.tw>

= 1.5 =
* Tested against WordPress 3.0
* Handle 3.0 login page failure "shake"
* Basic multisite support (parts thanks to <erik@erikshosting.com>)
* Added Dutch translation, thanks to Bjorn Wijers <burobjorn@burobjorn.nl>
* Added Hungarian translation, thanks to Bálint Vereskuti <balint@vereskuti.info>
* Added French translation, thanks to oVa <ova13lastar@gmail.com>

= 1.4.1 =
* Added Turkish translation, thanks to Yazan Canarkadas

= 1.4 =
* Protect admin page update using wp_nonce
* Added Czech translation, thanks to Jakub Jedelsky

= 1.3.2 =
* Added Bulgarian translation, thanks to Hristo Chakarov
* Added Norwegian translation, thanks to Rune Gulbrandsøy
* Added Spanish translation, thanks to Marcelo Pedra
* Added Persian translation, thanks to Mostafa Soufi
* Added Russian translation, thanks to Jack Leonid (http://studio-xl.com)

= 1.3.1 =
* Added Catalan translation, thanks to Robert Buj
* Added Romanian translation, thanks to Robert Tudor

= 1.3 =
* Support for getting the correct IP for clients while server is behind reverse proxy, thanks to Michael Skerwiderski
* Added German translation, thanks to Michael Skerwiderski

= 1.2 =
* No longer replaces pluggable function when cookie handling active. Re-implemented using available actions and filters
* Filter error messages during login to avoid information leak regarding available usernames
* Do not show retries or lockout messages except for login (registration, lost password pages). No change in actual enforcement
* Slightly more aggressive in trimming old retries data

= 1.1 =
* Added translation support
* Added Swedish translation
* During lockout, filter out all other login errors
* Minor cleanups

= 1.0 =
* Initial version

== Upgrade Notice ==

= 1.7.1 =
Users of version 1.6.2 and 1.7.0 should upgrade immediately. There was a problem with "auth cookie" lockout enforcement. Lockout of normal password login attempts still worked as it should. Please see plugin Changelog for more information.

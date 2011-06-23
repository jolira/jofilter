A Simple Servlet Filter for Obfuscating Access to Web Applications using Username & Password.

This filter checks for the presence of cookie, which controls whether the user can access a particular web-page. If a valid cookie is not present the user has to enter a username and password.

This filter is handy to control access QA environments of (mobile) web application, which need to be available on the public Internet, but should not be accessible to everyone.

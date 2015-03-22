# HTTP session hijacking on open wireless networks #
**All sniffing done using the Scapy library**

The main goal of this project is to (re)demonstrate all that is wrong with not using SSL for HTTP connections (HTTPS). Things can go really wrong. This tool didn't get much work into it and still does an effective job in capturing all cookies on open wireless networks and replaying them on a new browser window.

**Roadmap** is:

  * Get a man in the middle attack working properly
    * use arpspoof at first
    * implement it in scapy (really easy)

  * Get sslstrip working (this one is a tad harder to implement natively)

  * Improve the interface
    * Sort cookies by IP address
    * Have the ability to select individual cookies and load websites with them
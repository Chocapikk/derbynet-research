
- [Introduction](#introduction)
  - [Vulnerabilities Summary](#vulnerabilities-summary)
    - [Local File Inclusion Leading to Potential Remote Code Execution in DerbyNet's kiosk.php](#local-file-inclusion-leading-to-potential-remote-code-execution-in-derbynets-kioskphp)
    - [Unauthenticated SQL Injection via 'where' Clause in Award Document Rendering](#unauthenticated-sql-injection-via-where-clause-in-award-document-rendering)
    - [Unauthenticated SQL Injection via 'where' Clause in Racer Document Rendering](#unauthenticated-sql-injection-via-where-clause-in-racer-document-rendering)
    - [Unauthenticated XSS Vulnerability in ./inc/kiosks.inc](#unauthenticated-xss-vulnerability-in-inckiosksinc)
    - [Unauthenticated XSS in racer-results.php](#unauthenticated-xss-in-racer-resultsphp)
    - [Unauthenticated XSS in render-document.php](#unauthenticated-xss-in-render-documentphp)
    - [Unauthenticated XSS in photo.php](#unauthenticated-xss-in-photophp)
    - [Authenticated XSS in photo-thumbs.php](#authenticated-xss-in-photo-thumbsphp)
    - [Authenticated XSS Vulnerability in checkin.php](#authenticated-xss-vulnerability-in-checkinphp)


# Introduction

As of the time of writing, DerbyNet, a modest yet impactful open-source project on GitHub, has garnered nearly 100 stars, signaling a growing interest and appreciation within its community. This software, designed to streamline the management of Pinewood Derby races, has been around for several years, demonstrating its resilience and ongoing relevance. You can explore the project further through [this link](https://github.com/jeffpiazza/derbynet).

I embarked on this journey into DerbyNet's codebase driven by a curiosity to apply modern vulnerability identification techniques to a smaller-scale project. The inspiration behind this deep dive was a technique I learned from a blog post, which utilizes GitHub search patterns to uncover potential security flaws. By applying the pattern `/(require|include)(_once)?\s*\(\s*['"]?\s*\$(_POST|_GET|_REQUEST)/`, my aim was to unearth vulnerabilities within DerbyNet and, in doing so, contribute to the enhancement of its security posture.

This article is a narrative of my exploration, detailing the vulnerabilities I discovered and the process behind their identification. It's a testament to the importance of security in software development and a call to action for developers and security enthusiasts alike to continuously scrutinize and fortify the applications we create and rely on.

## Vulnerabilities Summary

In total, there are:

- **1 Local File Inclusion (LFI) Vulnerability**
- **6 Cross-Site Scripting (XSS) Vulnerabilities**
- **2 SQL Injection (SQLi) Vulnerabilities**
  

### Local File Inclusion Leading to Potential Remote Code Execution in DerbyNet's kiosk.php

- **Affected Component**: Kiosk functionality in `kiosk.php`
- **Type of Vulnerability**: Local File Inclusion (LFI) with potential for Remote Code Execution (RCE)
- **Impact**: Unauthenticated access to arbitrary files; potential pathway to RCE.
- **Location**: `kiosk.php` file within DerbyNet.

**Vulnerability Details:**

Before a critical security patch was applied, DerbyNet's `kiosk.php` exhibited a severe Local File Inclusion (LFI) vulnerability. The flaw was rooted in the handling of the `$_GET['page']` parameter:

```php
// 'page' query argument to support testing
if (isset($_GET['page'])) {
  require($_GET['page']);
} else {
  $kpage = kiosk_page(address_for_current_kiosk());
  $g_kiosk_parameters_string = $kpage['params'];
  require($kpage['page']);
}
```

This code snippet dangerously allowed for the inclusion of files specified by the user through the `page` parameter without proper validation, enabling the reading of arbitrary server files. This vulnerability could lead to the exposure of sensitive information and, with sophisticated exploitation techniques involving PHP filter chains, potentially allow attackers to execute arbitrary code on the server.

**Steps to Reproduce:**

1. Manipulate the `page` parameter in a request to `kiosk.php`, pointing it to a sensitive file path, e.g., `kiosk.php?page=../../path/to/sensitive/file`.
2. Although theoretical and not successfully demonstrated, advanced exploitation could involve complex PHP filter chains aiming for Remote Code Execution.

This vulnerability was promptly addressed after direct communication with the project maintainer, highlighting the importance of responsible vulnerability disclosure and the quick response from open-source project maintainers to secure their applications.

---

### Unauthenticated SQL Injection via 'where' Clause in Award Document Rendering

- **Affected Component**: `print/render/award.inc` in document rendering process.
- **Authentication**: None (Unauthenticated)
- **Vulnerability**: SQL Injection

**Vulnerability Details:**

DerbyNet's document rendering endpoint, specifically within `print/render/award.inc`, is vulnerable to an unauthenticated SQL Injection. This vulnerability is exploitable via the `where` parameter in the URL, as evidenced by sqlmap analysis:

- **Boolean-based blind SQL Injection**: Demonstrated by the payload that alters the query logic without affecting the application's response, confirming the vulnerability by ensuring the query returns true.
  
  Payload: `options={}&where=1 AND 1470=1470`

- **Time-based blind SQL Injection**: Verified through a payload causing a significant delay in the response, indicating control over query execution timing.

  Payload: `options={}&where=1 AND 4054=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))`

The SQL Injection manifests in the code as follows:

```php
$base_sql = 'SELECT awardid, awardname, awardtype, classid, rankid, racerid '
  .' FROM '.inner_join('Awards', 'AwardTypes', 'Awards.awardtypeid = AwardTypes.awardtypeid');

$sql = $base_sql;
if (($_GET['ids'])) {
  $sql .= ' WHERE awardid IN ('.$_GET['ids'].',0)';
} else if (isset($_GET['where'])) {
  $sql .= ' WHERE '.$_GET['where'];
}
```

The vulnerability is due to the direct incorporation of the `where` parameter into the SQL query without proper sanitization, allowing attackers to manipulate the SQL query structure and execute arbitrary SQL commands. This can lead to unauthorized data access, data modification, or even database structure compromise within the application's database management system (SQLite3, as indicated).

**Analysis:**

This SQL Injection flaw underscores the critical need for input validation and parameterized queries, especially in applications like DerbyNet that handle sensitive information. Implementing these security measures can significantly mitigate the risk posed by SQL Injection vulnerabilities.

---

### Unauthenticated SQL Injection via 'where' Clause in Racer Document Rendering

- **Affected Component**: Award document generation in `print/render/racer.inc`
- **Authentication**: None (Unauthenticated)
- **Vulnerability**: SQL Injection

**Vulnerability Details:**

The `print/render/racer.inc` component of DerbyNet is vulnerable to an unauthenticated SQL Injection attack. This vulnerability is due to improper sanitization of the `where` parameter in the URL. Attackers can manipulate SQL queries by injecting arbitrary SQL code through the `where` parameter. The sqlmap tool has confirmed this vulnerability by successfully exploiting the `where` parameter with a boolean-based blind SQL injection:

- **Payload**: `where=1 AND 8050=8050`

**Code Snippet with Vulnerability**:

```php
function draw_one_racer(&$racer) {
      global $doc;
      convert_strings($racer);
      clean_fake_photos($racer);
      $racer['barcode'] = 'PWDid'.sprintf('%03d', $racer['racerid']);
      $doc->DrawOne($racer);
}

    if (isset($_GET['ids'])) {
      $sql = $base_sql.' WHERE racerid = :racerid';
      $stmt = $db->prepare($sql);
      foreach (explode(',', $_GET['ids']) as $racerid) {
        $stmt->execute(array(':racerid' => $racerid));
        $racer = $stmt->fetch(PDO::FETCH_ASSOC);
        draw_one_racer($racer);
      }
    } else {
      $sql = $base_sql;
      if (isset($_GET['where'])) {
        $sql = $sql.' WHERE '.$_GET['where'];
      }
      $sql = $sql.' ORDER BY lastname, firstname, carnumber';

      foreach ($db->query($sql) as $racer) {
        draw_one_racer($racer);
      }
    }
```

The vulnerability arises from the direct inclusion of the `$_GET['where']` parameter into the SQL statement without proper validation or sanitization. This allows attackers to alter the SQL query's logic, potentially accessing or manipulating sensitive database information unauthorizedly.

### Unauthenticated XSS Vulnerability in ./inc/kiosks.inc

- **Affected Component**: Kiosk address handling in `./inc/kiosks.inc`
- **Authentication**: None (Unauthenticated)
- **Vulnerability**: Cross-Site Scripting (XSS)

**Vulnerability Details:**

In DerbyNet, an unauthenticated Cross-Site Scripting (XSS) vulnerability exists within the `address_for_current_kiosk()` function located in the `./inc/kiosks.inc` file. This vulnerability arises from the improper handling of user-supplied input through URL parameters `id` and `address`.

The function `address_for_current_kiosk()` is designed to determine the address identifier for a kiosk. It accepts input from URL parameters, which are directly assigned to a variable without sanitization. This flaw allows attackers to inject malicious JavaScript code by crafting malicious URLs, such as:

- `http://127.0.0.1:8000/kiosk.php?id=<script>alert(1)</script>`
- `http://127.0.0.1:8000/kiosk.php?address=<script>alert(1)</script>`

When these URLs are accessed, the JavaScript code within the parameters is executed, leading to an XSS attack.

**Code Snippet Highlighting the Issue:**

```php
function address_for_current_kiosk() {
  $addr = "";
  if (isset($_GET['id'])) {
    $addr = $_GET['id'];  // Direct assignment from user input without sanitization
  } else if (isset($_GET['address'])) {
    $addr = $_GET['address'];  // Direct assignment from user input without sanitization
  }
  // Further code that uses $addr, potentially leading to XSS when rendered in a browser
  return $addr;
}
```

**Analysis:**

The core of this vulnerability lies in the function's failure to sanitize the `id` and `address` URL parameters before using them. This oversight makes it possible for attackers to execute arbitrary JavaScript in the context of the user's browser session. Since this vulnerability does not require authentication to exploit, any malicious individual who can convince a user to click on a specially crafted link could potentially execute unauthorized actions on behalf of the user, steal sensitive information, or compromise the user's interaction with the application.

---

### Unauthenticated XSS in racer-results.php

- **Affected Component**: Display of racer results in `racer-results.php`
- **Authentication**: None (Unauthenticated)
- **Vulnerability**: Cross-Site Scripting (XSS)

**Vulnerability Details:**

The `racer-results.php` file in DerbyNet exhibits an unauthenticated Cross-Site Scripting (XSS) vulnerability through the mishandling of the `racerid` parameter in the URL. The vulnerability specifically arises within the HTML `<title>` tag, where the application dynamically inserts the value of the `racerid` parameter directly without any form of sanitization or encoding.

Attackers can exploit this vulnerability by crafting a URL that includes malicious JavaScript code as part of the `racerid` parameter. For instance:

- `http://127.0.0.1:8000/racer-results.php?racerid=</title><script>alert(1)</script>`

This crafted URL closes the `<title>` tag prematurely and injects a `<script>` tag that, when executed, can perform actions such as displaying an alert box, among other potential malicious activities.

**Code Snippet Highlighting the Issue:**

In `racer-results.php`, the vulnerable HTML code snippet is:

```php
<title>Results By Racer <?php if (isset($_GET['racerid'])) echo ' for '.$_GET['racerid']; ?></title>
```

This code directly incorporates user-supplied input from the `racerid` URL parameter into the HTML output without any sanitization. This oversight allows the injection of arbitrary HTML and JavaScript code into the page, leading to the XSS vulnerability.

**Analysis:**

The vulnerability stems from the direct inclusion of unsanitized user input (`$_GET['racerid']`) in the page output, particularly within the HTML `<title>` element. By injecting malicious content into the `racerid` parameter, an attacker can manipulate the page content or execute arbitrary JavaScript in the context of the victim's browser session.

---

### Unauthenticated XSS in render-document.php

- **Affected Component**: Document rendering in `render-document.php`
- **Authentication**: None (Unauthenticated)
- **Vulnerability**: Cross-Site Scripting (XSS)

**Vulnerability Details:**

`render-document.php` in DerbyNet is vulnerable to unauthenticated XSS due to improper handling of user input in document rendering paths. Attackers can inject malicious scripts via URLs:

- `http://127.0.0.1:8000/render-document.php/racer/<img src=x onerror=alert(1)>`
- `http://127.0.0.1:8000/render-document.php/<img src=x onerror=alert(1)>`

The vulnerability arises from the application's display of debug information, including `ORIG_SCRIPT_FILENAME`, `DOCUMENT_URI`, `SCRIPT_NAME`, and `PHP_SELF`, which improperly handle user-supplied input, leading to XSS.

**Analysis:**

The issue stems from echoing user input without sanitization in debug mode, a practice not recommended for production environments. This flaw allows for the injection of arbitrary scripts executable in a user's browser, compromising user data and interaction with the application. Proper handling and sanitization of input data are essential to mitigate such vulnerabilities.

---

### Unauthenticated XSS in photo.php

- **Affected Component**: Photo handling in `photo.php`
- **Authentication**: None (Unauthenticated)
- **Vulnerability**: Cross-Site Scripting (XSS)

**Vulnerability Details:**

`photo.php` within DerbyNet is susceptible to an unauthenticated XSS attack, facilitated by the display of debug text that improperly processes user input. By navigating to:

- `http://127.0.0.1:8000/photo.php/<img src=x onerror=alert(1)>`

an attacker can execute arbitrary JavaScript in the context of a victim's browser.

**Analysis:**

This vulnerability is a direct consequence of displaying debug information without adequately sanitizing user-controlled inputs. This practice can lead to the execution of malicious scripts, underlining the importance of removing or securing debug information in production environments.

---

### Authenticated XSS in photo-thumbs.php

- **Affected Component**: Photo thumbnails navigation in `photo-thumbs.php`
- **Authentication**: Required (Authenticated)
- **Vulnerability**: Cross-Site Scripting (XSS)

**Vulnerability Details:**

`photo-thumbs.php` in DerbyNet suffers from an authenticated XSS vulnerability due to improper handling of the `racerid` and `back` parameters. The application dynamically generates a URL for navigation without sanitizing these parameters, allowing an attacker to inject malicious scripts.

**Code Snippet Analysis:**

```php
<?php
    echo "<a class='button_link' id='refresh-button' onclick='window.location.reload();'>Refresh</a>";
    $url = "photo-thumbs.php?repo=$other_repo&amp;order=$order";
    if (isset($_GET['racerid'])) {
      $url .= "&amp;racerid=" . $_GET['racerid'];  // Vulnerable to XSS injection
    }
    if (isset($_GET['back'])) {
      $url .= "&amp;back=" . $_GET['back'];  // Vulnerable to XSS injection
    }
    echo "<a id='other-button' class='button_link' href='$url'>"; // Injection point
    echo $other_repo == 'head' ? 'Racers' : 'Cars';
    echo "</a>";
?>
```

1. **Injection through URL Parameters**: The script directly incorporates values from the `$_GET['racerid']` and `$_GET['back']` parameters into the URL without sanitizing them. This flaw allows attackers to craft URLs containing malicious JavaScript code.

2. **Vulnerable Dynamic URL Construction**: The constructed `$url` variable, containing the unsanitized inputs, is used in the `href` attribute of an anchor tag. When a user navigates to the maliciously crafted URL, the JavaScript code embedded in the URL parameters is executed in the context of the user's browser.

### Authenticated XSS Vulnerability in checkin.php

- **Affected Component**: Order handling in `checkin.php`
- **Authentication**: Required (Authenticated)
- **Vulnerability**: Cross-Site Scripting (XSS)

**Vulnerability Details:**

In DerbyNet's `checkin.php`, an authenticated Cross-Site Scripting (XSS) vulnerability is identified, emanating from improper handling of the `order` URL parameter. The vulnerability is introduced within a JavaScript variable assignment, where the `order` parameter value is directly embedded without proper sanitization or encoding, facilitating script injection via:

- `http://127.0.0.1:8000/checkin.php?order=</script><script>alert(1)</script>`
- `http://127.0.0.1:8000/checkin.php?order=';alert(1);//`

**Source Code Analysis:**

The critical part of the `checkin.php` source code is:

```php
<script type="text/javascript">
var g_order = '<?php echo $order; ?>';
var g_action_on_barcode = "<?php
  echo isset($_SESSION['barcode-action']) ? $_SESSION['barcode-action'] : "locate";
?>";
```

In this snippet, the `$order` PHP variable is directly echoed into a JavaScript variable declaration (`var g_order`). Since the value of `$order` comes from the `order` URL parameter and is not sanitized before being output, an attacker can inject arbitrary JavaScript by manipulating the `order` parameter.

The lack of proper input sanitization and output encoding in this context allows attackers to execute JavaScript code in the context of the authenticated user's session, potentially leading to unauthorized actions being performed or sensitive information being exposed.

This vulnerability underscores the importance of treating all user input as untrusted and applying rigorous sanitization and encoding practices, especially when incorporating such input into executable code contexts like JavaScript.
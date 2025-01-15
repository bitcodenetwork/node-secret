import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync
} from "crypto";

class Secret {
  constructor() { }

  private static createIV(algorithmParam: "sha256" | "sha512", secretParam: string, secretIVParam: string) {
    const algorithm = algorithmParam;
    const secret = secretParam;
    const secretIV = secretIVParam;

    const key: Buffer = createHash(algorithm).update(secret).digest();
    const iv: Buffer = Buffer.allocUnsafe(16);
    const encryptionIV: Buffer = createHash(algorithm).update(secretIV).digest();

    encryptionIV.copy(iv);

    return { key, iv };
  }

  /**
   * Random Bytes
   * ------------
   * generate random bytes using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param randomBytesParam random bytes to generate
   * @param type type of random bytes
   * @returns random bytes
   */
  public static randomBytes(randomBytesParam: number = 5, type: "ascii" | "base64" | "base64url" | "binary" | "hex" | "latin1" | "ucs2" | "ucs-2" | "utf16le" | "utf-16le" | "utf8" | "utf-8" = "hex"): string {
    return randomBytes(randomBytesParam).toString(type);
  }

  /**
   * Encrypt
   * -------
   * encrypt data using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to encrypt
   * @param options setting options for encryption: algorithm, secret, secretIV
   * @returns encrypted data or null
   */

  public static encrypt(data: string, options?: { algorithm?: "sha256" | "sha512", secret?: string, secretIV?: string }): string | null {
    try {
      if (!data || data == 'null' || data == 'undefined') return null;

      const algorithm: "sha256" | "sha512" | null = options?.algorithm || "sha256";
      const secret: string | undefined = options?.secret || process.env.ENCRYPT_SECRET;
      const secretIV: string | undefined = options?.secretIV || process.env.ENCRYPT_SECRET_IV;

      if (!secret || !secretIV) return null;

      const { key, iv } = this.createIV(algorithm, secret, secretIV);

      const cipher = createCipheriv('aes256', key, iv);

      return cipher.update(data, 'binary', 'hex') + cipher.final('hex')

    } catch (error) {
      throw error;
    }
  }

  /**
   * Decrypt
   * -------
   * decrypt data using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to decrypt
   * @param options setting options for decryption: algorithm, secret, secretIV
   * @returns decrypted data or null
   */

  public static decrypt(data: string, options?: { algorithm?: "sha256" | "sha512", secret?: string, secretIV?: string }): string | null {
    try {

      if (!data || data == 'null' || data == 'undefined') return null;

      const algorithm: "sha256" | "sha512" | null = options?.algorithm || "sha256";
      const secret: string | undefined = options?.secret || process.env.ENCRYPT_SECRET;
      const secretIV: string | undefined = options?.secretIV || process.env.ENCRYPT_SECRET_IV;

      if (!secret || !secretIV) return null;

      const { key, iv } = this.createIV(algorithm, secret, secretIV);

      const decipher = createDecipheriv('aes256', key, iv);

      return decipher.update(data, 'hex', 'binary') + decipher.final('binary')

    } catch (error) {
      throw error;
    }
  }

  /**
   * Encode
   * ------
   * encode data to base64, base64url, hex, etc, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to encode
   * @param type type of encoding
   * @returns encoded data or null
   */

  public static encode(data: string, type: "ascii" | "base64" | "base64url" | "binary" | "hex" | "latin1" | "ucs2" | "ucs-2" | "utf16le" | "utf-16le" | "utf8" | "utf-8" = "base64"): string | null {
    return Buffer.from(data).toString(type);
  }

  /**
   * Decode
   * ------
   * decode data from base64, base64url, hex, etc, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to decode
   * @param type type of decoding
   * @returns decoded data or null
   */

  public static decode(data: string, type: "ascii" | "base64" | "base64url" | "binary" | "hex" | "latin1" | "ucs2" | "ucs-2" | "utf16le" | "utf-16le" | "utf8" | "utf-8" = "base64"): string | null {
    return Buffer.from(data, type).toString('ascii');
  }

  /**
   * SCrypt
   * ------
   * scrypt data using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to scrypt
   * @param options setting options for scrypt: salt, type
   * @returns scrypted data or null
   */

  public static scrypt(data: string, options?: { salt?: string, type?: "hex" | "base64" | "base64url" }): string | null {
    const salt = options?.salt || process.env.SCRYPT_SALT;
    const type = options?.type || "base64url";

    if (!salt) return null;

    const key = this.scryptKey(data, salt, type);
    const hash = key;

    return hash;
  }

  /**
   * SCrypt Compare
   * --------------
   * compare scrypt data using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to compare
   * @param hash hash to compare
   * @param options setting options for scrypt: salt, type
   * @returns is data equal to hash or null
   */
  public static scryptCompare(data: string, hash: string, options?: { salt?: string, type?: "hex" | "base64" | "base64url" }): boolean | null {
    const salt = options?.salt || process.env.SCRYPT_SALT;
    const type = options?.type || "base64url";

    if (!salt) return null;

    const comparedKey = this.scryptKey(data, salt, type ?? "base64url");

    return comparedKey === hash;
  }

  /**
   * SCrypt Auto
   * -----------
   * scrypt data using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to scrypt
   * @param options setting options for scrypt: salt, type
   * @returns scrypted data or null
   */

  public static scryptAuto(data: string, options?: { salt?: string, type?: "hex" | "base64" | "base64url" }): string | null {
    const salt = options?.salt || process.env.SCRYPT_SALT || this.randomBytes();
    const type = options?.type || "base64url";

    if (!salt) return null;

    const encodedSalt = this.encode(salt, "base64url");
    const encodedType = this.encode(type, "base64url");

    const key = this.scryptKey(data, salt, type);
    const hash = encodedType + "$" + encodedSalt + "$" + key;

    return hash;
  }

  /**
   * SCrypt Auto Compare
   * -------------------
   * compare scrypt data using crypto, for more complete information please visit the documentation page.
   * 
   * https://github.com/bitcodenetwork/secret
   * 
   * @param data data to compare
   * @param hash hash to compare
   * @returns is data equal to hash or null
   */

  public static scryptAutoCompare(data: string, hash: string): boolean | null {
    const [encodedType, encodedSalt, key] = hash.split("$");

    const salt: string | null = this.decode(encodedSalt, "base64url");
    const type: "hex" | "base64" | "base64url" | null = this.decode(encodedType, "base64url") as "hex" | "base64" | "base64url" | null;

    if (!salt || !type) return null;

    const comparedKey = this.scryptKey(data, salt, type);

    return comparedKey === key;
  }

  private static scryptKey(data: string, salt: string, type: "hex" | "base64" | "base64url"): string {
    const scryptOptions = {
      N: 2 ** 14,
      r: 8,
      p: 1
    };

    return scryptSync(data, salt, 32, scryptOptions).toString(type ?? "base64");
  }
}

export default Secret;
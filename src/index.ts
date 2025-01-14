import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "crypto";

type Constructor = {
  algorithm?: "sha256" | "sha512";
  secret?: string;
  secretIV?: string;
}

class Secret {
  constructor(params?: Constructor) {

    const { algorithm, secret, secretIV } = params || {};

    const defaultSecret = randomBytes(5).toString("hex");
    const defaultSecretIV = randomBytes(5).toString("hex");

    this.algorithm = algorithm || process.env.CRYPTO_ALGORITHM || "sha256";
    this.secret = secret || process.env.CRYPTO_SECRET || defaultSecret;
    this.secretIV = secretIV || process.env.CRYPTO_SECRET_IV || defaultSecretIV;
  }

  private algorithm;

  private secret;

  private secretIV;

  private key(): Buffer {
    return createHash(this.algorithm).update(this.secret).digest();
  }

  private encryptionIV(): Buffer {
    return createHash(this.algorithm).update(this.secretIV).digest();
  }

  private resizedIV(): Buffer {
    return Buffer.allocUnsafe(16);
  }

  public encrypt(data: string): string | null {
    try {

      if (!data || data == 'null' || data == 'undefined') return null;

      const key: Buffer = this.key();
      const resizedIV: Buffer = this.resizedIV()
      const encryptionIV: Buffer = this.encryptionIV();

      encryptionIV.copy(resizedIV)

      const cipher = createCipheriv('aes256', key, resizedIV);
      return (cipher.update(data, 'binary', 'hex') + cipher.final('hex'))

    } catch (error) {
      throw error;
    }
  }

  public decrypt(data: string): string | null {
    try {

      if (!data || data == 'null' || data == 'undefined') return null;

      const key: Buffer = this.key();
      const resizedIV: Buffer = this.resizedIV()
      const encryptionIV: Buffer = this.encryptionIV();

      encryptionIV.copy(resizedIV)

      const decipher = createDecipheriv('aes256', key, resizedIV);
      return (decipher.update(data, 'hex', 'binary') + decipher.final('binary'))

    } catch (error) {
      throw error;
    }
  }

  public encode(data: string, type: "ascii" | "base64" | "base64url" | "binary" | "hex" | "latin1" | "ucs2" | "ucs-2" | "utf16le" | "utf-16le" | "utf8" | "utf-8" = "base64"): string | null {
    return Buffer.from(data).toString(type);
  }

  public decode(data: string, type: "ascii" | "base64" | "base64url" | "binary" | "hex" | "latin1" | "ucs2" | "ucs-2" | "utf16le" | "utf-16le" | "utf8" | "utf-8" = "base64"): string | null {
    return Buffer.from(data, type).toString('ascii');
  }

  public scrypt(data: string, options?: { salt?: string, type?: "hex" | "base64" | "base64url" }): string | null {
    const type = options?.type || "base64";
    const salt = options?.salt || randomBytes(5).toString("hex");
    const encodedType = this.encode(type, "base64");
    const encodedSalt = this.encode(salt, "base64");
    const key = this.scryptKey(data, salt, type);
    const hash = encodedType + "$" + encodedSalt + "$" + key;

    return hash;
  }

  public scryptCompare(data: string, hash: string): boolean {
    const [encodedType, encodedSalt, key] = hash.split("$");
    const type: any = this.decode(encodedType, "base64");
    const salt: any = this.decode(encodedSalt, "base64");

    const comparedKey = this.scryptKey(data, salt, type);

    return comparedKey === key;
  }

  private scryptKey(data: string, salt: string, type: "hex" | "base64" | "base64url"): string {
    const scryptOptions = {
      N: 2 ** 14,
      r: 8,
      p: 1
    };

    return scryptSync(data, salt, 32, scryptOptions).toString(type ?? "base64");
  }
}

export default Secret;
import { createCipheriv, createDecipheriv, createHash } from "crypto";

type Constructor = {
  algorithm?: "sha256" | "sha512";
  secret?: string;
  secretIV?: string;
}

export class Secret {
  constructor({ algorithm, secret, secretIV }: Constructor) {

    let defaultSecret = '';
    let defaultSecretIV = '';

    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;

    let counter = 0;

    while (counter < 5) {
      defaultSecret += characters.charAt(Math.floor(Math.random() * charactersLength));
      defaultSecretIV += characters.charAt(Math.floor(Math.random() * charactersLength));
      counter += 1;
    }

    this.algorithm = algorithm || "sha256";
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
}
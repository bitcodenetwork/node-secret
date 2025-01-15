import Secret from "../src";

test('random bytes check', () => {
  const randomBytes = Secret.randomBytes();
  expect(randomBytes).toBeTruthy();
});

test('encrypt check', () => {
  const secret = "secret";
  const secretIV = "secret_iv";
  const message = "testing";
  const encrypted = Secret.encrypt(message, { secret, secretIV });

  expect(encrypted).toBeTruthy();
});

test('decrypt check', () => {
  const secret = "secret";
  const secretIV = "secret_iv";
  const message = "testing";
  const encrypted = Secret.encrypt(message, { secret, secretIV });
  const decrypted = Secret.decrypt(encrypted as string, { secret, secretIV });

  expect(decrypted).toBe(message);
});

test('encode check', () => {
  const message = "testing";
  const encoded = Secret.encode(message);

  expect(encoded).toBeTruthy();
});

test('decode check', () => {
  const message = "testing";
  const encoded = Secret.encode(message);
  const decoded = Secret.decode(encoded as string);

  expect(decoded).toBe(message);
});

test('scrypt check', () => {
  const message = "testing";
  const salt = "salt";
  const scrypted = Secret.scrypt(message, { salt });

  expect(scrypted).toBeTruthy();
});

test('scrypt compare check', () => {
  const message = "testing";
  const salt = "salt";
  const scrypted = Secret.scrypt(message, { salt });
  const scryptCompared = Secret.scryptCompare(message, scrypted as string, { salt });

  expect(scryptCompared).toBeTruthy();
});

test('scrypt auto check', () => {
  const message = "testing";
  const scrypted = Secret.scryptAuto(message);

  expect(scrypted).toBeTruthy();
});

test('scrypt auto compare check', () => {
  const message = "testing";
  const scrypted = Secret.scryptAuto(message);
  const scryptCompared = Secret.scryptAutoCompare(message, scrypted as string);

  expect(scryptCompared).toBeTruthy();
});
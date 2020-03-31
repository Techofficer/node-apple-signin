/* eslint-env jest */
import AppleSignIn from "./AppleSignIn";
import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";

const createFakeApplePrivateKeyFile = (contents: string): string => {
  const uuid = crypto.randomBytes(16).toString("hex");
  const filePath = path.join(os.tmpdir(), `safe-to-delete-temp-private-key-for-tests-${uuid}.p8`);
  fs.writeFileSync(filePath, contents);
  return filePath;
};

const removeTempPrivateKey = (filepath: string): void => {
  if (fs.existsSync(filepath)) {
    fs.unlinkSync(filepath);
  }
};

const pathToFakeEmptyPrivateKey = createFakeApplePrivateKeyFile("");
const pathToFakeInvalidPrivateKey = createFakeApplePrivateKeyFile("Some invalid content");

afterAll(() => {
  removeTempPrivateKey(pathToFakeEmptyPrivateKey);
  removeTempPrivateKey(pathToFakeInvalidPrivateKey);
});

describe("AppleSignIn", () => {
  describe("constructor()", () => {
    describe("validates options", () => {
      const create = (options?: any) => () => new AppleSignIn(options);

      test("clientId", () => {
        expect(create(undefined)).toThrow("clientId is empty");
        expect(create({ clientId: "" })).toThrow("clientId is empty");
        expect(create({ clientId: undefined })).toThrow("clientId is empty");
      });

      test("teamId", () => {
        expect(create({ clientId: "com.my-company.my-app" })).toThrow("teamId is empty");
        expect(create({ clientId: "com.my-company.my-app", teamId: "" })).toThrow("teamId is empty");
        expect(create({ clientId: "com.my-company.my-app", teamId: undefined })).toThrow("teamId is empty");
      });

      test("keyIdentifier", () => {
        expect(create({ clientId: "com.my-company.my-app", teamId: "5B645323E8" })).toThrow("keyIdentifier is empty");
        expect(create({ clientId: "com.my-company.my-app", teamId: "5B645323E8", keyIdentifier: "" })).toThrow(
          "keyIdentifier is empty"
        );
        expect(create({ clientId: "com.my-company.my-app", teamId: "5B645323E8", keyIdentifier: undefined })).toThrow(
          "keyIdentifier is empty"
        );
      });

      test("privateKey and privateKeyPath", () => {
        const optionsBase = { clientId: "com.my-company.my-app", teamId: "5B645323E8", keyIdentifier: "U3B842SVGC" };

        expect(create(optionsBase)).toThrow("Empty private key from given input method");

        // privateKey method
        expect(create({ ...optionsBase, privateKey: "" })).toThrow("Empty private key from given input method");
        expect(create({ ...optionsBase, privateKey: undefined })).toThrow("Empty private key from given input method");
        expect(create({ ...optionsBase, privateKey: "test" })).not.toThrow();

        // privateKeyPath method
        expect(create({ ...optionsBase, privateKeyPath: "" })).toThrow("privateKeyPath is empty");
        expect(create({ ...optionsBase, privateKeyPath: undefined })).toThrow("privateKeyPath is empty");
        expect(create({ ...optionsBase, privateKeyPath: "test" })).toThrow(
          "Private key file for given path doesn't exist"
        );
        expect(create({ ...optionsBase, privateKeyPath: pathToFakeEmptyPrivateKey })).toThrow(
          "Empty private key from given input method"
        );
        expect(create({ ...optionsBase, privateKeyPath: pathToFakeInvalidPrivateKey })).not.toThrow();
      });
    });
  });

  test.todo("createClientSecret()");
  test.todo("getAppleSigninKey()");
  test.todo("getAuthorizationToken()");
  test.todo("getAuthorizationUrl()");
  test.todo("refreshAuthorizationToken()");
  test.todo("verifyIdToken()");
});

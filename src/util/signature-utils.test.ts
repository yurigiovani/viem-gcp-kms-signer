import { SignableMessage } from "viem";
import { signMessage } from "viem/accounts";
import { joinSignature, SignTypedDataVersion, splitSignature, validateVersion } from "./signature-utils";

describe("Signature Utils", () => {
  test("should validate the v1 correctly", () => {
    expect(validateVersion(SignTypedDataVersion.V1)).toMatchSnapshot("v1");
  });

  test("should validate the v3 correctly", () => {
    expect(validateVersion(SignTypedDataVersion.V3)).toMatchSnapshot("v3");
  });

  test("should validate the v4 correctly", () => {
    expect(validateVersion(SignTypedDataVersion.V4)).toMatchSnapshot("v4");
  });

  test("should throw an error if the version is not supported", () => {
    expect(() => validateVersion("V5" as SignTypedDataVersion)).toThrow("Invalid version: 'V5'");
  });

  test("should throw an error if no versions are allowed", () => {
    expect(() => validateVersion(SignTypedDataVersion.V1, [])).toThrow(
      "SignTypedDataVersion not allowed: 'V1'. Allowed versions are: "
    );
  });

  test("should throw an error if the version is not allowed", () => {
    expect(() => validateVersion(SignTypedDataVersion.V4, [SignTypedDataVersion.V1, SignTypedDataVersion.V3])).toThrow(
      "SignTypedDataVersion not allowed: 'V4'. Allowed versions are: V1, V3"
    );
  });

  test("should join the signature correctly", async () => {
    // Replace this with your actual private key
    const privateKey = "0x57d42336a4959b7f56cbde74ae2d50003d89e427b184c86ceac7d99a924ef706";
    // Message to be signed
    const message = "Hello, Ethereum!" as SignableMessage;
    // Sign the message
    const signature = await signMessage({
      message,
      privateKey,
    });

    const parsedSignature = splitSignature(signature);
    const joinedSignature = joinSignature(parsedSignature);

    expect(joinedSignature).toBe(signature);
  });
});

import speakeasy from "speakeasy";

function generateSecrets() {
  const secret = speakeasy.generateSecret({ length: 20 });
  return secret;
}

function generateToken(secret) {
  const twoSteptoken = speakeasy.totp({
    secret: secret.base32,
    encoding: "base32",
    step: 120,
  });
  return twoSteptoken;
}

const verifyTwoFactor = (secret, otp) => {
  return speakeasy.totp.verify({
    secret: secret.base32,
    encoding: "base32",
    token: otp,
    step: 120,
    window: 1, // adds extra 2 mins
  });
};

export { generateSecrets, generateToken, verifyTwoFactor };

/* eslint-disable @typescript-eslint/no-var-requires */
const twoFactor = require("./dist");

const main = async () => {
  console.log("*******************************");
  console.log("Generating New Secret");
  const newSecret = await twoFactor.generateSecret({ name: "My Awesome App", account: "johndoe" });
  console.log(newSecret);
  
  console.log("*******************************");
  console.log("Generating New Token With Secret " + newSecret.secret);
  const newToken = twoFactor.generateToken(newSecret.secret);
  console.log(newToken);
  
  console.log("*******************************");
  console.log("Verifying Valid Token");
  console.log(twoFactor.verifyToken(newSecret.secret, newToken.token));
  
  console.log("*******************************");
  console.log("Verifying Valid Token - Window: 1");
  console.log(twoFactor.verifyToken(newSecret.secret, newToken.token, 1));
  
  console.log("*******************************");
  console.log("Verifying Valid Token - Window: -3");
  console.log(twoFactor.verifyToken(newSecret.secret, newToken.token, -3));
  
  console.log("*******************************");
  console.log("Verifying Invalid Token");
  console.log(twoFactor.verifyToken(newSecret.secret, "11111"));
  
  console.log("*******************************");
  console.log("Done - Star Me On Github");
  
}

main().then()

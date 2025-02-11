// CSFLE adapted from https://github.com/mongodb/docs/tree/master/source/includes/generated/in-use-encryption/csfle/node/local/reader/
const GANTTIFY_IP = "206.81.1.248";
const LOCALHOST = `http://localhost:5173`;
const GANTTIFY_LINK = (process.env.NODE_ENV === 'dev') ? LOCALHOST : `http://`+GANTTIFY_IP;
if (process.env.NODE_ENV === 'dev'){
  console.log("Running in Dev Mode");
}
const express = require("express");
const {MongoClient, ObjectId, ClientEncryption, Timestamp, Binary, UUID} = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodeMailer = require("nodemailer");
const file = require("fs");
const path = require('path');
require("dotenv").config();
const {google} = require("googleapis");
const {Chromator} = require("chromator");
const OAuth2 = google.auth.OAuth2;

const router = express.Router();
const url = process.env.MONGODB_URI;

// Set up secure parameters.
var database_name = "ganttify";
var secure_collection = "protectUserAccounts";
var secure_namespace = `${database_name}.${secure_collection}`;

const provider = "local";
const savePath = "./csfle-master-key.txt";
const masterLocalKey = file.readFileSync(savePath);
const kmsProviders = {
  local: {key: masterLocalKey,},
};

const keyVaultNamespace = "encrypt_database.key_collection";
const keyId = "<NmIBCKRwRLKW2HQLrNEtsw==>";

// Regular client.
// Also allows automatic decryption.
let client;
(async () => {
  try {
    client = new MongoClient(url, {autoEncryption: {keyVaultNamespace, kmsProviders, bypassAutoEncryption: true, bypassQueryAnalysis: true}});
    await client.connect();
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
})();

// For CSFLE explicit encryption.
const encryptClient = new ClientEncryption(client, {keyVaultNamespace, kmsProviders});

const createSecureTransporter = async () => {

  try {

    const secureTransporter = nodeMailer.createTransport({
      service: 'gmail',
      host: "smtp.gmail.com",
      secure: true,
      port: 465,
      auth: {
        type: "login",
        user: process.env.USER_EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      }
    });

    return secureTransporter;
    
  } catch (error) {
    console.log(error);
    return null;
  }
};

//////////////
// User profile details and account security endpoints.
//////////////

//-----------------> Register Endpoint <-----------------//
router.post("/register", async (req, res) => {
  const { email, name, phone, password, username } = req.body;
  let error = "";

  if (!email || !name || !phone || !password || !username) {
    error = "All fields are required";
    return res.status(400).json({ error: "All fields are required" });
  }

  try {

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const tempCollection = db.collection("unverifiedUserAccounts");

    // Ensure that TTL exists.
    await tempCollection.createIndex(
      { "accountCreated": 1 },
      {
        expireAfterSeconds: 300, // expires in 5 minutes.
        partialFilterExpression: { "isEmailVerified": false }
      }
    );

    // Make an encrypted query against both the temporary and verified databases.
    var queryEncryptedEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
	  const existingUser = await userCollection.findOne({email: queryEncryptedEmail });
    const existingTempUser = await tempCollection.findOne({email: queryEncryptedEmail });

    // Check if the user already exists in the verified user account database.
    if (existingUser || existingTempUser) {
      return res.status(400).json({ error: "Email has already verified or registered." });
    }

    // Hash and encrypt data before adding to the database.
    const hashedPassword = await bcrypt.hash(password, 10);

    var enterName = await encryptClient.encrypt(name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var enterPhone = await encryptClient.encrypt(phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var enterUsername = await encryptClient.encrypt(username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var enterPassword = await encryptClient.encrypt(hashedPassword, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var discordAccount = await encryptClient.encrypt("", {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
	  var organization = await encryptClient.encrypt("", {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var timezone = await encryptClient.encrypt("", {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var pronouns = await encryptClient.encrypt("", {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var tempIdString = new ObjectId().toString();

    const newTempUser = {
      tempId: tempIdString,
	    email: queryEncryptedEmail,
	    name: enterName,
	    phone: enterPhone,
      username: enterUsername,
	    password: enterPassword,
	    discordAccount: discordAccount,
	    organization: organization,
	    pronouns: pronouns,
	    timezone: timezone,
	    accountCreated: new Date(),
	    isEmailVerified: false, 
	    projects: [],
	    toDoList: [],
    };

    // Insert unverified account into temporary collection.
    await tempCollection.insertOne(newTempUser);

    // For nodemailer.
    // Should use an encrypted email address.
    const secret = process.env.JWT_SECRET + enterPassword.toString();
    const token = jwt.sign({email: tempIdString}, secret, {expiresIn: "5m",} );

    let link = GANTTIFY_LINK+`/verify-email/${tempIdString}/${token}`;

    // Use secure transporter.
    const secureTransporter = await createSecureTransporter();
    if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Verify Your Ganttify Account',
      text: `Hello ${name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
      html: `<p>Hello ${name},</p> <p>Please verify your Ganttify account by clicking the following link:\n</p> <a href="${link}" className="btn">Verify Account</a>`
    };

    secureTransporter.sendMail(mailDetails, function (err, data) {
      if (err) {
        return res.status(500).json({ error: 'Error sending verification email.' });
      } else {
        return res.status(200).json({ message: 'Verification email sent.' });
      }
    });

  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

//-----------------> Verify Registration Email Endpoint <-----------------//
router.get('/verify-email/:email/:token', async (req, res) => {
  // NOTE: Email should already be an encrypted parameter.
  const { email, token } = req.params;

  try {

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const tempCollection = db.collection("unverifiedUserAccounts");

    // Make an encrypted query.
    const existingTempUser = await tempCollection.findOne({tempId: email});

    // Checks if the user is present in the unverified account database.
    if (!existingTempUser) {
      // No such registration.
      return res.status(404).send("Registration not found.");
    }

    var enterPassword = await encryptClient.encrypt(existingTempUser.password, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const secret = process.env.JWT_SECRET + enterPassword.toString();

    try {

      jwt.verify(token, secret);

      // Encrypt data.
      var enterEmail = await encryptClient.encrypt(existingTempUser.email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var enterName = await encryptClient.encrypt(existingTempUser.name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var enterPhone = await encryptClient.encrypt(existingTempUser.phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var enterUsername = await encryptClient.encrypt(existingTempUser.username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var discordAccount = await encryptClient.encrypt(existingTempUser.discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
	    var organization = await encryptClient.encrypt(existingTempUser.organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var timezone = await encryptClient.encrypt(existingTempUser.timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var pronouns = await encryptClient.encrypt(existingTempUser.pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

      const newUser = {
        email: enterEmail,
        name: enterName,
        phone: enterPhone,
        username: enterUsername,
        password: enterPassword,
        discordAccount: discordAccount,
        organization: organization,
        pronouns: pronouns,
        timezone: timezone,
        accountCreated: existingTempUser.accountCreated,
        isEmailVerified: true, 
        projects: [],
        toDoList: [],
        uiOptions: {
          ribbonColor: "#FDDC87",
          dashboardSideNavBarColor: "#DC6B2C",
          dashboardBackgroundColor: "#FFFFFF", // 
          projectPaneBackgroundColor: "#FFFFFF", // default option
          accentButtonColor: "#135C91", // all buttons
          textFontStyle: "\"Inter\", sans-serif", // default option - 
          textFontSize: "",
        } // Object for holding UI options.
      };

      // Add verified user to the database and remove it from the temporary account.
      await userCollection.insertOne(newUser);
      await tempCollection.deleteOne({tempId: email});
      res.status(201).send("Account was successfully verified.");
      
    } catch (error) {
      res.send("Invalid or expired token");
    }

  } catch (error) {
    console.error('Error during verification:', error);
    res.status(400).send("Invalid ID format");
  }

});

//-----------------> Login Endpoint <-----------------//
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let error = "";

  if (!email || !password) {
    error = "Email and password are required";
    return res.status(400).json({ error });
  }

  try {

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Perform an encrypted query.
    var enterEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const verifiedUser = await userCollection.findOne({ email: enterEmail });

    // console.log("Verified user: \n");
    // console.log(verifiedUser);
    
    // If user account is not found in the verified database.
    if (!verifiedUser) {
      error = "Invalid email or password";
      return res.status(401).json({ error });
    }

    console.log("Email found");
 
    const isPasswordValid = await bcrypt.compare(password, verifiedUser.password);

  if (!isPasswordValid) {
    error = "Invalid email or password";
    return res.status(401).json({ error });
  }
	  console.log("successful login");
    const token = jwt.sign({ id: verifiedUser._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    // Encrypt data.
    var encryptEmail = await encryptClient.encrypt(verifiedUser.email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptName = await encryptClient.encrypt(verifiedUser.name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptPhone = await encryptClient.encrypt(verifiedUser.phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptUsername = await encryptClient.encrypt(verifiedUser.username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptDiscord = await encryptClient.encrypt(verifiedUser.discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptOrganization = await encryptClient.encrypt(verifiedUser.organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptTimezone = await encryptClient.encrypt(verifiedUser.timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptPronouns = await encryptClient.encrypt(verifiedUser.pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    
    res.status(200).json({
      token,
      _id: verifiedUser._id,
      email: encryptEmail,
      name: encryptName,
      username: encryptUsername,
      phone: encryptPhone,
      discordAccount: encryptDiscord,
      organization: encryptOrganization,
      pronouns: encryptPronouns,
      timezone: encryptTimezone,
      projects: verifiedUser.projects,
      toDoList: verifiedUser.toDoList,
      uiOptions: verifiedUser.uiOptions,
      error: ""
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-----------------> Forgot Password Endpoint <-----------------//
// Retrieves the account via entered email account. Leads to the reset-password page.
router.post('/forgot-password', async (req, res) => 
{
  const {email} = req.body;
  let error = '';
  
  try{

    const db = client.db('ganttify');
    const userCollection = db.collection('userAccounts');

    // Enter an encrpyted query.
    var enterEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const user = await userCollection.findOne({email: enterEmail});

    if (user) {
      
      const secret = process.env.JWT_SECRET + user.password;
      const token = jwt.sign({email: user.email, id: user._id}, secret, {expiresIn: "5m",} );

      let link = GANTTIFY_LINK+`/reset-password/${user._id}/${token}`;

      const secureTransporter = await createSecureTransporter();
      if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: 'Reset Your Ganttify Password',
        text: `Hello ${user.name},\n We received a request to reset your Ganttify password. Click the link to reset your password: ${link}`,
        html: `<p>Hello ${user.name},</p> <p>We received a request to reset your Ganttify password. Click the button to reset your password:\n</p> <a href="${link}" className="btn">Reset Password</a>`
      };

      secureTransporter.sendMail(mailDetails, function (err, data) {
        if (err) {
          return res.status(500).json({ error: 'Error sending email' });
        } else {
          return res.status(200).json({ message: 'Password reset email sent' });
        }
      });
    } else {
      return res.status(404).json({ error: 'User with that email address does not exist.' });
    }

  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error });
  } 
});

//-----------------> Password Reset Email Endpoint <-----------------//
// Verifies that the email request for a password reset is legitimate.
router.get('/reset-password/:id/:token', async (req, res) => {
  const { id, token } = req.params;

  try {
    console.log("Entered /reset-password/:id/:token API endpoint.");

    // Find the user.
    const db = client.db('ganttify');
    const userCollection = db.collection('userAccounts');
    const user = await userCollection.findOne({_id: new ObjectId(id)});

    if (user) {
      const secret = process.env.JWT_SECRET + user.password;
      try {

        jwt.verify(token, secret);
        return res.status(200).json({ message: "Password reset has been verified." });

      } catch (error) {
        return res.send("Password reset has not been verified.");
      }

    } else {
      return res.status(404).send("User does not exist.");
    }

  } catch(error) {
    console.error('Error during password reset verification:', error);
    return res.status(400).send("Invalid ID format");
  }
  
});

//-----------------> Reset Password Endpoint <-----------------//
// Endpoint where the user enters in their new password.
router.post('/reset-password', async (req, res) => 
  {
    const { id, password } = req.body;
    let error = '';
    console.log("Entered /reset-password API endpoint.");
  
    try {
      const db = client.db('ganttify');
      const userCollection = db.collection('userAccounts');
      const user = await userCollection.findOne({_id: new ObjectId(id)});
  
      if (user){

        // Compare the hashes to ensure that the new password is not the same as the old password.
        const isPasswordChanged = await bcrypt.compare(password, user.password);
        console.log("isPassword = " + isPasswordChanged);

        if (isPasswordChanged == true){
          return res.status(406).json({ message: "Please enter a new password." });
        }

        // Hash new password before entering it in the database.
        const hashedPassword = await bcrypt.hash(password, 10);

        try {

          var enterNewPassword = await encryptClient.encrypt(hashedPassword, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
          await userCollection.updateOne({_id: new ObjectId(id)}, {$set: {password: enterNewPassword}});
          res.status(200).json({ message: "Password has been changed successfully." });

        } catch(error) {
          return res.json({status: "error", data: error})
        }
  
      } else {
        error = 'User not found.';
        return res.status(404).json({ message: "User not found." });
      }
  
    } catch (error) {
      console.error('Error occured during password reset:', error);
      error = 'Internal server error';
      res.status(500).json({ message: error });
    } 
});

//-----------------> Edit Email Endpoint <-----------------//
// Allows logged in users to change their email account.
// Requires the user to know their password before proceeding.
router.post("/edit-email", async (req, res) => {
  const { id, email, password } = req.body;
  
  try {

    // Check to see if the email is already taken by another email. Encrypt the new email.
    var newEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const unverifiedEmailCollection = db.collection("unverifiedEmails");
    const user = await userCollection.findOne({_id: new ObjectId(id)});
    const existEmail = await userCollection.findOne({email: newEmail});

    // Check if the user exists.
    if (!user){return res.status(404).send("User does not exist.");}

    // Check if the new email address entered is already being used.
    if (existEmail){return res.status(406).send("Email address entered is already being used. Please choose another email address.");}

    // Checks password validity.
    const match = await bcrypt.compare(password, user.password);
    if (!match){return res.status(401).send("Incorrect password. Please try again.");}

    // Proceed with changing the email.
    // This will send a verification email to the new account.
    const secret = process.env.JWT_SECRET + user.password;
    const token = jwt.sign({id: user._id}, secret, {expiresIn: "5m"});

    // Temporarily collect the new email in the user document holding the temporary email address change.
    // Ensure that TTL exists. 
    await unverifiedEmailCollection.createIndex(
      { "requestedEmailChangeTime": 1 },
      {
        expireAfterSeconds: 300, // expires in 5 minutes.
      }
    );

    // Check to see if a email request was already submitted.
    var existEarlier = await unverifiedEmailCollection.findOne({tempId: id});
    if (existEarlier){return res.status(400).send("An email change request has already been sent. Please wait at least 5 minutes before submitting another request.");}

    // Insert the temporary information.
    const temp = {tempId: user._id, email: newEmail, requestedEmailChangeTime: new Date()};
    await unverifiedEmailCollection.insertOne(temp);

    let link = GANTTIFY_LINK+`/edit-email/${user._id.toString()}/${token}`;

    const secureTransporter = await createSecureTransporter();
    if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Changing Your Ganttify Email Address',
      text: `Hello ${user.name},\n We received a request to change your Ganttify email attached to your acccount. Click the link to confirm that you changed your email: ${link}`,
      html: `<p>Hello ${user.name},</p> <p>We received a request to change your Ganttify email attached to your acccount. Click the link to confirm that you changed your email:\n</p> <a href="${link}" className="btn">Change Email</a>`
    };

    secureTransporter.sendMail(mailDetails, function (err, data) {
      if (err) {
        return res.status(500).json({ error: 'Error sending email.' });
      } else {
        return res.status(200).json({ message: 'Verification email sent to your new email address.' });
      }
    });

 
  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }

});

//----------- Retrieve UI Settings Users Endpoint----------------//
router.post("/get-user-ui", async (req, res) => {
  const {userId} = req.body;
  let error = "";
  
  try {

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const user = await userCollection.findOne({_id: new ObjectId(userId)});

    if (!user){
      return res.status(400).send("User not found.");
    }

    // If the fields are not found, return a default list of UI settings to prevent errors.
    if (!user.uiOptions){
      return res.status(201).json({
        ribbonColor: "#FDDC87", // all instances or classnames. 
        dashboardSideNavBarColor: "#DC6B2C",
        dashboardBackgroundColor: "#FFFFFF",
        projectPaneBackgroundColor: "#FFFFFF",
        accentButtonColor: "#135C91",
        textFontStyle: "\"Inter\", sans-serif",
        textFontSize: "",
      });
    }

    // Returns the user's saved ui settings as a JSON.
    return res.status(200).json(user.uiOptions);

  }
  catch (error) {
    console.error("Login error:", error);
    error = "Internal server error";
    return res.status(500).json({error});
  }
});

// <----------------- Edit UI details ----------------------------> 
// Returns a list of ui attributes for the frontend to receive.
router.put("/edit-user-ui/:userId", async (req, res) => {
  const { userId } = req.params;
  const updateFields = req.body; // Note: updateFields must be a Object JSON.
  let error = "";
  
  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const user = await userCollection.findOne({_id: new ObjectId(userId)});

    // Expression to validate hex color
    const isValidHexColor = (color) => /^#([0-9A-F]{3}){1,2}$/i.test(color);

    // Validate that each of the updated colors are valid.
    if (!isValidHexColor(updateFields.ribbonColor) 
      || !isValidHexColor(updateFields.dashboardSideNavBarColor)
      || !isValidHexColor(updateFields.dashboardBackgroundColor)
      || !isValidHexColor(updateFields.accentButtonColor)
      || !isValidHexColor(updateFields.projectPaneBackgroundColor)){
      return res.status(400).send("Invalid hex code(s) provided in fields.");
    }


    if (!user){
      return res.status(400).send("User not found.");
    }

    if (!Object.keys(updateFields).length){
      error = "No fields provided to update";
      return res.status(400).json({ error });
    }

    // Determine if the chosen colors for the ribbon, buttons, and dashboard navigation bar have 
    // enough contrast between the button text color (white) and navigation text color (black).
    let warning = "";
    const ribbonColor = new Chromator(updateFields.ribbonColor);
    const dashboardNavBarColor = new Chromator(updateFields.dashboardSideNavBarColor);
    const dashboardBackgroundColor = new Chromator(updateFields.dashboardBackgroundColor);
    const buttonAccentColor = new Chromator(updateFields.accentButtonColor);
    const projectPaneBackgroundColor = new Chromator(updateFields.projectPaneBackgroundColor);
    
    // Immutable text color.
    const ribbonTextColor = new Chromator("#000000");
    const buttonTextColor = new Chromator("#FFFFFF");

    // Check for all custom colors if it fails WCAG 2.2 AA Contrast Standards.
    if (ribbonColor.findContrast(ribbonTextColor) < 4.5){
      warning = warning.concat("Warning - Contrast between ribbon text color and ribbon background color are insufficient.\n");
    } 

    if (ribbonColor.findContrast(projectPaneBackgroundColor) < 4.5){
      warning = warning.concat("Warning - Contrast between ribbon text color and project pane background color are insufficient.\n");
    } 

    if (ribbonColor.findContrast(dashboardBackgroundColor) < 4.5){
      console.log("ribbonColor.findContrast(dashboardBackgroundColor) = " + ribbonColor.findContrast(dashboardBackgroundColor));
      warning = warning = warning.concat("Warning - Contrast between ribbon background color and dashboard background color are insufficient.\n");
    }

    if (dashboardNavBarColor.findContrast(dashboardBackgroundColor) < 4.5){
      warning = warning.concat("Warning - Contrast between ribbon text color and dashboard background color are insufficient.\n");
    }

    if (buttonAccentColor.findContrast(buttonTextColor) < 4.5){
      warning = warning.concat("Warning - Contrast between button text color and button background color are insufficient.\n");
    }

    console.log("Applicable warnings: " + warning);
    updateFields.alert = warning;

    // Update UI fields in the database.
    await userCollection.updateOne(
      {_id: new ObjectId(userId), 
        $or:
        [
          {'uiOptions.ribbonColor': {$ne: ["uiOptions.ribbonColor", updateFields.ribbonColor]}},
          {'uiOptions.dashboardSideNavBarColor': {$ne: ["uiOptions.dashboardSideNavBarColor", updateFields.dashboardSideNavBarColor]}},
          {'uiOptions.dashboardBackgroundColor': {$ne: ["uiOptions.dashboardBackgroundColor", updateFields.dashboardBackgroundColor]}},
          {'uiOptions.projectPaneBackgroundColor': {$ne: ["uiOptions.projectPaneBackgroundColor", updateFields.projectPaneBackgroundColor]}},
          {'uiOptions.accentButtonColor': {$ne: ["uiOptions.accentButtonColor", updateFields.accentButtonColor]}},
          {'uiOptions.textFontStyle': {$ne: ["uiOptions.textFontStyle", updateFields.textFontStyle]}},
          {'uiOptions.textFontSize': {$ne: ["uiOptions.textFontSize", updateFields.textFontSize]}}
        ]
      },
      {$set: 
        {
          'uiOptions.ribbonColor': updateFields.ribbonColor, 
          'uiOptions.dashboardSideNavBarColor': updateFields.dashboardSideNavBarColor, 
          'uiOptions.dashboardBackgroundColor': updateFields.dashboardBackgroundColor, 
          'uiOptions.projectPaneBackgroundColor': updateFields.projectPaneBackgroundColor,
          'uiOptions.accentButtonColor': updateFields.accentButtonColor,
          'uiOptions.textFontStyle': updateFields.textFontStyle,
          'uiOptions.textFontSize': updateFields.textFontSize
        },
      } 
    );

    // Return the updated json when done with applicable warnings.
    return res.status(200).json(updateFields);
 
  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }

});

//-----------------> Verify Email Change Endpoint <-----------------//
// This is sent to the new email adddress to verify the change.
router.get("/edit-email/:email/:token", async (req, res) => {
  const {email, token} = req.params;
  // Note: email should already be an encrypted parameter.
  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const unverifiedEmailCollection = db.collection("unverifiedEmails");
    const user = await userCollection.findOne({_id: new ObjectId(email)});

    // Check that the user exists.
    if (!user){return res.status(404).send("User does not exist.");}

    try {

      const secret = process.env.JWT_SECRET + user.password;
      jwt.verify(token, secret);
      
      // Retrieve the new email temporarily saved.
      var tempInfo = await unverifiedEmailCollection.findOne({tempId: user._id});

      // Validate that the temporary email entered exists.
      if (!tempInfo){
        return res.status(404).send("Email change information not found.");
      }

      // console.log("Edit email verify API endpoint; new email = " + tempInfo.email);
      var newEmail = await encryptClient.encrypt(tempInfo.email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

      // Update the email address.
      await userCollection.updateOne({_id: new ObjectId(email)}, {$set: {email: newEmail}});

      // Delete the temporary save.
      await unverifiedEmailCollection.deleteOne({tempId: user._id});
      return res.status(200).json({ message: "Email has been changed successfully." });

    } catch (error){
      console.log(error);
      return res.status(401).send("Invalid or expired token.");
    }

  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }

});

//-----------Read Users Endpoint----------------//
router.post("/read/users", async (req, res) => {
    const { users } = req.body;
    let error = "";
    console.log();
    
    if (!users) {
      error = "User ids are required";
      return res.status(400).json({ error });
    }

    // Convert to objectIds.
    const userIds = users.map(n => new ObjectId(n));
    console.log("userIds = " + userIds);
  
    try {

      const db = client.db("ganttify");
      const userCollection = db.collection("userAccounts");

      // Find all users for this task.
      const usersInfo = await userCollection.find({_id: {$in: userIds}}, {name: 1, assignedTasks: 1, username: 1}).toArray();
      // console.log("All people in this project (including the founder):");
      // console.log(usersInfo);

      if (!usersInfo){
        error = "no users found";
        return res.status(400).json({error});
      } else {
        return res.status(200).json({usersInfo, error});
      }
    }
    catch (error) {
      console.error("Login error:", error);
      error = "Internal server error";
      return res.status(500).json({error});
    }
  });

// TASK CRUD Operations
//-----------------> Create Task Endpoint <-----------------//
//------> Create Task & Added Task Category <-------//
router.post('/createtask', async (req, res) => {
  const {
    description = '',
    dueDateTime,
    progress = 'Not Started',
    assignedTasksUsers = [],
    taskTitle,
    tiedProjectId,
    taskCreatorId,
    startDateTime,
    color = '#DC6B2C',
    pattern = '',
    patternColor = '#000000',
    taskCategory = '', // Task category is optional
    prerequisiteTasks = [], // Stores all other task ids that this task depends on being done.
    dependentTasks = [],// Stores all other task ids who are dependent on this task being done.
    allowEmailNotify
  } = req.body;

  // Validate required fields
  if (!dueDateTime || !taskTitle || !taskCreatorId || !startDateTime) {
    return res.status(400).json({
      error: 'Task dueDateTime, taskTitle, taskCreatorId, and startDateTime are required'
    });
  }

  try {
    const db = client.db('ganttify');
    const taskCollection = db.collection('tasks');
    const projectCollection = db.collection('projects');
    const userCollection = db.collection('userAccounts');
    const taskCategoriesCollection = db.collection('task_categories');

    // Initialize categoryId to null
    let categoryId = null;

    // Check if taskCategory is provided and not empty
    if (taskCategory && taskCategory.trim()) {
    console.log(`Checking for existing category: ${taskCategory}`);

    // Try to find the existing category
    let category = await taskCategoriesCollection.findOne({ categoryTitle: taskCategory });

    if (!category) {
      console.log('Category not found. Inserting new category.');

      // Insert the new category
      const newCategory = {
        categoryTitle: taskCategory,
        tasksUnder: [] // Initialize with an empty array for tasks
      };

      const insertedCategory = await taskCategoriesCollection.insertOne(newCategory);
      categoryId = insertedCategory.insertedId;
      console.log(`New category inserted with ID: ${categoryId}`);
    } else {
      // If the category exists, get its ID
      categoryId = category._id;
      console.log(`Using existing category with ID: ${categoryId}`);
    }
  } else {
    console.log('No task category provided.');
  }
  
  // Create the new task object with taskCategoryId if available
  const newTask = {
    description,
    dueDateTime: new Date(dueDateTime),
    taskCreated: new Date(),
    progress,
    assignedTasksUsers: assignedTasksUsers.map((id) => new ObjectId(id)),
    taskTitle,
    tiedProjectId: new ObjectId(tiedProjectId),
    taskCreatorId: new ObjectId(taskCreatorId),
    startDateTime: new Date(startDateTime),
    color,
    pattern,
    patternColor,
    taskCategory,
    taskCategoryId: categoryId, // Include the category ID if available.
    prerequisiteTasks: prerequisiteTasks.map((id) => new ObjectId(id)), // Stores all other task ids that this task depends on being done.
    dependentTasks: dependentTasks.map((id) => new ObjectId(id)), // Stores all other task ids who are dependent on this task being done.
    allPrequisitesDone: true // True ndicates if all of this task's prequisites are done or has no prequisite tasks; false if not all prequisite tasks are completed or otherwise.
  };

    // Insert the new task into the tasks collection
    const taskResult = await taskCollection.insertOne(newTask);
    const taskId = taskResult.insertedId;
    console.log(`Task inserted with ID: ${taskId}`);

    // Update the project with the new task ID
    await projectCollection.updateOne(
      { _id: new ObjectId(tiedProjectId) },
      { $push: { tasks: taskId } }
    );

    // Update user task lists if assigned users are provided
    if (assignedTasksUsers.length > 0) {
      await userCollection.updateMany(
        { _id: { $in: assignedTasksUsers.map((id) => new ObjectId(id)) } },
        { $push: { toDoList: taskId } }
      );
    }

    // Add task category.
    await taskCategoriesCollection.updateOne(
      { _id: categoryId },
      { $push: { tasksUnder: taskId } }
    );

    // Determine if the list of prequisities for this task have already been completed.
    var allCompletedPrequisites = await taskCollection.find({$and: [{_id: {$in: prerequisiteTasks.map((id) => new ObjectId(id))}}, {progress: {$eq: "Completed"}}]}, {progress: 1}).toArray(); 

    // Check if the user assigned prequisite tasks for this new task.
    if (prerequisiteTasks.length > 0){

      // For each prequisite task, add this task as a dependency.
      await taskCollection.updateMany(
        {_id: {$in: prerequisiteTasks.map((id) => new ObjectId(id))}},
        {$push: {dependentTasks: taskId}}
      );

      if (prerequisiteTasks.length == allCompletedPrequisites.length){
        // All of this task's prequisites are done. 
        await taskCollection.updateOne({_id: taskId}, {$set: {allPrequisitesDone: true}});
      } else {
        // All of this task's prequisites are not done.
        await taskCollection.updateOne({_id: taskId}, {$set: {allPrequisitesDone: false}});
      }

    }

    // Respond with the newly created task details
    res.status(201).json({ ...newTask, _id: taskId });
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ error: 'Internal server error' });
  }

});

//-----------------> Read Task <-----------------//
router.get("/readtasks", async (req, res) => {
  let error = "";
  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const tasks = await taskCollection.find({}).toArray();
    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error finding tasks:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

//-----------------> Update Task & Task Category <-----------------//
router.put("/tasks/:id", async (req, res) => {
  const { id } = req.params;
  const updateFields = req.body;
  let error = "";
  console.log("Updating task: " + id);

  if (!Object.keys(updateFields).length) {
    error = "No fields provided to update";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const taskCategoriesCollection = db.collection("task_categories");
    const userCollection = db.collection("userAccounts");
    const task = await taskCollection.findOne({_id: new ObjectId(id)}); // from the database.
    let addedPrequisites; // for later calculations
    let removedPrequisites; // for later calculations.
    let updatePrequisiteList; // for later calculations.
    let addedAssigned; // for later calculations.
    let removedAssigned; // for later calculations.
    let oldProgress = task.progress; // for later calculations.

    console.log("Current progress status: " + oldProgress);

    // Task to update was not found.
    if (!task){
      error = "Task not found. Updates failed";
      return res.status(404).json({ error });
    }

    // Determine which prequisites, if any, were added or removed from the database.
    if (updateFields.prerequisiteTasks) {

      // Needed to properly update tasks with object ids
      updateFields.prerequisiteTasks = updateFields.prerequisiteTasks.map(id => new ObjectId(id));

      var incomingPrequisiteStrings = updateFields.prerequisiteTasks.map(n => n.toString());
      var databasePrequisiteStrings = task.prerequisiteTasks.map(n => n.toString());

      console.log("Incoming update:\n");
      console.log(incomingPrequisiteStrings);
      console.log("In the database currently:\n");
      console.log(databasePrequisiteStrings);
      
      // Calculate shared prequisites for the database and updated list of prequisites.
      const samePrequisites = incomingPrequisiteStrings.filter(n => databasePrequisiteStrings.includes(n));
      console.log("Shared prequisites currently:\n");
      console.log(samePrequisites);

      // Remove shared items between lists.
      const removeCommonIncoming = incomingPrequisiteStrings.filter(n => !samePrequisites.includes(n));
      const removeCommonDatabase = databasePrequisiteStrings.filter(n => !samePrequisites.includes(n));
      
      // Calculate the added and removed prequisites for this task.
      addedPrequisites = removeCommonIncoming.filter(n => !removeCommonDatabase.includes(n));
      removedPrequisites = removeCommonDatabase.filter(n => !removeCommonIncoming.includes(n));

      // Determine the updated list.
      updatePrequisiteList = samePrequisites.concat(addedPrequisites); // since same already accounts for removed prequisites.
      updatePrequisiteList = updatePrequisiteList.map(id => new ObjectId(id));
      updateFields.prerequisiteTasks = updatePrequisiteList;
      console.log("Updated prequisite tasks for this list: " + updatePrequisiteList);

    } else {
      updatePrequisiteList = task.prerequisiteTasks;
      addedPrequisites = [];
      removedAssigned = [];
    }

    // Convert any provided ObjectId fields
    if (updateFields.assignedTasksUsers) {
      
      updateFields.assignedTasksUsers = updateFields.assignedTasksUsers.map(
        (id) => new ObjectId(id)
      );

      var incomingAssignStrings = updateFields.assignedTasksUsers.map(n => n.toString());
      var databaseAssignStrings = task.assignedTasksUsers.map(n => n.toString());

      // Check if we need to add or remove assigned team members for the assigned to-do list.
      // Calculate shared prequisites for the database and updated list of prequisites.
      const sameAssignedUsers = incomingAssignStrings.filter(n => databaseAssignStrings.includes(n));

      // Remove shared items between lists.
      const removeCommonIncoming = incomingAssignStrings.filter(n => !sameAssignedUsers.includes(n));
      const removeCommonDatabase = databaseAssignStrings.filter(n => !sameAssignedUsers.includes(n));
      
      // Calculate the added and removed team members for this task.
      addedAssigned = removeCommonIncoming.filter(n => !removeCommonDatabase.includes(n));
      removedAssigned = removeCommonDatabase.filter(n => !removeCommonIncoming.includes(n));

    } else {
      addedAssigned = [];
      removedAssigned = [];
    }

    // Update the tied project id if necessary.
    if (updateFields.tiedProjectId) {
      updateFields.tiedProjectId = new ObjectId(updateFields.tiedProjectId);
    }

    // Update task creator id if necessary.
    if (updateFields.taskCreatorId) {
      updateFields.taskCreatorId = new ObjectId(updateFields.taskCreatorId);
    }

    // Update task due date time if necessary.
    if (updateFields.dueDateTime) {
      updateFields.dueDateTime = new Date(updateFields.dueDateTime);
    }

    // Update task category if necessary.
    if (updateFields.taskCategory) {
      const categoryTitle = updateFields.taskCategory;

      // Find the category by its name
      let category = await taskCategoriesCollection.findOne({ categoryTitle });

      if (category) {
        // If the category exists, update the task and add it to the tasksUnder array
        await taskCategoriesCollection.updateOne(
          { categoryTitle },
          { $push: { tasksUnder: new ObjectId(id) } } // Add task to tasksUnder field
        );
      } else {
        // If the category doesn't exist, create a new category and add the task under it
        const newCategory = {
          categoryTitle,
          tasksUnder: [new ObjectId(id)],
        };

        const result = await taskCategoriesCollection.insertOne(newCategory);
        category = result.ops[0];  // Retrieve the newly inserted category.

      }

      // Update the task with the category ID
      updateFields.taskCategoryId = new ObjectId(category._id);
    }

    // Check if the task exists before proceeding.
    const status = await taskCollection.findOne({_id: new ObjectId(id)}); // from the database.

    // Concurrency check. If the task happens to be deleted upon attempting to submit, let the user know that the task was deleted.
    if (!status){
      return res.status(404).json({message: "Task no longer exists."});
    }

    // Update the task itself.
    const updatedTask = await taskCollection.updateOne({ _id: new ObjectId(id)}, {$set: updateFields});

    console.log("Current progress status: " + updateFields.progress);

    // Handle to-do lists.
    if (addedAssigned && addedAssigned.length > 0){
      // Add this task as an item on their to-do list.
      await userCollection.updateMany(
        { _id: { $in: addedAssigned.map((id) => new ObjectId(id)) } },
        { $push: {toDoList: new ObjectId(id)}}
      );
    }

    if (removedAssigned && removedAssigned > 0){
      // Remove this task as an item on their to-do list.
      await userCollection.updateMany(
        { _id: { $in: removedAssigned.map((id) => new ObjectId(id)) } },
        { $pull: {toDoList: new ObjectId(id)}}
      );
    }

    // Do the following once the task has been updated:
    // Check if added or removed prequisites for this task need their dependency to this task modified.
    if (addedPrequisites && addedPrequisites.length > 0){

      console.log("Adding the following prequisites to this task:\n");
      console.log(addedPrequisites);

      // Add this task as a dependency to each prequisite.
      await taskCollection.updateMany({_id: {$in: addedPrequisites.map(n => new ObjectId(n))}}, {$addToSet: {dependentTasks: new ObjectId(id)}});
      
    } else {
      console.log("List of prequisite task ids to add: N/A");
    }

    // Check if removed prequisites for this task need their dependency to this task modified.
    if (removedPrequisites && removedPrequisites.length > 0){
      console.log("Removing the following prequisites to this task:\n");
      console.log(removedPrequisites);

      // Remove all selected prequisites from this task.
      await taskCollection.updateMany({_id: {$in: removedPrequisites.map(n => new ObjectId(n))}}, {$pull: {dependentTasks: new ObjectId(id)}});

    } else {
      console.log("List of prequisite task ids to remove: N/A");
    }

    if (updateFields.prerequisiteTasks){

      // Reexamine if all of this task's prequisites are completed or not.
      var allCompletedPrequisites = await taskCollection.find({$and: [{_id: {$in: updateFields.prerequisiteTasks}}, {progress: {$eq: "Completed"}}]}, {progress: 1}).toArray(); 
      console.log("All completed prequisites:\n" + allCompletedPrequisites);

      if ((allCompletedPrequisites.length === updatePrequisiteList.length)){
        
        // This task's prequisites are all completed, or this task no longer has any prequisites attached to it.
        await taskCollection.updateOne({_id: new ObjectId(id)}, {$set: {progress: "Completed", allPrequisitesDone: true}});

      } else {

        // Not all of this task's prequisites are done.
        if (task.progress === "Completed"){
          console.log("Changing this task from completed to in-progress due to not of its prequisites being completed.");
          await taskCollection.updateOne({_id: new ObjectId(id)}, {$set: {progress: "In-progress", allPrequisitesDone: false}});
        } else {
          await taskCollection.updateOne({_id: new ObjectId(id)}, {$set: {allPrequisitesDone: false}});
        }

      } 
    }

    // If this task's completion status has changed, evaluate the task's dependencies.
    if (updatedTask.progress !== oldProgress){
      console.log("Re-evaluating dependencies.");
      // Convert all dependent tasks into ObjectIds from the updateField.
      // Find all dependencies of this task. 
      var allDependencies = await taskCollection.find({_id: {$in: task.dependentTasks.map((id) => new ObjectId(id))}}, {prerequisiteTasks: 1, assignedTasksUsers: 1, taskTitle: 1}).toArray();
      console.log("All Dependencies ", allDependencies);
      
      for (const dependTasks of allDependencies) {
        
        // Check each dependent task's prequisities.
        var completedDependPrequisites = await taskCollection.find({$and: [{_id: {$in: dependTasks.prerequisiteTasks.map((id) => new ObjectId(id))}}, {progress: {$eq: "Completed"}}]}, {progress: 1}).toArray(); 
        console.log("Made it");
        
        // If this task caused those tasks status to change...
        if (dependTasks.prerequisiteTasks.length == completedDependPrequisites.length){
          
          console.log("Dependency \"" + dependTasks.taskTitle +  "\" of task \"" + task.taskTitle + "\" has all of its prequisities completed.");
          
          // Update the status of this dependency.
          await taskCollection.updateOne({_id: dependTasks._id}, {$set: {allPrequisitesDone: true}});

        } else {

          console.log("Dependency \"" + dependTasks.taskTitle +  "\" of task \"" + task.taskTitle + "\" prequisities no longer has all of its prequisites completed.");
    
          if (dependTasks.progress === "Completed"){
            // Update the status of this dependency.
            await taskCollection.updateOne({_id: dependTasks._id}, {$set: {progress: "In-progress", allPrequisitesDone: false}});
          } else {
            await taskCollection.updateOne({_id: dependTasks._id}, {$set: { allPrequisitesDone: false}});
          }
        }  
      }
    }

    return res.status(200).json({message: "Task updated successfully"});

  } catch (error) {
    console.error("Error updating task:", error);
    error = "Internal server error";
    return res.status(500).json({ error });
  }
});

//-------------> Update Task Category ONLY <------------//
router.put("/tasks/:id/category", async (req, res) => {
  const { id } = req.params;
  const { taskCategory } = req.body;
  let error = "";

  if (!taskCategory) {
    error = "Task category is required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const taskCategoriesCollection = db.collection("task_categories");

    // Find the category by its name
    const category = await taskCategoriesCollection.findOne({ categoryTitle: taskCategory });

    let categoryId;
    if (category) {
      // If the category exists, update the tasksUnder array
      categoryId = category._id;
      await taskCategoriesCollection.updateOne(
        { categoryTitle: taskCategory },
        { $addToSet: { tasksUnder: new ObjectId(id) } } // Prevent duplicates
      );
    } else {
      // If category doesn't exist, create a new category and associate the task with it
      const newCategory = {
        categoryTitle: taskCategory,
        tasksUnder: [new ObjectId(id)],
      };

      const insertResult = await taskCategoriesCollection.insertOne(newCategory);
      categoryId = insertResult.insertedId;
    }

    // Update the task's category in the tasks collection
    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { taskCategory, taskCategoryId: new ObjectId(categoryId) } }
    );

    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating task category:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


//-----------> Create Task Category <----------------//
router.post("/taskcategories", async (req, res) => {
  const { categoryTitle } = req.body;
  let error = "";

  if (!categoryTitle) {
    error = "Category title is required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCategoriesCollection = db.collection("task_categories");

    // Step 1: Check if the category already exists
    const existingCategory = await taskCategoriesCollection.findOne({ categoryTitle });

    if (existingCategory) {
      return res.status(200).json(existingCategory); // If category exists, return the existing category
    }

    // Step 2: If category doesn't exist, create a new one
    const newCategory = {
      categoryTitle,
      tasksUnder: [],
    };

    const insertResult = await taskCategoriesCollection.insertOne(newCategory);

    // Step 3: Return the newly created category
    const createdCategory = await taskCategoriesCollection.findOne({
      _id: insertResult.insertedId,
    });

    res.status(201).json(createdCategory); // Return the newly created category
  } catch (error) {
    console.error("Error creating task category:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-----------------> Delete Task <-----------------//
router.delete("/tasks/:id", async (req, res) => {
  const { id: taskId } = req.params;
  const { projectId: projectId } = req.body;
  let error = "";

  console.log(taskId, projectId)
  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const projectsCollection = db.collection("projects");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");
    const task = await taskCollection.findOne({_id: new ObjectId(taskId)});
    
    // Remove all prequisites attached to this task.
    if (task.prerequisiteTasks && task.prerequisiteTasks.length > 0) {
      console.log("Removing these task(s) as a dependency for each task's prequisites.\n");
      console.log(task.prerequisiteTasks);
      await taskCollection.updateMany({_id: {$in: task.dependentTasks}}, {$pull: {dependentTasks: new ObjectId(taskId)}})
    }

    // Dependent tasks for this deleted task no longer have this task as a prequisite.
    if (task.dependentTasks && task.dependentTasks.length > 0) {
      console.log("Removing these task(s) as a dependency for tasks that have this task as a prequisite.");

      // Find all dependencies of this task. 
      var allDependencies = await taskCollection.find({_id: {$in: task.dependentTasks}}, {prerequisiteTasks: 1, assignedTasksUsers: 1, taskTitle: 1}).toArray();
      
      // Determine if removing this task consequentially caused its dependent tasks to remove a prequisite,
      // and potentially now having its prequisite tasks completed. 
      for (const dependTasks of allDependencies) {
        console.log("Dependent task of this task:" + dependTasks);

        // Remove this task as a prequisite to this task.
        await taskCollection.updateOne({_id: dependTasks._id}, {$pull: {prerequisiteTasks: new ObjectId(taskId)}});

        // Check each dependent task's prequisities.
        var completedDependPrequisites = await taskCollection.find({$and: [{_id: {$in: dependTasks.prerequisiteTasks}}, {progress: {$eq: "Completed"}}]}, {progress: 1}).toArray(); 
        
        // If this task caused those tasks status to change...
        if (dependTasks.prerequisiteTasks.length !== 0 || dependTasks.prerequisiteTasks.length === completedDependPrequisites.length){
          
          console.log("After deleting its prequisite task, dependency " + dependTasks.taskTitle +  " of task " + task.taskTitle + " has all of its prequisities completed.");
          
          // Update the status of this dependency.
          await taskCollection.updateOne({_id: dependTasks._id}, {$set: {allPrequisitesDone: true}});

        } else {

          console.log("After deleting its prequisite task, dependency " + dependTasks.taskTitle +  " of task " + task.taskTitle + " prequisities no longer has all of its prequisites completed.");
          
          // Update the status of this dependency.
          await taskCollection.updateOne({_id: dependTasks._id}, {$set: {allPrequisitesDone: false}});

        }
      }      
    }

    // Deleting task in tasks collection
    const taskDeleteResult = await taskCollection.deleteOne({ _id: new ObjectId(taskId) });
    if (taskDeleteResult.deletedCount === 0) {
      return res.status(404).json({ message: "Task not found" });
    }

    const projectUpdateResult = await projectsCollection.updateOne(
      { 
        _id: new ObjectId(projectId),
        tasks: new ObjectId(taskId) // Ensure the taskId exists in the tasks array
      },
      { 
        $pull: { 
          tasks: new ObjectId(taskId) // Pull the task by taskId (ObjectId)
        } 
      }
    );

    if (projectUpdateResult.modifiedCount === 0) {
      return res.status(404).json({ message: "Task not found in project" });
    }
        
    // Remove this task from all to-do lists.
    // Find the tied project this task is under.
    const project = await projectsCollection.findOne({_id: task.tiedProjectId});

    // Find all members of this project.
    const projectTeam = await teamCollection.findOne({_id: project.team});

    // For each person tied to this project, remove this project and tasks from their project arrays and to-do lists.
    var founderOnProject = [projectTeam.founderId];
    const allUsersOnProject = founderOnProject.concat(projectTeam.editors, projectTeam.members);

    // Remove this task from the to-do lists of each user on this project.
    await userCollection.updateMany(
      {_id: {$in: allUsersOnProject.map((id) => new ObjectId(id))}}, 
      {$pull: {toDoList: new ObjectId(taskId)}}
    );

    res.status(200).json({ message: "Task deleted successfully from both task and project collections." });


  } catch (error) {
    console.error("Error deleting task:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

// --------------> Get all Task Categories <-----------//
router.get('/taskcategories', async (req, res) => {
  try {
    const db = client.db("ganttify");
    const taskCategoriesCollection = db.collection("task_categories");

    const taskCategories = await taskCategoriesCollection.find().toArray(); // Fetch all categories

    res.status(200).json(taskCategories); // Return the task categories as a JSON array
  } catch (error) {
    console.error("Error fetching task categories:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------> Assign user to a task <----------------- //
router.post("/assignusertotask", async (req, res) => {
  const { taskId, userId } = req.body;

  if (!taskId || !userId) {
    return res.status(400).json({ error: "Task ID and user ID are required" });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    //Check if the user is already assigned to the task
    const task = await taskCollection.findOne({
      _id: new ObjectId(taskId),
      assignedTasksUsers: new ObjectId(userId)
    });

    if (task) {
      return res.status(400).json({error: "User is already assigned to this task"});
    }

    // Update task to add user to assignedTasksUsers 
    const result = await taskCollection.updateOne(
      { _id: new ObjectId(taskId) },
      { $addToSet: { assignedTasksUsers: new ObjectId(userId) } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.status(200).json({ message: "User assigned to task successfully" });
  } catch (error) {
    console.error("Error assigning user to task:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------> Assign task to a project <----------------- //
router.post("/assigntaskstoproject", async (req, res) => {
  const { projectId, taskId } = req.body;
  let error = "";

  if (!projectId || !taskId || !Array.isArray(taskId) || taskId.length === 0) {
    error = "Project ID and an array of Task IDs are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");

    // Ensure the project exists
    const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });
    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    // Ensure all tasks exist
    const tasks = await taskCollection.find({
      _id: { $in: taskId.map(id => new ObjectId(id)) }
    }).toArray();

    if (tasks.length !== taskId.length) {
      return res.status(404).json({ error: "One or more tasks not found" });
    }

    // Check if any of the tasks are already assigned to the project
    const assignedTasks = await taskCollection.find({
      _id: { $in: taskId.map(id => new ObjectId(id)) },
      tiedProjectId: new ObjectId(projectId)
    }).toArray();

    if (assignedTasks.length > 0) {
      const alreadyAssignedTasks = assignedTasks.map(task => task._id.toString());
      return res.status(400).json({ error: `Task is already assigned to this project` });
    }

    // Add taskId to the project's tasks array
    await projectCollection.updateOne(
      { _id: new ObjectId(projectId) },
      { $addToSet: { tasks: { $each: taskId.map(id => new ObjectId(id)) } } }
    );

    // Update each task's tiedProjectId field
    await taskCollection.updateMany(
      { _id: { $in: taskId.map(id => new ObjectId(id)) } },
      { $set: { tiedProjectId: new ObjectId(projectId) } }
    );

    res.status(200).json({ message: "Tasks assigned to project successfully" });
  } catch (error) {
    console.error("Error assigning tasks to project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Project CRUD Operations
//-----------------> Create a project / Import a project <-----------------//
router.post("/createproject", async (req, res) => {
  const { nameProject, isVisible = 1, founderId, flagDeletion = 0, csvData } = req.body;
  let error = "";

  if (!nameProject || !founderId) {
    return res.status(400).json({ error: "Project name required." });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const tasksCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

    
    let parsedCSV = [];
    if (csvData) {
      try {
        if (typeof csvData === "string") {
          parsedCSV = await parseCSV(csvData.trim());
        } else if (Array.isArray(csvData)) {
          parsedCSV = csvData.filter((row) => row && Object.keys(row).length > 0);
        } else {
          return res.status(400).json({ error: "CSV data format is invalid." });
        }
      } catch (parseError) {
        console.error("Error parsing CSV data:", parseError);
        return res.status(400).json({ error: "Error parsing CSV data." });
      }

      if (!parsedCSV.length) {
        return res.status(400).json({ error: "CSV data is empty or invalid." });
      }
    }

    // Create project object
    const newProject = {
      nameProject,
      dateCreated: new Date(),
      team: null,
      tasks: [],
      isVisible,
      founderId: new ObjectId(founderId),
      flagDeletion,
    };

    // Insert project
    const project = await projectCollection.insertOne(newProject);
    const projectId = project.insertedId;

    // Insert tasks if CSV data exists
    if (parsedCSV.length > 0) {
      const taskDocs = parsedCSV.map((task) => {
        console.log('Raw Task Data:', task); // Debugging

        const taskTitle = task.Task?.trim() || "Untitled Task"; 
        const startDate = task.Start ? new Date(task.Start) : null;
        const endDate = task.End ? new Date(task.End) : null;

        // Handle "No category" case or empty category
        const taskCategory = task.Category && task.Category.trim() !== "No category" ? task.Category : "";

        return {
          taskTitle,
          description: task.Description || "",
          startDateTime: startDate && !isNaN(startDate.getTime()) ? startDate : null,
          dueDateTime: endDate && !isNaN(endDate.getTime()) ? endDate : null,
          taskCreated: new Date(),
          taskCategory,
          taskCategoryId: null,
          color: task.Color,
          pattern: task.Pattern || "No Pattern",
          patternColor: task.patternColor,
          progress: "Not Started",
          assignedTasksUsers: [],
          prerequisiteTasks: [],
          dependentTasks: [],
          allPrequisitesDone: false,
          tiedProjectId: projectId,
          taskCreatorId: new ObjectId(founderId),
        };
      });

      const insertedTasks = await tasksCollection.insertMany(taskDocs);
      const taskIds = Object.values(insertedTasks.insertedIds);

      // Update project with task references
      await projectCollection.updateOne({ _id: projectId }, { $set: { tasks: taskIds } });
    }

    // Create team for the project
    const newTeam = { founderId: new ObjectId(founderId), editors: [], members: [], projects: [projectId] };
    const team = await teamCollection.insertOne(newTeam);

    await projectCollection.updateOne({ _id: projectId }, { $set: { team: team.insertedId } });

    await userCollection.updateOne(
      { _id: new ObjectId(founderId) },
      { $push: { projects: projectId } }
    );

    res.status(201).json({
      success: true,
      project: { ...newProject, _id: projectId, team: team.insertedId },
      csvData: parsedCSV.length > 0 ? parsedCSV : "No CSV data provided",
    });

  } catch (error) {
    console.error("Error creating project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-----------------> Read all projects <-----------------//
router.get("/readprojects", async (req, res) => {
  let error = "";

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const projects = await projectCollection.find({}).toArray();
    res.status(200).json(projects);
  } catch (error) {
    console.error("Error finding projects:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

//-----------------> Read public projects only <-----------------//
router.get("/publicprojects", async (req, res) => {
  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const publicProjects = await projectCollection.find({ isVisible: 1 }).toArray();

    res.status(200).json(publicProjects);
  } catch (error) {
    console.error("Error fetching public projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------> Read specific projects <-----------------//
router.post("/readspecificprojects", async (req, res) => {
  const { projectId } = req.body; // Assuming projectIds is an array of _id values

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const projects = await projectCollection.find({
      _id: { $in: projectId.map(id => new ObjectId(id)) }
    }).toArray();

    res.status(200).json(projects);
  } catch (error) {
    console.error("Error finding projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-----------------> Read all projects for a specific user (public & founder) <-----------------//
router.get("/userprojects/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const accessibleProjects = await projectCollection.find({
      $or: [
        { isVisible: 1 },
        { founderId: new ObjectId(userId) }
      ]
    }).toArray();

    res.status(200).json(accessibleProjects);
  } catch (error) {
    console.error("Error fetching user projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-----------------> Update Project <-----------------//
router.put("/projects/:id", async (req, res) => {
  const { id } = req.params;
  const updateFields = req.body;
  let error = "";

  if (!Object.keys(updateFields).length) {
    error = "No fields provided to update";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    // Convert any provided ObjectId fields
    if (updateFields.team) {
      updateFields.team = new ObjectId(updateFields.team);
    }
    if (updateFields.tasks) {
      updateFields.tasks = updateFields.tasks.map((id) => new ObjectId(id));
    }
    if (updateFields.founderId) {
      updateFields.founderId = new ObjectId(updateFields.founderId);
    }
    if (updateFields.group) {
      updateFields.group = new ObjectId(updateFields.group);
    }

    const result = await projectCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields },
    );

    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

//-------> Update Project Name ONLY <-----------//
router.put('/projects/updateProjectName/:id', async (req, res) => {
  const { id } = req.params;
  const { nameProject } = req.body;
  let error = "";

  // Validate the project ID
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid project ID format' });
  }

  // Validate the new project name
  if (!nameProject || typeof nameProject !== 'string' || nameProject.trim() === '') {
    console.log("Invalid or empty project name:", nameProject);
    return res.status(400).json({ error: 'Project name cannot be empty or invalid' });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    //Fetch the current project
    const project = await projectCollection.findOne({ _id: new ObjectId(id) });
    if (!project) {
      console.log("Project not found:", id);
      return res.status(404).json({ error: "Project not found" });
    }

    // Update the project name
    const result = await projectCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { nameProject: nameProject.trim() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Fetch the updated project
    const updatedProject = await projectCollection.findOne({ _id: new ObjectId(id) });
    console.log("Updated project:", updatedProject);

    res.status(200).json({
      message: 'Project name updated successfully',
      updatedProject
    });

  } catch (error) {
    console.error("Error updating project name:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//----------------> Fetch the project by ID (added) <---------//
router.get("/projects/:projectId", async (req, res) => {
  const { projectId } = req.params;

  try {
      const db = client.db("ganttify");
      const projectCollection = db.collection("projects");
      const tasksCollection = db.collection("tasks");

      // Fetch the project by its ID
      const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });

      if (!project) {
          return res.status(404).json({ error: "Project not found" });
      }

      // Fetch tasks associated with the project
      const tasks = await tasksCollection.find({ projectId: new ObjectId(projectId) }).toArray();

      // Return the project data along with tasks
      res.status(200).json({ project, tasks });
  } catch (error) {
      console.error("Error fetching project:", error);
      res.status(500).json({ error: "Internal server error" });
  }
});


Date.prototype.addDays = function(days) {
    var date = new Date(this.valueOf());
    date.setDate(date.getDate() + days);
    return date;
}

//-----------------> Delete a project <-----------------//
router.delete("/projects/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const deletedProjectsCollection = db.collection("recently_deleted_projects");
    const deletedTasksCollection = db.collection("recently_deleted_tasks");
    const deletedTeamsCollection = db.collection("recently_deleted_teams");
    const results = db.collection('userAccounts');
    const projectEmail = await projectCollection.findOne({ _id: new ObjectId(id) });
    const user = await results.findOne({_id: projectEmail.founderId});

    const email = user.email;

    // Ensure TTL index exists
    await deletedProjectsCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    await deletedTasksCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    await deletedTeamsCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    // Find the project to delete
    const project = await projectCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Add necessary field for tracking account deletion date.
    project.dateMoved = new Date();

    // Insert the project into the deleted_projects collection
    await deletedProjectsCollection.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await taskCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
          dateMoved: new Date(),
        }));
        await deletedTasksCollection.insertMany(tasksToMove);
        console.log("Tasks moved to deleted_tasks"); // Debugging line
        // Delete the associated tasks from the main collection
        await taskCollection.deleteMany({ _id: { $in: taskIds } });
      } else {
        console.log("No tasks found for the project"); // Debugging line
      }
    } else {
      console.log("No tasks assigned to the project"); // Debugging line
    }

    // Handle associated team
    if (project.team) {
      const teamId = new ObjectId(project.team);
      console.log("Team ID to move:", teamId); // Debugging line
      const team = await teamCollection.findOne({ _id: teamId });
      console.log("Team found:", team); // Debugging line
      if (team) {
        // Set dateMoved for the team
        const teamToMove = {
          ...team,
          dateMoved: new Date(),
        };
        await deletedTeamsCollection.insertOne(teamToMove);
        console.log("Team moved to deleted_teams"); // Debugging line
        // Delete the associated team from the main collection
        await teamCollection.deleteOne({ _id: teamId });
      } else {
        console.log("Team not found for the project"); // Debugging line
      }
    } else {
      console.log("No team assigned to the project"); // Debugging line
    }

    // Delete the project from the main collection
    await projectCollection.deleteOne({ _id: new ObjectId(id) });

    const secureTransporter = await createSecureTransporter();
    if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

    // Send an email notification
    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email, 
      subject: "Project Moved to Recently Deleted",
      text: `Hello,\n\nYour project "${project.nameProject}" has been moved to the Recently Deleted Projects collection. It will remain there for 30 days before permanent deletion.\n\nBest regards,\nThe Ganttify Team`,
    };

    secureTransporter.sendMail(mailDetails, (err, info) => {
      if (err) {
        return res.status(500).json({ error: 'Error sending email' });
      } else {
        return res.status(200).json({ message: 'Project and associated data moved to deleted collections successfully' });
      }
    });

    //res.status(200).json({ message: "Project and associated data moved to deleted collections successfully" });
  } catch (error) {
    console.error("Error deleting project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

// Wipe a project
router.delete("/wipeproject/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const deletedProjectsCollection = db.collection("recently_deleted_projects");
    const deletedTasksCollection = db.collection("recently_deleted_tasks");
    const deletedTeamsCollection = db.collection("recently_deleted_teams");
    const deleteAll = db.collection("VOID");

    // Ensure TTL index exists
    await deleteAll.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 0,
      }
    );

    // Find the project to delete
    const project = await deletedProjectsCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Add necessary field to track account deletion date.
    project.dateMoved = new Date();

    // Insert the project into the VOID collection.
    await deleteAll.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await deletedTasksCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved and metadata for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
          dateMoved: new Date(),
        }));
        await deleteAll.insertMany(tasksToMove);
        console.log("Tasks moved to deleted_tasks"); // Debugging line
        // Delete the associated tasks from the main collection.
        await deletedTasksCollection.deleteMany({ _id: { $in: taskIds } });
      } else {
        console.log("No tasks found for the project"); // Debugging line
      }
    } else {
      console.log("No tasks assigned to the project"); // Debugging line
    }

    // Handle associated team
    if (project.team) {
      const teamId = new ObjectId(project.team);
      console.log("Team ID to move:", teamId); // Debugging line
      const team = await deletedTeamsCollection.findOne({ _id: teamId });
      console.log("Team found:", team); // Debugging line
      if (team) {
        // Set dateMoved and metadata for the team
        const teamToMove = {
          ...team,
          dateMoved: new Date(),
        };
        await deleteAll.insertOne(teamToMove);
        console.log("Team moved to deleted_teams"); // Debugging line
        // Delete the associated team from the main collection
        await deletedTeamsCollection.deleteOne({ _id: teamId });
      } else {
        console.log("Team not found for the project"); // Debugging line
      }
    } else {
      console.log("No team assigned to the project"); // Debugging line
    }

    // Delete the project from the main collection
    await deletedProjectsCollection.deleteOne({ _id: new ObjectId(id) });

    res.status(200).json({ message: "Project and associated data have been wiped successfully" });
  } catch (error) {
    console.error("Error wiping project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

// -----------------> Update/edit a specific user profile <-----------------//
router.put("/user/:userId", async (req, res) => {
  const userId = req.params.userId;
  const { name, username, phone, discordAccount, pronouns, organization, timezone } = req.body;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Validate that the user exists.
    const user = await userCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let updateName = await encryptClient.encrypt(name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    let updateUsername = await encryptClient.encrypt(username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    let updatePhone = await encryptClient.encrypt(phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    let updatePronouns = await encryptClient.encrypt(pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    let updateDiscord = await encryptClient.encrypt(discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    let updateOrganization = await encryptClient.encrypt(organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    let updateTimezone = await encryptClient.encrypt(timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

    // Update only if necessary.
    // upsert field ($or) determines if the update will perform.
    // Approach taken from MongoDB documentation and here:
    // https://www.mongodb.com/community/forums/t/update-document-only-if-new-data-differs-from-current-data/139827/2
    await userCollection.updateOne(
      {_id: new ObjectId(userId), 
        $or:
        [
          {name: {$ne: ["name", updateName]}},
          {username: {$ne: ["username", updateUsername]}},
          {phone: {$ne: ["phone", updatePhone]}},
          {pronouns: {$ne: ["pronouns", updatePronouns]}},
          {discordAccount: {$ne: ["discordAccount", updateDiscord]}},
          {organization: {$ne: ["organization", updateOrganization]}},
          {timezone: {$ne: ["timezone", updateTimezone]}}
        ]
      },
      {$set: 
        {
          name: updateName, 
          username: updateUsername, 
          phone: updatePhone, 
          pronouns: updatePronouns,
          discordAccount: updateDiscord,
          organization: updateOrganization,
          timezone: updateTimezone
        },
      } 
    );

    // Fetch the updated user.
    const updatedUser = await userCollection.findOne(
      { _id: new ObjectId(userId) },
      { projection: { password: 0 } }
    );

    console.log(updatedUser);
    
    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint to initiate account deletion.
// This must be password-protected simliarly to the edit email API endpoint.
router.post("/user/request-delete/:userId", async (req, res) => {
  const userId = req.params.userId;
  const {password} =  req.body;

  try {

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Validate that the user exists.
    const user = await userCollection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    console.log("Found user information:\n");
    console.log(user);

    // Verify if user entered in correct password before proceeding with deletion.
    const match = await bcrypt.compare(password, user.password);

    if (!match){
      return res.status(401).send("Incorrect password. Please try again.");
    }

    const email = user.email;
    const secret = process.env.JWT_SECRET + user.password;
    const token = jwt.sign({ email: email }, secret, { expiresIn: "5m" }); // Token valid for 5 minutes

    // Configure Nodemailer transport.
    const secureTransporter = await createSecureTransporter();
    if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

    let link = GANTTIFY_LINK+`/confirm-delete/${userId}/${token}`;

    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: "Confirm Account Deletion",
      text: `Hello,\n\nTo confirm the deletion of your account, please click the link below:\n\n${link}\n\nIf you did not request this, please ignore this email.`,
      html: `<p>Hello,</p> <p>To confirm the deletion of your account, please click the link below:\n</p> <a href="${link}" className="btn">Delete Account</a> <p>If you did not request this, please ignore this email.</p>`,
    };

    secureTransporter.sendMail(mailDetails, (err, info) => {
      if (err) {
        return res.status(500).json({ error: 'Error sending email' });
      } else {
        return res.status(200).json({ message: 'Account deletion confirmation email sent successfully.' });
      }
    });
  } catch (error) {
    console.error("Error initiating account deletion:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint to confirm and delete the account
router.delete("/user/confirm-delete/:userId/:token", async (req, res) => {
  const { userId, token } = req.params;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const deletedAccountCollection = db.collection("deleted_user_accounts");
    const deletedAccountProjectsCollection = db.collection("deleted_account_projects");
    const deletedAccountTasksCollection = db.collection("deleted_account_tasks");
    const deletedAccountTeamsCollection = db.collection("deleted_acount_teams");
    
    // Ensure that TTL exists.
    await deletedAccountCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 259200, // expires in 72 hours.
      }
    );

    await deletedAccountProjectsCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    await deletedAccountTasksCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    await deletedAccountTeamsCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    // Find the user.
    const user = await userCollection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    try {
      
      const email = user.email;
      const secret = process.env.JWT_SECRET + user.password;
      jwt.verify(token, secret);

      // Proceed with deletion. First handle find all projects owned by the user and associated data.
      var allProjects = await projectCollection.find({founderId: new ObjectId(userId)}).toArray();

      if (allProjects && allProjects.length > 0){
        for (project of allProjects){
          // Add an expiration date to the project.
          project.dateMoved = new Date();
          // Handle this project's associated tasks.
           if (project.tasks && project.tasks.length > 0) {
            const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
            console.log("Task IDs to move:", taskIds); // Debugging line
            
            // Find all tasks associated with this project.
            const tasks = await taskCollection.find({ _id: { $in: taskIds } }).toArray();
            console.log("Tasks found:", tasks); // Debugging line
            
            if (tasks.length > 0) {
              // Set dateMoved for tasks
              const tasksToMove = tasks.map(task => ({
                ...task,
                accountDeleted: new Date(),
              }));
              
              await deletedAccountTasksCollection.insertMany(tasksToMove);
              console.log("Tasks moved to deleted_tasks"); // Debugging line
              // Delete the associated tasks from the main collection
              await taskCollection.deleteMany({ _id: { $in: taskIds }});
  
            } else {
              console.log("No tasks found for the project"); // Debugging line
            }
          } else {
            console.log("No tasks assigned to the project"); // Debugging line
          }
  
          // Handle associated team.
          if (project.team) {
            const teamId = new ObjectId(project.team);
            console.log("Team ID to move:", teamId); // Debugging line
  
            // Find team associated with this project.
            const team = await teamCollection.findOne({ _id: teamId });
            console.log("Team found:", team); // Debugging line
            if (team) {
              // Set dateMoved and metadata for the team
              const teamToMove = {
                ...team,
                accountDeleted: new Date(),
              };
              
              await deletedAccountTeamsCollection.insertOne(teamToMove);
              console.log("Team moved to deleted_teams"); // Debugging line
  
              // Delete the associated team from the main collection
              await teamCollection.deleteOne({ _id: teamId });
  
            } else {
              console.log("Team not found for the project"); // Debugging line
            }
          } else {
            console.log("No team assigned to the project"); // Debugging line
          }
        }
        // Delete all projects associated with the user afterwards.
        await deletedAccountProjectsCollection.insertMany(allProjects);
        await projectCollection.deleteMany({ _id: { $in: user.projects.map(id => new ObjectId(id))}});
      }

      // After all associated data is handled, delete the user account itself while moving it to a temporary holding collection for 72 hours.
      // Encrypt data first.
      var encryptEmail = await encryptClient.encrypt(user.email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptName = await encryptClient.encrypt(user.name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptPhone = await encryptClient.encrypt(user.phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptUsername = await encryptClient.encrypt(user.username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptPassword = await encryptClient.encrypt(user.password, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptDiscord = await encryptClient.encrypt(user.discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
	    var encryptOrganization = await encryptClient.encrypt(user.organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptTimezone = await encryptClient.encrypt(user.timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptPronouns = await encryptClient.encrypt(user.pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

      const encryptDeleteUser ={
        _id: user._id,
        email: encryptEmail,
	      name: encryptName,
	      phone: encryptPhone,
        username: encryptUsername,
	      password: encryptPassword,
	      discordAccount: encryptDiscord,
	      organization: encryptOrganization,
	      pronouns: encryptPronouns,
	      timezone: encryptTimezone,
	      accountCreated: user.accountCreated,
	      isEmailVerified: user.isEmailVerified,
        accountDeleted: new Date()
      };

      // Delete the old account, then move it to the temporary collection.
      const deleteResult = await userCollection.deleteOne({ _id: new ObjectId(userId) });
      const resultTempAccount = await deletedAccountCollection.insertOne(encryptDeleteUser);

      if (deleteResult.deletedCount === 0) {
        return res.status(400).json({ error: "Failed to delete user." });
      }

      // Configure Nodemailer transport.
      const secureTransporter = await createSecureTransporter();
      if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

      const newSecret = process.env.JWT_SECRET + user.password;
      const newToken = jwt.sign({ email: email }, newSecret, { expiresIn: "72h" }); // Token valid for 72 hours.

      // Set up this restoration link.
      let restoreLink = GANTTIFY_LINK+`/restore-account/${userId}/${newToken}`;

      // Send an email notification
      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: "Ganttify Account Deletion",
        text: `Hello,\n\nYour account has been deleted from our system. We are sorry to see you go!\n\n${restoreLink}\n\nIf you did not request this, please ignore this email.`,
        html: `<p>Hello,</p> <p>Your account has been deleted from our system. We are sorry to see you go!\n\nAfter confirming your account deletion, you can recover your account and your associated data within 72 hours by clicking the below link:\n</p> <a href="${restoreLink}" className="btn">Restore Your Account</a> <p>If you did not request this, please ignore this email.</p>`,
      };

      secureTransporter.sendMail(mailDetails, (err, info) => {
        if (err) {
          return res.status(500).json({ error: 'Error sending email' });
        } else {
          return res.status(200).json({ message: 'Account and associated data moved to deleted collections successfully' });
        }
      });

    } catch (error) {
      console.error("Token verification failed:", error);
      return res.status(400).json({ error: "Invalid or expired token" });
    }

  } catch (error) {
    console.error("Error confirming account deletion:", error);
    res.status(500).json({ error: "Internal server error" });
  }

});

// Endpoint to restore the account via clicking on the email link.
router.post("/user/restore-account/:userId/:token", async (req, res) => {
  const { userId, token } = req.params;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const deletedAccountCollection = db.collection("deleted_user_accounts");
    const deletedAccountProjectsCollection = db.collection("deleted_account_projects");
    const deletedAccountTasksCollection = db.collection("deleted_account_tasks");
    const deletedAccountTeamsCollection = db.collection("deleted_acount_teams");
    
    // Ensure that TTL exists.
    await deletedAccountCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 259200, // expires in 72 hours.
      }
    );

    await deletedAccountProjectsCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 2592000, // expires in 72 hours.
      }
    );

    await deletedAccountTasksCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    await deletedAccountTeamsCollection.createIndex(
      { "accountDeleted": 1 },
      {
        expireAfterSeconds: 2592000,
      }
    );

    // Find the user. Ensure that the user does not attempt to use this endpoint when the user account already exists.
    const exist = await userCollection.findOne({_id: new ObjectId(userId) });
    const user = await deletedAccountCollection.findOne({ _id: new ObjectId(userId) });

    if (exist){return res.status(403).json({error: "Your account already exists."});} // indicates that the account is already present and not deleted.
    if (!user) {return res.status(404).json({ error: "Your account does not exist, or your account has been permanently deleted after 72 hours." });} // indicates that data was already wiped.

    console.log("Project ids to restore.");
    console.log(user.projects);
    const email = user.email;
    const secret = process.env.JWT_SECRET + user.password;

    try {

      jwt.verify(token, secret);

      // Proceed with restoration. First handle find all projects and associated data.
      var allProjects = await deletedAccountProjectsCollection.find({founderId: new ObjectId(userId)}).toArray();

      if (allProjects && allProjects.length > 0){
        for (project of allProjects){
          // Remove unnecessary field for dateMoved.
          delete project.dateMoved;
          // Handle associated tasks
          if (project.tasks && project.tasks.length > 0) {
            const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
            console.log("Task IDs to move:", taskIds); // Debugging line
            
            const tasks = await deletedAccountTasksCollection.find({ _id: { $in: taskIds } }).toArray();
            console.log("Tasks found:", tasks); // Debugging line
            
            if (tasks.length > 0) {
              const tasksToMove = tasks.map(task => ({
                ...task,
              }));
              await taskCollection.insertMany(tasksToMove);
              console.log("Tasks moved to deleted_tasks"); // Debugging line
              // Delete the associated tasks from the main collection
              await deletedAccountTasksCollection.deleteMany({ _id: { $in: taskIds } });
            } else {
              console.log("No tasks found for the project"); // Debugging line
            }
  
          } else {
            console.log("No tasks assigned to the project"); // Debugging line
          }
  
          // Handle associated team
          if (project.team) {
            
            const teamId = new ObjectId(project.team);
            console.log("Team ID to move:", teamId); // Debugging line
            
            const team = await deletedAccountTeamsCollection.findOne({ _id: teamId });
            console.log("Team found:", team); // Debugging line
            
            if (team) {
              const teamToMove = {
                ...team,
              };
              await teamCollection.insertOne(teamToMove);
              console.log("Team moved to deleted_teams"); // Debugging line
              // Delete the associated team from the main collection
              await deletedAccountTeamsCollection.deleteOne({ _id: teamId });
            } else {
              console.log("Team not found for the project"); // Debugging line
            }
  
          } else {
            console.log("No team assigned to the project"); // Debugging line
          }
        }
        // Afterwards, restore the projects.
        await projectCollection.insertMany(allProjects);
        await deletedAccountProjectsCollection.deleteMany({ _id: { $in: user.projects.map(id => new ObjectId(id))}});
      }

      // After all associated data is handled, restore the user account itself.
      // Encrypt data first.
      var encryptEmail = await encryptClient.encrypt(user.email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptName = await encryptClient.encrypt(user.name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptPhone = await encryptClient.encrypt(user.phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptUsername = await encryptClient.encrypt(user.username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptPassword = await encryptClient.encrypt(user.password, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptDiscord = await encryptClient.encrypt(user.discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
	    var encryptOrganization = await encryptClient.encrypt(user.organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptTimezone = await encryptClient.encrypt(user.timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var encryptPronouns = await encryptClient.encrypt(user.pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

      const encryptRestoreUser ={
        _id: user._id,
        email: encryptEmail,
	      name: encryptName,
	      phone: encryptPhone,
        username: encryptUsername,
	      password: encryptPassword,
	      discordAccount: encryptDiscord,
	      organization: encryptOrganization,
	      pronouns: encryptPronouns,
	      timezone: encryptTimezone,
	      accountCreated: user.accountCreated,
	      isEmailVerified: user.isEmailVerified,
      };

      // Remove from the temporary collection and return to the regular user collection.
      const deleteResult = await deletedAccountCollection.deleteOne({ _id: new ObjectId(userId) });
      await userCollection.insertOne(encryptRestoreUser);

      if (deleteResult.deletedCount === 0) {
        return res.status(400).json({ error: "Failed to remove user's old data from temporary collection." });
      }

      // Configure Nodemailer transport.
      const secureTransporter = await createSecureTransporter();
      if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

      // Send an email notification
      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email, 
        subject: "Ganttify Account Restored...Welcome Back!",
        text: 'Hello,\n\nYour account has been restored from our system.\n\nWe are glad to see you back!\n\nYou are now able to login again and see your projects.',
      };

      secureTransporter.sendMail(mailDetails, (err, info) => {
        if (err) {
          return res.status(500).json({ error: 'Error sending email' });
        } else {
          return res.status(200).json({ message: 'Account and associated data restored from deleted collections successfully.' });
        }
      });

    }catch (error) {
      console.error("Token verification failed:", error);
      return res.status(400).json({ error: "Invalid or expired token" });
    }

  } catch (error) {
    console.error("Error confirming account deletion:", error);
    res.status(500).json({ error: "Internal server error" });
  }

});

// -----------------> Delete a specific user <-----------------//
router.delete("/user/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Validate that the user exists
    const user = await userCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    const deleteResult = await userCollection.deleteOne({ _id: new ObjectId(userId) });

    if (deleteResult.deletedCount === 0) {
      return res.status(400).json({ error: "Failed to delete user" });
    }

    res.status(200).json({ message: "User account deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//////////////////////
// SEARCH ENDPOINTS //
//////////////////////

// -----------------> Search a specific user <-----------------//
router.get("/user/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    const user = await userCollection.findOne(
      { _id: new ObjectId(userId) },
      { projection: { password: 0 } } // Exclude the password field
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.status(200).json(user);
  } catch (error) {
    console.error("Error finding user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------> Get All Users <-----------------//
router.get("/allusers", async (req, res) => {
  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Retrieve all users excluding their passwords
    const users = await userCollection.find({}, { projection: { password: 0 } }).toArray();
    
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//------------------> Search users by ids<-------------------------------------//
router.post("/search/taskworkers", async (req, res) => {
  const { ids } = req.body;
  //console.log(ids);
  const oIds = ids.map((id) => new ObjectId(id));
  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    const query = {_id : {$in : oIds}};

    // Find users matching ids excluding passwords
    const users = await userCollection.find(query).project({name:1,phone:1,email:1}).toArray();
    //console.log(users);
    res.status(200).json(users);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------> Search users by email, name, username or projects <-----------------//
router.post("/searchusers", async (req, res) => {
  const { email, name, username, projects } = req.body;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Build search criteria array
    const searchCriteria = [];
    if (email) searchCriteria.push({ email: email });
    if (name) searchCriteria.push({ name: name });
    if (username) searchCriteria.push({ username: username });
    if (projects && projects.length) {
      // Search for users where the projects field contains any of the given project IDs
      searchCriteria.push({ projects: { $in: projects.map(id => new ObjectId(id)) } });
    }

    // Check if there are any search criteria
    if (searchCriteria.length === 0) {
      return res.status(400).json({ error: "At least one search parameter must be provided" });
    }

    // Find users matching any of the search criteria, excluding passwords
    const users = await userCollection.find({
      $or: searchCriteria
    }, {
      projection: { password: 0 } // Exclude password from the results
    }).toArray();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-> Search Project by Title & Sort by Date Created <-//
router.post("/search/projects", async (req, res) => {

    const { founderId, title, sortBy = "dateCreated" } = req.body;
  
    try {
      const db = client.db("ganttify");
      const projectCollection = db.collection("projects");
      const teamCollection = db.collection("teams");
  
      const teams = await teamCollection.find({
        $or: [
          { founderId: new ObjectId(founderId) },
          { editors: new ObjectId(founderId) },
          { members: new ObjectId(founderId) }
        ]
      }).toArray();
  
     console.log("These are the teams: ", teams);
  
      const teamIds = teams.map(team => new ObjectId(team._id));
  
     console.log("These are the team IDs: ", teamIds);
  
      const query = {
        $or: [
          { founderId: new ObjectId(founderId) },
          { team: { $in: teamIds } }
        ],
        nameProject: { $regex: title, $options: "i" }
      };
  
      console.log("These are the query: ", query);
  
      const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending
  
      const projects = await projectCollection
        .find(query)
        .sort(sortOptions)
        .toArray();
  
      res.status(200).json(projects);
  
      console.log("These are the projects: ", projects);
  
    } catch (error) {
      console.error("Error searching projects:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }); 
  
//-> Search Recently-Deleted Projects by Title & Sort by Due Date <-//
router.post("/search/recently-deleted", async (req, res) => {

  const { founderId, title, sortBy = "dueDate" } = req.body;

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("recently_deleted_projects");
    const query = {founderId: new ObjectId(founderId), nameProject: { $regex: title, $options: "i" } };
    const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending

    const projects = await projectCollection
      .find(query)
      .sort(sortOptions)
      .toArray();

    res.status(200).json(projects);

  } catch (error) {
    console.error("Error searching projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}); 

//-> Search Categories by Title and Sort by Completion Percentage <-//
router.post("/search/categories", async (req, res) => {
  const { title, sortBy = "completionPercentage" } = req.body;

  try {
    const db = client.db("ganttify");
    const categoryCollection = db.collection("categories");

    const query = { title: { $regex: title, $options: "i" } };
    const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending

    const categories = await categoryCollection
      .find(query)
      .sort(sortOptions)
      .toArray();

    res.status(200).json(categories);
  } catch (error) {
    console.error("Error searching categories:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Search Task by Name, Due Date, (Sort by Completion Percentage)
router.post("/search/tasks", async (req, res) => {
  //need to also add functionality for teamId, we'll get there
  const {founderId, name, dueDate, sortBy = "completionPercentage" } = req.body;
  const query = {};

  if (!dueDate) {
    query.description = { founderId:founderId,$regex: name, $options: "i" };
  } else {
    query.description = { founderId: founderId, $gte: new Date(dueDate) };
  }
  console.log(query);

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending
    const tasks = await taskCollection.find(query).sort(sortOptions).toArray();

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error searching tasks:", error);
    res.status(500).json({ error: "Internal server error" });
  }

});

//-> Search Task for Specific User on Project Team <-//
router.post("/search/tasks/users", async (req, res) => {
  const { projectId, userId } = req.body;

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const query = {
      tiedProjectId: ObjectId(projectId),
      assignedTasksUsers: ObjectId(userId),
    };

    const tasks = await taskCollection.find(query).toArray();

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error searching tasks for user on project team:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-> Search Tasks for Specific User  <-//
router.post("/search/tasks/todo", async (req, res) => {
    const { userId } = req.body;
  
    try {
      const db = client.db("ganttify");
      const taskCollection = db.collection("tasks");
  
      const query = {
        assignedTasksUsers: new ObjectId(userId),
      };
      
      const tasks = await taskCollection.find(query).sort({dueDateTime: 1}).toArray();
  
      res.status(200).json(tasks);
    } catch (error) {
      console.error("Error searching tasks for user on project team:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

//-------------> Display team info <-------------//
router.get('/teams/:teamId/teaminfo', async (req, res) => {
  const { teamId } = req.params;

  if (!teamId) {
    return res.status(400).json({ error: "Team ID is required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts"); // Changed from 'users' to 'userAccounts'

    // Validate teamId
    if (!ObjectId.isValid(teamId)) {
      return res.status(400).json({ error: "Invalid Team ID format" });
    }

    // Convert teamId to ObjectId
    const teamObjectId = new ObjectId(teamId);

    // Check if the team exists
    const team = await teamCollection.findOne({ _id: teamObjectId });
    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    // Retrieve the members and editors details
    const members = await userCollection.find({ _id: { $in: team.members } }).toArray();
    const editors = await userCollection.find({ _id: { $in: team.editors } }).toArray();

    return res.status(200).json({
      members: members.map(member => ({ id: member._id, name: member.name })),
      editors: editors.map(editor => ({ id: editor._id, name: editor.name }))
    });
  } catch (error) {
    console.error("Error retrieving team members and editors:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Restore a project
router.post("/restore-project/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const deletedProjectsCollection = db.collection("recently_deleted_projects");
    const deletedTasksCollection = db.collection("recently_deleted_tasks");
    const deletedTeamsCollection = db.collection("recently_deleted_teams");

    // Find the project to restore
    const project = await deletedProjectsCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Remove obsolete field.
    delete project.dateMoved;

    // Insert the project into the deleted_projects collection
    await projectCollection.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await deletedTasksCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved and metadata for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
        }));
        await taskCollection.insertMany(tasksToMove);
        console.log("Tasks moved to deleted_tasks"); // Debugging line
        // Delete the associated tasks from the main collection
        await deletedTasksCollection.deleteMany({ _id: { $in: taskIds } });
      } else {
        console.log("No tasks found for the project"); // Debugging line
      }
    } else {
      console.log("No tasks assigned to the project"); // Debugging line
    }

    // Handle associated team
    if (project.team) {
      const teamId = new ObjectId(project.team);
      console.log("Team ID to move:", teamId); // Debugging line
      const team = await deletedTeamsCollection.findOne({ _id: teamId });
      console.log("Team found:", team); // Debugging line
      if (team) {
        // Set dateMoved and metadata for the team
        const teamToMove = {
          ...team,
        };
        await teamCollection.insertOne(teamToMove);
        console.log("Team moved to deleted_teams"); // Debugging line
        // Delete the associated team from the main collection
        await deletedTeamsCollection.deleteOne({ _id: teamId });
      } else {
        console.log("Team not found for the project"); // Debugging line
      }
    } else {
      console.log("No team assigned to the project"); // Debugging line
    }

    // Delete the project from the main collection
    await deletedProjectsCollection.deleteOne({ _id: new ObjectId(id) });

    res.status(200).json({ message: "Project and associated data restored to collections successfully" });
  } catch (error) {
    console.error("Error restoring project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }

});

// Add members to a team
router.put('/teams/:teamId/members', async (req, res) => {
  const { teamId } = req.params;
  const { members = [] } = req.body;

  if (!teamId) {
    return res.status(400).json({ error: "Team ID is required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

    // Validate teamId
    if (!ObjectId.isValid(teamId)) {
      return res.status(400).json({ error: "Invalid Team ID format" });
    }

    // Validate teamId
    if (!ObjectId.isValid(teamId)) {
      return res.status(400).json({ error: "Invalid Team ID format" });
    }
    
    // Convert teamId to ObjectId
    const teamObjectId = new ObjectId(teamId);

    // Check if the team exists
    const team = await teamCollection.findOne({ _id: teamObjectId });
    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    // Validate user IDs
    for (const id of members) {
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ error: `Invalid user ID format: ${id}` });
      }
    }

    // Convert user IDs to ObjectId
    const memberObjectIds = members.map(id => new ObjectId(id));

    // Verify that all members are valid users
    const users = await userCollection.find({ _id: { $in: memberObjectIds } }).toArray();
    const validUserIds = users.map(user => user._id.toString());
    const invalidMembers = members.filter(id => !validUserIds.includes(id));

    if (invalidMembers.length > 0) {
      return res.status(400).json({ error: "Some provided user IDs are invalid", invalidMembers });
    }

    // Update the team with new members
    const update = {
      $addToSet: {
        members: { $each: memberObjectIds }
      }
    };

    const result = await teamCollection.updateOne({ _id: teamObjectId }, update);

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to update team" });
    }

    return res.status(200).json({ message: "Members added successfully" });
  } catch (error) {
    console.error("Error updating team:", error);
    return res.status(500).json({ error: "Internal server error" });
  }

});

// Update the role of an existing member
router.put('/teams/:teamId/update-role', async (req, res) => {
  const { teamId } = req.params;
  const { userId, newRole } = req.body;

  if (!teamId || !userId || !newRole) {
    return res.status(400).json({ error: "Team ID, user ID, and new role are required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

   
    if (!ObjectId.isValid(teamId) || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid Team ID or User ID format" });
    }

    const teamObjectId = new ObjectId(teamId);
    const userObjectId = new ObjectId(userId);
    const team = await teamCollection.findOne({ _id: teamObjectId });

    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }
    
    const user = await userCollection.findOne({ _id: userObjectId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMember = teamCollection.findOne({members: userObjectId});
    const isEditor = teamCollection.findOne({editors: userObjectId});
    
    if (!isMember && !isEditor) {
      return res.status(404).json({ error: "User not found in the team" });
    }

    let update;

    if (newRole === "editor") {
      update = {
        $addToSet: { editors: userObjectId },
        $pull: { members: userObjectId }
      };

    } else if (newRole === "member") {
      update = {
        $addToSet: { members: userObjectId },
        $pull: { editors: userObjectId }
      };

    } else {
      return res.status(400).json({ error: "Invalid role. Role must be 'editor' or 'member'." });
    }

    const result = await teamCollection.updateOne({ _id: teamObjectId }, update);

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to update user's role in the team" });
    }

    return res.status(200).json({ message: "User's role updated successfully" });

  } catch (error) {
    console.error("Error updating user's role in the team:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Removes members or editors from a team
router.put('/teams/:teamId/removeteammember', async (req, res) => {

  const { teamId } = req.params;
  const { userId, projectId } = req.body;

  if (!teamId || !userId || !projectId) {
    return res.status(400).json({ error: "Team ID, User ID, and Project ID are required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

    if (!ObjectId.isValid(teamId) || !ObjectId.isValid(userId) || !ObjectId.isValid(projectId)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const teamObjectId = new ObjectId(teamId);
    const userObjectId = new ObjectId(userId);
    const projectObjectId = new ObjectId(projectId);
    const team = await teamCollection.findOne({ _id: teamObjectId });

    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    const user = await userCollection.findOne({ _id: userObjectId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMember = team.members.some(memberId => memberId.equals(userObjectId));
    const isEditor = team.editors.some(editorId => editorId.equals(userObjectId));

    console.log("Member: ", isMember, " , isEditor: ", isEditor);

    if (!isMember && !isEditor) {
      return res.status(404).json({ error: "User not found in the team" });
    }

    const update = {
      $pull: {
        members: userObjectId,
        editors: userObjectId
      }
    };

    const result = await teamCollection.updateOne({ _id: teamObjectId }, update);

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to update team" });
    }

    const userUpdateResult = await userCollection.updateOne(
      { _id: userObjectId },
      { $pull: { projects: projectObjectId } }
    );

    return res.status(200).json({ message: "Member removed successfully" });

  } catch (error) {
    console.error("Error updating team:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/search/tasks/project", async (req, res) => {
  const { projectId } = req.body;

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    let tasks = [];

    if (Array.isArray(project.tasks) && project.tasks.length > 0) {
      tasks = await taskCollection.find({
        _id: { $in: project.tasks }
      }).toArray();
    }

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error searching tasks for project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// <------------- Update To-Do List of a task --------------->
router.post("/updateSingleUserToDoList", async (req, res) => {
  const { taskId, userId, isChecked } = req.body;
  let error = "";

  if (!taskId || !userId || typeof isChecked !== 'boolean') {
    error = "Task ID, user ID, and isChecked are required";
    return res.status(400).json({ error });
  }

  try {

    // Update the to-do list of each user.
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    await userCollection.updateOne({ _id: new ObjectId(userId) }, isChecked ? { $addToSet: { toDoList: new ObjectId(taskId) } } : { $pull: { toDoList: new ObjectId(taskId) } });

    res.status(200).json({ message: "User's toDoList updated successfully" });
  } catch (error) {
    console.error("Error updating user's toDoList:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

router.get('/getProjectDetails/:projectId', async (req, res) => {
  const projectId = req.params.projectId;
  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    if (!project.team || !ObjectId.isValid(project.team)) {
      return res.status(404).json({ error: "Invalid team ID in project" });
    }

    const teamCollection = db.collection("teams");
    const team = await teamCollection.findOne({ _id: new ObjectId(project.team) });

    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    project.team = team;
    res.status(200).json(project);
  } catch (error) {
    console.error("Error fetching project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get('/teams/:teamId', async (req, res) => {
  const teamId = req.params.teamId;

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const team = await teamCollection.findOne({ _id: new ObjectId(teamId) });

    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    res.status(200).json(team);
  } catch (error) {
    console.error("Error fetching team:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//Invite team member api's//
router.post('/invite-user', async (req, res) => {
  const { email, projectId } = req.body;

  if (!email || !projectId) {
    return res.status(400).json({ error: 'Email and Project ID are required' });
  }

  try {
    const db = client.db('ganttify');
    const userAccounts = db.collection('userAccounts');
    var queryEncryptedEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const user = await userAccounts.findOne({queryEncryptedEmail});
    const secret = process.env.JWT_SECRET + (user ? user.password : 'newuseraccount');
    const token = jwt.sign({ email, projectId }, secret, { expiresIn: '5m' });
    
    const link = user ? `https://ganttify-5b581a9c8167.herokuapp.com/accept-invite/${token}` : `https://ganttify-5b581a9c8167.herokuapp.com/register/${token}`;

    const secureTransporter = await createSecureTransporter();
    if (secureTransporter == null) {return res.status.json({error: 'Secure transporter for email failed to initialize or send.'});}

    const mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Invitation to Join Ganttify',
      text: `Hello,\n\nYou have been invited to join a project on Ganttify. Click the link to ${user ? 'accept the invitation' : 'create an account and join'}: ${link}`,
      html: `<p>Hello,</p><p>You have been invited to join a project on Ganttify. Click the button below to ${user ? 'accept the invitation' : 'create an account and join'}:</p><a href="${link}" class="btn">Join Ganttify</a>`,
    };

    secureTransporter.sendMail(mailDetails, (err, data) => {

      if (err) {
        return res.status(500).json({ error: 'Error sending email' });
      } else {
        return res.status(200).json({ message: 'Invitation email sent' });
      }

    });
  } catch (error) {
    console.error('Error inviting user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
  

router.get('/accept-invite/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const decodedToken = jwt.decode(token);
    const { email, projectId } = decodedToken;

    const db = client.db('ganttify');
    const userAccounts = db.collection('userAccounts');
    const projectCollection = db.collection('projects');
    const teamCollection = db.collection('teams');
    var queryEncryptedEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const user = await userAccounts.findOne({queryEncryptedEmail});

    if (user) {
      const secret = process.env.JWT_SECRET + user.password;

      try {
        jwt.verify(token, secret);

        await userAccounts.updateOne(
          { _id: user._id },
          { $addToSet: { projects: new ObjectId(projectId) } }
        );

        const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });

        if (!project) {
          return res.status(404).send('Project does not exist');
        }

        await teamCollection.updateOne(
          { _id: new ObjectId(project.team) },
          { $addToSet: { members: user._id } }
        );
        res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
      } catch (error) {
        console.error('Invalid or expired token:', error);
        res.status(400).send('Invalid or expired token');
      }
    } else {
      return res.status(404).send('User does not exist');
    }

  } catch (error) {
    console.error('Error during invitation acceptance:', error);
    res.status(400).send('Invalid ID format');
  }
});

router.put("/tasks/:id/dates", async (req, res) => {
  const { id } = req.params;
  const { dueDateTime, startDateTime } = req.body;
  let error = "";

  if (!dueDateTime && !startDateTime) {
    error = "Both dueDateTime and startDateTime are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const updateFields = {};
    
    if (dueDateTime) {
      updateFields.dueDateTime = new Date(dueDateTime);
    }
    if (startDateTime) {
      updateFields.startDateTime = new Date(startDateTime);
    }

    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields },
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating task dates:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/fetchTask/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const task = await taskCollection.findOne({ _id: new ObjectId(id) });
	  if (!task) {return res.status(404).json({ error: "Task not found" });}
    
      res.status(200).json(task);
  } catch (error) {
    console.error("Error fetching task:", error);
    res.status(500).json({ error: "Internal server error" });
  }	
});

module.exports = router;
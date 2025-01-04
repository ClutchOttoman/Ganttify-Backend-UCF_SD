// CSFLE adapted from https://github.com/mongodb/docs/tree/master/source/includes/generated/in-use-encryption/csfle/node/local/reader/

const express = require("express");
const {MongoClient, ObjectId, ClientEncryption, Timestamp, Binary, UUID} = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodeMailer = require("nodemailer");
const file = require("fs");
const path = require('path');
const crypto = require("crypto");
require("dotenv").config();

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
    
    const newTempUser = {
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
    const token = jwt.sign({email: email}, secret, {expiresIn: "5m",} );

    let link = `http://206.81.1.248/verify-email/${email}/${token}`;
    //let link = `http://localhost:5173/verify-email/${email}/${token}`; // for testing API localhost purposes only.

    const transporter = nodeMailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Verify Your Ganttify Account',
      text: `Hello ${name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
      html: `<p>Hello ${name},</p> <p>Please verify your Ganttify account by clicking the following link:\n</p> <a href="${link}" className="btn">Verify Account</a>`
    };

    transporter.sendMail(mailDetails, function (err, data) {
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
  // NOTE: Email should already be an ecrypted parameter.
  const { email, token } = req.params;

  try {

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const tempCollection = db.collection("unverifiedUserAccounts");

    // Make an encrypted query.
    var queryEncryptedEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const existingTempUser = await tempCollection.findOne({email: queryEncryptedEmail});

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
      var enterName = await encryptClient.encrypt(existingTempUser.name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var enterPhone = await encryptClient.encrypt(existingTempUser.phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var enterUsername = await encryptClient.encrypt(existingTempUser.username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var discordAccount = await encryptClient.encrypt(existingTempUser.discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
	    var organization = await encryptClient.encrypt(existingTempUser.organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var timezone = await encryptClient.encrypt(existingTempUser.timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
      var pronouns = await encryptClient.encrypt(existingTempUser.pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});

      const newUser = {
        email: queryEncryptedEmail,
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
      };

      // Add verified user to the database and remove it from the temporary account.
      await userCollection.insertOne(newUser);
      await tempCollection.deleteOne({email: queryEncryptedEmail});
      //res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
      
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
    console.log("Hi")
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Perform an encrypted query.
    var enterEmail = await encryptClient.encrypt(email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    const verifiedUser = await userCollection.findOne({ email: enterEmail });
    //const unverifiedUser = await tempCollection.findOne({ email: enterEmail});

    // If found in the unverified database, initiate the registration process.
    // if (unverifiedUser) {
    //   const secret = process.env.JWT_SECRET + user.password;
    //   const token = jwt.sign({ email: user.email }, secret, { expiresIn: "5m" });

    //   let link = `https://ganttify-5b581a9c8167.herokuapp.com/verify-email/${email}/${token}`;

    //   const transporter = nodeMailer.createTransport({
    //     service: 'gmail',
    //     auth: {
    //       user: process.env.USER_EMAIL,
    //       pass: process.env.EMAIL_PASSWORD
    //     }
    //   });

    //   let mailDetails = {
    //     from: process.env.USER_EMAIL,
    //     to: email,
    //     subject: 'Verify Your Ganttify Account',
    //     text: `Hello ${user.name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
    //     html: `<p>Hello ${user.name},</p> <p>Please verify your Ganttify account by clicking the following link:</p> <a href="${link}" className="btn">Verify Account</a>`
    //   };

    //   transporter.sendMail(mailDetails, function (err, data) {
    //     if (err) {
    //       return res.status(500).json({ error: 'Error sending verification email' });
    //     } else  {
    //       return res.status(400).json({ error: 'Email not verified. Verification email sent again.' });
    //     }
    //   });
    //   return;
    // }

    // If user account is not found in the verified database.
    if (!verifiedUser) {
      error = "Invalid email or password";
      return res.status(401).json({ error });
    }

 
  const isPasswordValid = await bcrypt.compare(password, verifiedUser.password);

  if (!isPasswordValid) {
    error = "Invalid email or password";
    return res.status(401).json({ error });
  }

	  console.log("successful login");
    const token = jwt.sign({ id: verifiedUser._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    // Encrypt data.
    var encryptEmail = await encryptClient.encrypt(verifiedUser.email, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptId = await encryptClient.encrypt(verifiedUser._id, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptName = await encryptClient.encrypt(verifiedUser.name, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptPhone = await encryptClient.encrypt(verifiedUser.phone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptUsername = await encryptClient.encrypt(verifiedUser.username, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptDiscord = await encryptClient.encrypt(verifiedUser.discordAccount, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptOrganization = await encryptClient.encrypt(verifiedUser.organization, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptTimezone = await encryptClient.encrypt(verifiedUser.timezone, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    var encryptPronouns = await encryptClient.encrypt(verifiedUser.pronouns, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    
    res.status(200).json({
      token,
      _id: encryptId,
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
      error: ""
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Forgot password
router.post('/forgot-password', async (req, res) => 
{
  const {email} = req.body;
  let error = '';
  
  try{

    const db = client.db('ganttify');
    const results = db.collection('userAccounts');
    const user = await results.findOne({email});

    if (user) {
      
      const secret = process.env.JWT_SECRET + user.password;
      const token = jwt.sign({email: user.email, id: user._id}, secret, {expiresIn: "2m",} );

      let link = `https://ganttify-5b581a9c8167.herokuapp.com/reset-password/${user._id}/${token}`;
     
      const transporter = nodeMailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.USER_EMAIL,
          pass: process.env.EMAIL_PASSWORD
        }
      });

      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: 'Reset Your Ganttify Password',
        text: `Hello ${user.name},\n We recieved a request to reset your Ganttify password. Click the link to reset your password: ${link}`,
        html: `<p>Hello ${user.name},</p> <p>We recieved a request to reset your Ganttify password. Click the button to reset your password:\n</p> <a href="${link}" className="btn">Reset Password</a>`
      };

      transporter.sendMail(mailDetails, function (err, data) {
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
  
router.get('/reset-password/:id/:token', async (req, res) => 
{

  const { id, token } = req.params;

  try {

    const objectId = new ObjectId(id);
  
    const db = client.db('ganttify');
    const results = db.collection('userAccounts');
    const user = await results.findOne({_id: objectId});


    if (user) {
      const secret = process.env.JWT_SECRET + user.password;
  
      try {

        jwt.verify(token, secret);
        res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
  
      } catch (error) {
        res.send("Not verified");
      }
    } 
  
    else{
      return res.status(404).send("User does not exist");
    }
  } catch(error) {
    console.error('Error during password reset verification:', error);
    res.status(400).send("Invalid ID format");
  }

});
  
router.post('/reset-password', async (req, res) => 
{
  const { id, password } = req.body;

  let error = '';

  try {
    const db = client.db('ganttify');
    const objectId = ObjectId.createFromHexString(id); 
    const userCollection = db.collection('userAccounts');
    const user = await userCollection.findOne({_id: objectId});


    if (user){
      const hashedPassword = await bcrypt.hash(password, 10);

      try {
        await userCollection.updateOne({_id: objectId}, {$set: {password: hashedPassword}});
        res.status(200).json({ message: "Password has been reset successfully" });
      } catch(error) {
        return res.json({status: "error", data: error})
      }

    } else {
      error = 'User not found';
      return res.status(400).json({ error });
    }

  } catch (error) {
    console.error('Error occured during password reset:', error);
    error = 'Internal server error';
    res.status(500).json({ error });
  } 
});

let userList = [];
// //-----------------> User List Endpoint <-----------------//
router.get("/userlist", (req, res) => {
  res.status(200).json({ users: userList });
});

//-----------Read Users Endpoint----------------//
router.post("/read/users", async (req, res) => {
    const { users } = req.body;
    let error = "";
    var usersInfo = [];
    
    if (!users) {
        error = "User ids are required";
        return res.status(400).json({ error });
    }
  
    try {
        for(let i = 0;i<users.length;i++){
            const db = client.db("ganttify");
            const results = db.collection("userAccounts");
        
          
            const user = await results.findOne({ _id:new ObjectId(users[i])});
            usersInfo.push(user);
        }

        if(!userList){
            error = "no users found";
            res.status(400).json({error});
        }
        else{
            res.status(200).json({usersInfo,error});
        }
        
    }
    catch (error) {
        console.error("Login error:", error);
        error = "Internal server error";
        res.status(500).json({ error });
    }
  });

// TASK CRUD Operations
//-----------------> Create Task Endpoint <-----------------//

// Expression to validate hex color
const isValidHexColor = (color) => /^#([0-9A-F]{3}){1,2}$/i.test(color);

// List of valid patterns
// Replaced the valid file as pngs instead of svgs.
const allowedPatterns = {
  hollow_shape_family: [
    // "Hollow_Mac_Noodle_Density_1.svg", // Removed
    "Hollow_Single_Circle_Density_1.png",
    "Hollow_Single_Dot_Density_1.png",
    "Hollow_Single_Rhombus_Density_1.png",
    "Hollow_Single_Square_Density_1.png",
    "Hollow_Single_Star_Density_1.png",
    "Hollow_Single_Triangle_Density_1.png",
  ],
  line_family: [
    "Diagonal_Left_Single_Line_Density_1.png",
    "Diagonal_Right_Single_Line_Density_1.png",
    "Diagonal_Woven_Line_Density_1.png",
    "Single_Horizontal_Line_Density_1.png",
    "Single_Vertical_Line_Density_1.png",
  ],
  solid_shape_family: [
    // "Solid_Mac_Noodle_Density_1.svg", // Removed.
    "Solid_Single_Circle_Density_1.png",
    "Solid_Single_Dot_Density_1.png",
    "Solid_Single_Rhombus_Density_1.png",
    "Solid_Single_Square_Density_1.png",
    "Solid_Single_Star_Density_1.png",
    "Solid_Single_Triangle_Density_1.png",
  ], 
  halftone_family: [
    "Halftone_Density_1.png",
    "Halftone_Density_2.png",
    "Halftone_Density_3.png",
  ]
};

// Expression to validate pattern selection
const isValidPattern = (pattern) => {
  const [folder, file] = pattern.split('/');
  return allowedPatterns[folder] && allowedPatterns[folder].includes(file);
};

//------> Create Task & Added Task Category <-------//
router.post('/createtask', async (req, res) => {
  let {
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
    taskCategory = '' // Task category is optional
  } = req.body;

  const taskCreatorIdBinary = new Binary(Buffer.from(taskCreatorId, 'base64'), 6); //6 for encrypted data

  // Convert the keyId to Binary with BSON subtype 4
  const keyBinary = new Binary(Buffer.from(keyId, 'base64'), 4); //4 for encryption key
  
  // Using binary versions of id and key for decryption.
  const decryptedId = await encryptClient.decrypt(taskCreatorIdBinary, {
    keyId: keyBinary,
    algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
  });

  taskCreatorId = decryptedId;
  
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
      taskCategory,
      taskCategoryId: categoryId // Include the category ID if available
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

      await taskCategoriesCollection.updateOne(
        { _id: categoryId },
        { $push: { tasksUnder: taskId } }
      );

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

  console.log(id);
  if (!Object.keys(updateFields).length) {
    error = "No fields provided to update";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const taskCategoriesCollection = db.collection("task_categories");

    // Convert any provided ObjectId fields
    if (updateFields.assignedTasksUsers) {
      updateFields.assignedTasksUsers = updateFields.assignedTasksUsers.map(
        (id) => new ObjectId(id)
      );
    }
    if (updateFields.tiedProjectId) {
      updateFields.tiedProjectId = new ObjectId(updateFields.tiedProjectId);
    }
    if (updateFields.taskCreatorId) {
      updateFields.taskCreatorId = new ObjectId(updateFields.taskCreatorId);
    }
    if (updateFields.dueDateTime) {
      updateFields.dueDateTime = new Date(updateFields.dueDateTime);
    }

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
        category = result.ops[0];  // Retrieve the newly inserted category
      }

      // Update the task with the category ID
      updateFields.taskCategoryId = new ObjectId(category._id);
    }

    // Update the task itself
    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );

    if (result.modifiedCount === 0) {
      error = "Task not found or no changes made";
      return res.status(404).json({ error });
    }

    res.status(200).json({ message: "Task updated successfully" });
  } catch (error) {
    console.error("Error updating task:", error);
    error = "Internal server error";
    res.status(500).json({ error });
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
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const result = await taskCollection.deleteOne({ _id: new ObjectId(id) });
    res.status(200).json(result);
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
//-----------------> Create a project <-----------------//
router.post("/createproject", async (req, res) => {
  const {
    nameProject,
    team,
    tasks,
    isVisible = 1,
    founderId,
    flagDeletion = 0,
    group,
  } = req.body;
  let error = "";


  if (!nameProject || !founderId) {
    error = "Project name and founder ID are required";
    return res.status(400).json({ error });
  }

  const founderIdBinary = new Binary(Buffer.from(founderId, 'base64'), 6); //6 for encrypted data

  // Convert the keyId to Binary with BSON subtype 4
  const keyBinary = new Binary(Buffer.from(keyId, 'base64'), 4); //4 for encryption key
  
  // Using binary versions of id and key for decryption.
  const decryptedId = await encryptClient.decrypt(founderIdBinary, {
    keyId: keyBinary,
    algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
  });
  
  console.log(decryptedId)
  try {
    console.log(req.body)
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

    const newProject = {
      nameProject,
      dateCreated: new Date(),
      team: new ObjectId(),
      tasks: [], 
      isVisible,
      founderId: new ObjectId(decryptedId),
      flagDeletion,
      group: [new ObjectId()],
    };

    const project = await projectCollection.insertOne(newProject);
    const projectId = project.insertedId;
    const newTeam = {founderId: new ObjectId(decryptedId), editors: [], members: [], projects: [projectId],};
    const team = await teamCollection.insertOne(newTeam);

    await projectCollection.updateOne(
      { _id: projectId },
      { $set: { team: team.insertedId } }
    );

    await userCollection.updateOne(
      { _id: new ObjectId(decryptedId) },
      { $push: { projects: projectId } }
    );

    res.status(201).json({ ...newProject, _id: projectId, team: team.insertedId });

  } catch (error) {

    console.error("Error creating project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
    
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

//-----------------> Delete a project <-----------------//
Date.prototype.addDays = function(days) {
    var date = new Date(this.valueOf());
    date.setDate(date.getDate() + days);
    return date;
}

// Delete a project
router.delete("/projects/:id", async (req, res) => {
  const { id, } = req.params;
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
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    await deletedTasksCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    await deletedTeamsCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    // Find the project to delete
    const project = await projectCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Set flagDeletion to 1, add dateMoved and metadata fields
    project.flagDeletion = 1;
    project.dateMoved = new Date();
    project.metadata = { projectId: id }; // Example metadata, adjust as needed

    // Insert the project into the deleted_projects collection
    await deletedProjectsCollection.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await taskCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved and metadata for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { taskId: task._id }
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
        // Set dateMoved and metadata for the team
        const teamToMove = {
          ...team,
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { teamId: team._id }
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

    // Configure Nodemailer transport
    const transporter = nodeMailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    // Send an email notification
    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email, 
      subject: "Project Moved to Recently Deleted",
      text: `Hello,\n\nYour project "${project.nameProject}" has been moved to the Recently Deleted Projects collection. It will remain there for 30 days before permanent deletion.\n\nBest regards,\nThe Ganttify Team`,
    };

     transporter.sendMail(mailDetails, (err, info) => {
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
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    // Find the project to delete
    const project = await deletedProjectsCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Set flagDeletion to 1, add dateMoved and metadata fields
    project.flagDeletion = 1;
    project.dateMoved = new Date();
    project.metadata = { projectId: id }; // Example metadata, adjust as needed

    // Insert the project into the deleted_projects collection
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
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { taskId: task._id }
        }));
        await deleteAll.insertMany(tasksToMove);
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
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { teamId: team._id }
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

// -----------------> Update a specific user <-----------------//
router.put("/user/:userId", async (req, res) => {
  const userId = req.params.userId;
  const { name, email, phone } = req.body;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Validate that the user exists
    const user = await userCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update the user with the new data
    const updateResult = await userCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { name, email, phone } }
    );

    // Fetch the updated user
    const updatedUser = await userCollection.findOne(
      { _id: new ObjectId(userId) },
      { projection: { password: 0 } }
    );

    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
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

    const founderIdBinary = new Binary(Buffer.from(founderId, 'base64'), 6); //6 for encrypted data

    // Convert the keyId to Binary with BSON subtype 4
    const keyBinary = new Binary(Buffer.from(keyId, 'base64'), 4); //4 for encryption key
    
    // Using binary versions of id and key for decryption.
    const decryptedId = await encryptClient.decrypt(founderIdBinary, {
      keyId: keyBinary,
      algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
    });
  
    
    console.log(req.body)
    
  
    try {
      const db = client.db("ganttify");
      const projectCollection = db.collection("projects");
      const teamCollection = db.collection("teams");
  
      const teams = await teamCollection.find({
        $or: [
          { founderId: new ObjectId(decryptedId) },
          { editors: new ObjectId(decryptedId) },
          { members: new ObjectId(decryptedId) }
        ]
      }).toArray();
  
     console.log("These are the teams: ", teams);
  
      const teamIds = teams.map(team => new ObjectId(team._id));
  
     console.log("These are the team IDs: ", teamIds);
  
      const query = {
        $or: [
          { founderId: new ObjectId(decryptedId) },
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

  const founderIdBinary = new Binary(Buffer.from(founderId, 'base64'), 6); //6 for encrypted data

  // Convert the keyId to Binary with BSON subtype 4
  const keyBinary = new Binary(Buffer.from(keyId, 'base64'), 4); //4 for encryption key
  
  // Using binary versions of id and key for decryption.
  const decryptedId = await encryptClient.decrypt(founderIdBinary, {
    keyId: keyBinary,
    algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
  });

  if (!dueDate) {
    query.description = { founderId:decryptedId,$regex: name, $options: "i" };
  } else {
    query.description = { founderId:decryptedId, $gte: new Date(dueDate) };
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

    // Set flagDeletion to 1, add dateMoved and metadata fields
    project.flagDeletion = 0;
    delete project.dateMoved;
    delete project.metadata; // Example metadata, adjust as needed

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
          flagDeletion: 0
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
          flagDeletion: 0
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

router.post("/updateSingleUserToDoList", async (req, res) => {
  const { taskId, userId, isChecked } = req.body;
  let error = "";

  if (!taskId || !userId || typeof isChecked !== 'boolean') {
    error = "Task ID, user ID, and isChecked are required";
    return res.status(400).json({ error });
  }

  try {
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

    var encryptId = await encryptClient.encrypt(project.founderId, {keyId: new Binary(Buffer.from(keyId, "base64"), 4), algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"});
    project.founderId = encryptId

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
    const user = await userAccounts.findOne({ email });

    const secret = process.env.JWT_SECRET + (user ? user.password : 'newuseraccount');
    const token = jwt.sign({ email, projectId }, secret, { expiresIn: '5m' });
    
    const link = user ? `https://ganttify-5b581a9c8167.herokuapp.com/accept-invite/${token}` : `https://ganttify-5b581a9c8167.herokuapp.com/register/${token}`;

    const transporter = nodeMailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Invitation to Join Ganttify',
      text: `Hello,\n\nYou have been invited to join a project on Ganttify. Click the link to ${user ? 'accept the invitation' : 'create an account and join'}: ${link}`,
      html: `<p>Hello,</p><p>You have been invited to join a project on Ganttify. Click the button below to ${user ? 'accept the invitation' : 'create an account and join'}:</p><a href="${link}" class="btn">Join Ganttify</a>`,
    };

    transporter.sendMail(mailDetails, (err, data) => {

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
    const user = await userAccounts.findOne({ email });

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

router.post("/register/:token", async (req, res) => {
  const { token } = req.params;
  const { email, name, phone, password, username } = req.body;

  if (!email || !name || !phone || !password || !username) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {

    const decodedToken = jwt.decode(token);
    const { projectId } = decodedToken;
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const existingUser = await userCollection.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ error: "Email already used" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      email,
      name,
      phone,
      password: hashedPassword,
      username,
      accountCreated: new Date(),
      projects: [],
      toDoList: [],
      isEmailVerified: false,
    };

    // Insert the new user
    const insertedUser = await userCollection.insertOne(newUser);
    const secret = process.env.JWT_SECRET + hashedPassword;
    const verificationToken = jwt.sign({ email: newUser.email, projectId }, secret, { expiresIn: "5m" });
    let link = `https://ganttify-5b581a9c8167.herokuapp.com/verify-invite/${verificationToken}`;

    const transporter = nodeMailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Verify Your Ganttify Account',
      text: `Hello ${newUser.name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
      html: `<p>Hello ${newUser.name},</p> <p>Please verify your Ganttify account by clicking the following link:\n</p> <a href="${link}" className="btn">Verify Account</a>`
    };

    transporter.sendMail(mailDetails, function (err, data) {
      if (err) {
        return res.status(500).json({ error: 'Error sending verification email' });
      } else {
        return res.status(200).json({ message: 'Verification email sent' });
      }
    });
  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error });
  }
});

router.post('/decode-token', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.email) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    res.json({ email: decoded.email });
  } catch (error) {
    console.error('Error decoding token:', error);
    res.status(500).json({ error: 'Failed to decode token' });
  }
});

router.get('/verify-invite/:token', async (req, res) => {
  const { token } = req.params;

  try {

    const decodedToken = jwt.decode(token);
    if (!decodedToken) {
      return res.status(400).send("Invalid token");
    }

    const { email, projectId } = decodedToken;
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const projectCollection = db.collection("projects");
    const teamCollection = db.collection("teams");
    const user = await userCollection.findOne({ email });

    if (!user) {
      return res.status(404).send("User does not exist");
    }

    const secret = process.env.JWT_SECRET + user.password;

    try {
      jwt.verify(token, secret);

      await userCollection.updateOne(
        { _id: user._id },
        { $set: { isEmailVerified: true }, $addToSet: { projects: projectId } }
      );

      const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });
      if (!project) {
        return res.status(404).send('Project does not exist');
      }

      await teamCollection.updateOne(
        { _id: new ObjectId(project.team) },
        { $addToSet: { members: user._id } }
      );


      return res.status(200).send("User verified and added to project and team");
    } catch (error) {
      console.error('Token verification failed:', error);
      return res.status(400).send("Invalid or expired token");
    }
  } catch (error) {
    console.error('Error during invitation acceptance:', error);
    return res.status(400).send("Invalid ID format");
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
    //console.log("fetching task: " + id);
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const task = await taskCollection.findOne({ _id: new ObjectId(id) });
    //console.log("found task: " + task.taskTitle );
	  if (!task) {return res.status(404).json({ error: "Task not found" });}
    
      res.status(200).json(task);
  } catch (error) {
    console.error("Error fetching task:", error);
    res.status(500).json({ error: "Internal server error" });
  }	
});

module.exports = router;

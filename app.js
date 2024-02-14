import express from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcrypt";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { v2 as cloudinary } from "cloudinary";
import databaseClient from "./services/database.mjs";
import { ObjectId } from "mongodb";
import { auth } from "./middlewares/auth.js";
import signupRoute from "./module/signup.js";
import loginRoute from "./module/login.js";
import getdata from "./module/getdata.js";


const HOSTNAME = process.env.SERVER_IP || "localhost";
const PORT = process.env.SERVER_PORT || 8000;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_SECRET,
});

async function uploadToCloudinary(req, res, next) {
  // console.log("req.file", req.file);
  const fileBufferBase64 = Buffer.from(req.file.buffer).toString("base64");
  const base64File = `data:${req.file.mimetype};base64,${fileBufferBase64}`;
  // console.log("fileBufferBase64", fileBufferBase64);
  // console.log("base64File", base64File);
  req.cloudinary = await cloudinary.uploader.upload(base64File, {
    resource_type: "auto",
  });
  // console.log(req.cloudinary);
  next();
}

// upload to local
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     cb(null, "./public/uploads");
//   },
//   filename: function (req, file, cb) {
//     const name = uuidv4();
//     const extension = file.mimetype.split("/")[1];
//     const filename = `${name}.${extension}`;
//     cb(null, filename);
//   },
// });

dotenv.config();
const storage = multer.memoryStorage();
const upload = multer({ storage });
const app = express();
// const port = 8000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cors());
app.use(helmet());

app.get("/user/activity/:userId", auth, async (req, res) => {
  const { userId } = req.params;
  // const data = [...mockUserActivity];
  // const userData = data.filter((user) => user.userId === Number(userId));
  const userData = await databaseClient
    .db()
    .collection("user-activity")
    .find({ userId: new ObjectId(userId) })
    .toArray();
  res.json({ count: userData.length, data: userData });
});

app.get("/user/info/:userId", auth, async (req, res) => {
  const { userId } = req.params;
  // const data = [...mockUserInfo];
  // const userData = data.filter((user) => user.userId === Number(userId));
  const userData = await databaseClient
    .db()
    .collection("user-info")
    .find({ _id: new ObjectId(userId) })
    .project({ password: 0 })
    .toArray();
  res.json({ data: userData });
});

app.post("/user/changePassword/:userId", auth, async (req, res) => {
  const { userId } = req.params;
  const { newPassword } = req.body;
  const saltRounds = 12;
  const hashedPassword = bcrypt.hashSync(newPassword, saltRounds);
  // const data = [...mockUserInfo];
  // const userData = data.filter((user) => user.userId === Number(userId))[0];
  // userData.password = hashedPassword;
  await databaseClient
    .db()
    .collection("user-info")
    .updateOne(
      { _id: new ObjectId(userId) },
      { $set: { password: hashedPassword } }
    );
  res.status(200).send("OK");
});

app.patch(
  "/user/editProfile/:userId",
  auth,
  upload.single("image"),
  uploadToCloudinary,
  async (req, res) => {
    const { userId } = req.params;
    const { name, email, phoneNumber } = req.body;
    // const { filename } = req.file;
    // const data = [...mockUserInfo];
    // const userData = data.filter((user) => user.userId === Number(userId))[0];
    // userData.fullName = name;
    // userData.email = email;
    // userData.phone = phoneNumber;
    // userData.imagePath = `/uploads/${filename}`;
    await databaseClient
      .db()
      .collection("user-info")
      .updateOne(
        { _id: new ObjectId(userId) },
        {
          $set: {
            fullName: name,
            email: email,
            phone: phoneNumber,
            imagePath: req.cloudinary.secure_url,
          },
        }
      );
    res.send("OK");
  }
);

// mock upload
// app.patch("/user/:userId/uploads", upload.single("image"), (req, res) => {
//   const { filename } = req.file;
//   const { name } = req.body;
//   console.log(req.file);
//   const todoId = parseInt(req.params.userId, 10);
//   const updatedTodo = updateTodo(todoId, { imagePath: `/uploads/${filename}` });
//   if (!updatedTodo) {
//     res.status(404).json({ error: { message: "todo not found" } });
//   }

//   res.json({ data: [{ id: todoId, imagePath: `/uploads/${filename}`, name }] });
// });

// mock login
app.post("/mock/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await databaseClient
    .db()
    .collection("user-info")
    .findOne({ email: email });

  // Fetch user from database

  if (!user) {
    return res
      .status(400)
      .send({ error: { message: "Invalid email or password" } });
  }
  // Check password
  const validPassword = bcrypt.compareSync(password, user.password);
  if (!validPassword) {
    return res
      .status(400)
      .send({ error: { message: "Invalid email or password" } });
  }

  res.send({ token: createJwt(email), userId: user._id });
});

function createJwt(email) {
  const jwtSecretKey = process.env.JWT_SECRET_KEY;
  const token = jwt.sign({ id: email }, jwtSecretKey, {
    expiresIn: "1h",
  });

  return token;
}

//USERHOME-PAGE
app.get("/post/", async (req, res) => {
  try {
    const data = await databaseClient
      .db()
      .collection("user_card")
      .aggregate([
        {
          $lookup: {
            from: "members",
            localField: "userId",
            foreignField: "_id",
            as: "userDetails"
          }
        },
        {
          $unwind: "$userDetails"
        },
        {
          $project: {
            _id: 1,
            userId: 1,
            activityName: 1,
            activityType: 1,
            date: 1,
            durations: 1,
            distance: 1,
            description: 1,
            imageUrl: 1,
            createdAt: 1,
            "userDetails.fullName": 1,
            "userDetails.imagePath": 1
          }
        },
        {
          $sort: { createdAt: -1 }
        }
      ])
      .toArray();
    res.status(200).json(data);
  } catch (err) {
    res.status(500).send(err);
  }
});

//show user cards
app.get("/post/:userId/", async (req, res) => {
  const { userId } = req.params;
  try {
    // Check if userId is a valid ObjectId
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid userId format" });
    }
    
    const data = await databaseClient
      .db()
      .collection("user_card")
      .aggregate([
        {
          $match:{ userId: new ObjectId(userId) } 
        },
        {
          $lookup: {
            from: "members",
            localField: "userId",
            foreignField: "_id",
            as: "userDetails"
          }
        },
        {
          $unwind: "$userDetails"
        },
        {
          $project: {
            _id: 1,
            userId: 1,
            activityName: 1,
            activityType: 1,
            date: 1,
            durations: 1,
            distance: 1,
            description: 1,
            imageUrl: 1,
            createdAt: 1,
            "userDetails.fullName": 1,
            "userDetails.imagePath": 1
          }
        },
        {
          $sort: { createdAt: -1 }
        }
      ])
      .toArray();
      
    if (data.length === 0) {
      res.status(404).json({ error: "No data found for the provided userId" });
    } else {
      res.status(200).json(data);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "An error occurred while processing your request" });
  }
});

//edit card
app.put("/edit/post/:cardId", upload.single("imageUrl"), async (req, res) => {
  const { cardId } = req.params;
  const {  activityName, activityType, date, durations, distance, description, oldImageUrl } = req.body;

  try {
    let imageUrlToUpdate;

    if (!req.file) {
      imageUrlToUpdate = oldImageUrl;
    } else {
      await uploadToCloudinary(req, res, () => {}); // Call the middleware to upload the image to Cloudinary
      imageUrlToUpdate = req.cloudinary.secure_url;
    }

    console.log(imageUrlToUpdate);

    // Update the user document
    const result = await databaseClient
      .db()
      .collection("user_card")
      .findOneAndUpdate(
        { _id: new ObjectId(cardId) },
        {
          $set: {
            activityName: activityName,
            activityType: activityType,
            date: date,
            durations: durations,
            distance: distance,
            description: description,
            imageUrl: imageUrlToUpdate,
          }
        }
      );

    console.log(result);

    if (!result) {
      res.status(500).json({ message: "Failed to update user data" });
    } else {
      res.status(200).json({ message: "User data updated successfully" });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//create a new card
app.post("/post/", upload.single("imageUrl"),uploadToCloudinary,  async (req, res) => {
  try {
    const { userId,  activityName, activityType, date, durations, distance, description } = req.body;
    // Get the current timestamp
    const createdAt = new Date();
    // Insert the new record into the database collection and capture the result
    const insertResult = await databaseClient
      .db()
      .collection("user_card")
      .insertOne({
        userId: new ObjectId(userId),
        activityName: activityName,
        activityType: activityType,
        date: date,
        durations: durations,
        distance: distance,
        description: description,
        imageUrl: req.cloudinary.secure_url, // Assuming this holds the URL from Cloudinary upload
        createdAt: createdAt, // Add the createdAt field
      });

    // Check if the insertion was successful
    if (insertResult.acknowledged === true) {
      res.status(201).send({ insertedId: insertResult.insertedId });
    } else {
      res.status(500).json({ error: "Failed to insert record into the database" });
    }    
    
  } catch (error) {
    console.error("Error creating new record:", error);
    res.status(500).send("Internal Server Error");
  }
});


//delete card
app.delete("/delete/post/:cardId", async (req, res) =>{
  const {cardId} = req.params;
  try {
    // Find and delete the user document
    const result = await databaseClient

      .db()
      .collection("user_card")
      .findOneAndDelete({ _id: new ObjectId(cardId) });
       // Check if any document was deleted
       console.log(result);
      
    if (result) {
      res.status(200).json({ message: "User data deleted successfully" });
    } else {
      res.status(404).json({ message: "Card not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

//get user data using E-mail
app.get("/user/data/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const data = await databaseClient
      .db()
      .collection("members")
      .aggregate([
        { $match: { email: email } },
        {
          $project: {
            userId: { $toString: "$_id" }, 
            dob: 1,
            email: 1,
            fullName: 1,
            gender: 1,
            password: 1,
            phoneNumber: 1,
            typemem: 1,
            imagePath: 1,
          }
        }
      ])
      .toArray();
    if (data.length > 0) {
      res.status(200).json(data);
    } else {
      res.status(404).json({ message: 'User not found' });
    }

  } catch (err) {
    res.status(500).json(err);
  }
});

app.post("/signup", signupRoute);

app.post("/login" ,  loginRoute);

app.post("/data" , getdata);

app.get("/", (req, res) => {res.send("Hi")});






// app.listen(PORT, () => {
//   console.log(`Example app listening on port ${PORT}`);
// });

// initilize web server
const currentServer = app.listen(PORT, HOSTNAME, () => {
  console.log(
    `DATABASE IS CONNECTED: NAME => ${databaseClient.db().databaseName}`
  );
  console.log(`SERVER IS ONLINE => http://${HOSTNAME}:${PORT}`);
});

const cleanup = () => {
  currentServer.close(() => {
    console.log(
      `DISCONNECT DATABASE: NAME => ${databaseClient.db().databaseName}`
    );
    try {
      databaseClient.close();
    } catch (error) {
      console.error(error);
    }
  });
};

// cleanup connection such as database
process.on("SIGTERM", cleanup);
process.on("SIGINT", cleanup);

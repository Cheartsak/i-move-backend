import bcrypt from "bcrypt"; // Make sure to import the bcrypt library
import { checkMissingField } from "../utils/requestUtils.js"; // Import the checkMissingField function
import databaseClient from "../services/database.mjs"; // Import the databaseClient

const changpassword = async (req, res) => {
  const DATA_KEY_password = ["dob", "password", "email"];
  let body = req.body;

  const [isBodyChecked, setISsChecked] = checkMissingField(
    DATA_KEY_password,
    body
  );

  if (!isBodyChecked) {
    res.send(`Missing Fields: ${"".concat(setISsChecked)}`);
    return;
  }

  const SALT = 10;
  const saltRound = await bcrypt.genSalt(SALT);
  body["password"] = await bcrypt.hash(body["password"], saltRound);

  const email = body.email;
  await databaseClient
    .db()
    .collection("members")
    .updateOne(
      {
        email: { email },
      },
      {
        $set: { password: body },
      }
    );

  res.status(200).json(body);
};

export default changpassword;

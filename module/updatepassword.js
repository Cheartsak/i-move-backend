import bcrypt from "bcrypt"; // Make sure to import the bcrypt library
import { checkMissingField } from "../utils/requestUtils.js"; // Import the checkMissingField function
import databaseClient from "../services/database.mjs"; // Import the databaseClient

const changpassword = async (req, res) => {
  const DATA_KEY_password = ["password", "email"];
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
  const hashpassword = await bcrypt.hash(body.password, saltRound);

  const email = body.email;
  await databaseClient
    .db()
    .collection("members")
    .updateOne(
      {
        email: email ,
      },
      {
        $set: { password: hashpassword },
      }
    );

  res.status(200).json("Change Password Success");
};

export default changpassword;

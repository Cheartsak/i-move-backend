import databaseClient from "../services/database.mjs";
import { checkMissingField } from "../utils/requestUtils.js";
import cors from "cors";
import express, { response } from "express";

// app.get(/api/email), (req, res) => {
//     let body = req.query;
// }

const getemailRoute = async (req, res) => {
  let body = req.query;
  // console.log(body);
  // console.log(body.email);

  const user = await databaseClient
    .db()
    .collection("members")
    .findOne({ email: body.email }, { projection: { password: 0 } });

  if (!user) {
    res.status(304).send("Invalid Email");
    console.log("Invalid Email");
  } else {
    res.status(200).send("Match Email");
    console.log("Match Email");
  }
};


export default getemailRoute;

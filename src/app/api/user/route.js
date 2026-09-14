import { NextResponse } from "next/server";
import { ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import { getClientPromise } from "../../../lib/mongodb";
import { verifyJWT, isAdmin } from "../../../lib/auth";

function checkAccess(request) {
  if (!verifyJWT(request)) {
    return NextResponse.json(
      { message: "Please log in" },
      { status: 401 }
    );
  }

  if (!isAdmin(request)) {
    return NextResponse.json(
      { message: "Admin access required" },
      { status: 403 }
    );
  }

  return null;
}

async function getUsersCollection() {
  if (!process.env.DB_NAME) {
    throw new Error("DB_NAME is not configured");
  }

  const client = await getClientPromise();
  return client.db(process.env.DB_NAME).collection("user");
}

export async function GET(request) {
  const denied = checkAccess(request);
  if (denied) return denied;

  try {
    const collection = await getUsersCollection();
    const users = await collection
      .find({}, { projection: { password: 0 } })
      .toArray();

    return NextResponse.json({ users });
  } catch (error) {
    console.error(
      "Load users failed:",
      error.name,
      error.message
    );

    return NextResponse.json(
      { message: "Unable to load users" },
      { status: 500 }
    );
  }
}

export async function PATCH(request) {
  const denied = checkAccess(request);
  if (denied) return denied;

  let body;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { message: "Invalid JSON" },
      { status: 400 }
    );
  }

  const { userId, newPassword } = body ?? {};

  if (
    typeof userId !== "string" ||
    !/^[a-fA-F0-9]{24}$/.test(userId)
  ) {
    return NextResponse.json(
      { message: "Invalid user ID" },
      { status: 400 }
    );
  }

  if (
    typeof newPassword !== "string" ||
    newPassword.length < 8 ||
    Buffer.byteLength(newPassword, "utf8") > 72
  ) {
    return NextResponse.json(
      {
        message:
          "Use at least 8 characters and at most 72 bytes",
      },
      { status: 400 }
    );
  }

  try {
    const collection = await getUsersCollection();
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    const result = await collection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { password: hashedPassword } }
    );

    if (result.matchedCount === 0) {
      return NextResponse.json(
        { message: "User not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error(
      "Change password failed:",
      error.name,
      error.message
    );

    return NextResponse.json(
      { message: "Unable to change password" },
      { status: 500 }
    );
  }
}
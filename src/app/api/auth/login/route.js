import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { NextResponse } from "next/server";
import { getClientPromise } from "../../../../lib/mongodb";

export async function POST(request) {
  let body;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { message: "Invalid JSON" },
      { status: 400 }
    );
  }

  const { email, password } = body ?? {};

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email.trim() ||
    !password
  ) {
    return NextResponse.json(
      { message: "Enter your username or email and password" },
      { status: 400 }
    );
  }

  const identifier = email.trim();

  function invalidLogin() {
    return NextResponse.json(
      { message: "Invalid username or password" },
      { status: 401 }
    );
  }

  try {
    let user;

    if (identifier === process.env.ADMIN_USER) {
      if (password !== process.env.ADMIN_PASS) {
        return invalidLogin();
      }

      user = {
        id: "1",
        email: identifier,
        username: "admin",
      };
    } else {
      if (!process.env.DB_NAME) {
        throw new Error("DB_NAME is not configured");
      }

      const client = await getClientPromise();
      const db = client.db(process.env.DB_NAME);

      const account = await db.collection("user").findOne({
        $or: [
          { email: identifier },
          { username: identifier },
        ],
      });

      if (
        !account ||
        account.status !== "ACTIVE" ||
        typeof account.password !== "string"
      ) {
        return invalidLogin();
      }

      const matches = await bcrypt.compare(
        password,
        account.password
      );

      if (!matches) {
        return invalidLogin();
      }

      user = {
        id: account._id.toString(),
        email: account.email,
        username: account.username,
      };
    }

    const token = jwt.sign(user, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    const response = NextResponse.json({
      message: "Login successful",
      user,
    });

    response.cookies.set("token", token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
      secure: process.env.NODE_ENV === "production",
    });

    return response;
  } catch (error) {
    console.error("Login failed:", error.name);

    return NextResponse.json(
      { message: "Unable to log in. Check backend configuration." },
      { status: 500 }
    );
  }
}
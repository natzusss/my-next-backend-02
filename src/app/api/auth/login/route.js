import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";

export async function POST(request) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return NextResponse.json(
      { message: "Missing email or password" },
      { status: 400 }
    );
  }

  if (
    email !== process.env.ADMIN_USER ||
    password !== process.env.ADMIN_PASS
  ) {
    return NextResponse.json(
      { message: "Invalid email or password" },
      { status: 401 }
    );
  }

  const user = {
    id: "1",
    email,
    username: "admin",
  };

  const token = jwt.sign(user, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  const response = NextResponse.json(
    { message: "Login successful", user },
    { status: 200 }
  );

  response.cookies.set("token", token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
    secure: false,
  });

  return response;
}
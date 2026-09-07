import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";

export async function GET(request) {
  const token = request.cookies.get("token")?.value;

  if (!token) {
    return NextResponse.json(
      { message: "Unauthorized request" },
      { status: 401 }
    );
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    return NextResponse.json(user, { status: 200 });
  } catch {
    return NextResponse.json(
      { message: "Unauthorized request" },
      { status: 401 }
    );
  }
}
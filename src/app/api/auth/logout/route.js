import { NextResponse } from "next/server";

export async function GET() {
  const response = NextResponse.json(
    { message: "Logout successful" },
    { status: 200 }
  );

  response.cookies.set("token", "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
    secure: false,
  });

  return response;
}
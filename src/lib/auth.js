import jwt from "jsonwebtoken";

export function verifyJWT(request) {
  try {
    const token = request.cookies.get("token")?.value;

    if (!token) return null;

    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

export function isAdmin(request) {
  const user = verifyJWT(request);

  return user?.id === "1";
}
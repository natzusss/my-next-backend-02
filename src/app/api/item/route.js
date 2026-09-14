import { NextResponse } from "next/server";
import { getClientPromise } from "../../../lib/mongodb";
import { verifyJWT } from "../../../lib/auth";

export async function GET(request) {
  const user = verifyJWT(request);

  if (!user) {
    return NextResponse.json(
      { message: "Please log in" },
      { status: 401 }
    );
  }

  try {
    if (!process.env.DB_NAME) {
      throw new Error("DB_NAME is not configured");
    }

    const client = await getClientPromise();
    const db = client.db(process.env.DB_NAME);

    const itemList = await db
      .collection("item")
      .find({})
      .toArray();

    await db.collection("audit_log").insertOne({
      action: "READ_ITEMS",
      userId: user.id,
      username: user.username,
      method: "GET",
      path: "/api/item",
      timestamp: new Date(),
      resultCount: itemList.length,
    });

    return NextResponse.json({ itemList });
  } catch (error) {
    console.error("Load items failed:", error.name);

    return NextResponse.json(
      { message: "Unable to load items or record audit log" },
      { status: 500 }
    );
  }
}
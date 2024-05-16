import { NextResponse } from 'next/server';

export default function middleware(req) {
    // console.log("Middleware executed!");
    let verify = req.cookies.get("loggedIn");
    let url = req.url;

    // console.log(verify);

    if (!verify && url.includes('/home')) {
        return NextResponse.redirect("http://localhost:3000/");
    }

    if (verify && url==="http://localhost:3000/") {
        return NextResponse.redirect("http://localhost:3000/home");
    }
}